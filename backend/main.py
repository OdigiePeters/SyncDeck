from fastapi import FastAPI, Depends, HTTPException, status, Form, UploadFile, File
import shutil
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List, Optional
from datetime import datetime, timedelta
import pyotp
import io
from . import models, schemas, auth, database
from .routers import github
from .export_utils import generate_csv, generate_pdf

models.Base.metadata.create_all(bind=database.engine)

app = FastAPI(title="Task Tracker API", root_path="/api")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In production, specify the frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(github.router)

# Request logging middleware for debugging
from fastapi import Request
@app.middleware("http")
async def log_login_requests(request: Request, call_next):
    if request.url.path == "/token":
        print("\n" + "=" * 60)
        print("LOGIN REQUEST RECEIVED FROM BROWSER")
        print(f"Method: {request.method}")
        print(f"Content-Type: {request.headers.get('content-type')}")
        
        # Read and log the body
        body = await request.body()
        print(f"Body (raw bytes): {body}")
        print(f"Body (decoded): {body.decode('utf-8')}")
        print("=" * 60 + "\n")
        
        # Recreate request with body for FastAPI to process
        from starlette.requests import Request as StarletteRequest
        async def receive():
            return {"type": "http.request", "body": body}
        request = StarletteRequest(request.scope, receive)
    
    response = await call_next(request)
    return response

# Dependency
get_db = database.get_db

@app.post("/token", response_model=schemas.Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), mfa_code: str = Form(None), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == form_data.username).first()
    if not user or not auth.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if user.mfa_secret:
        if not mfa_code:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="MFA_REQUIRED",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if not auth.verify_totp(user.mfa_secret, mfa_code):
             raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid MFA code",
                headers={"WWW-Authenticate": "Bearer"},
            )

    access_token = auth.create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/auth/mfa/setup")
def mfa_setup(current_user: models.User = Depends(auth.get_current_active_user)):
    secret = auth.generate_totp_secret()
    # In a real app, we would save this temporarily or return it to be saved after verification
    # For simplicity, we return it and the frontend calls enable with the code
    return {"secret": secret, "uri": pyotp.TOTP(secret).provisioning_uri(name=current_user.username, issuer_name="TaskTracker")}

@app.post("/auth/mfa/enable")
def mfa_enable(secret: str = Form(...), code: str = Form(...), db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_active_user)):
    if not auth.verify_totp(secret, code):
        raise HTTPException(status_code=400, detail="Invalid code")
    
    current_user.mfa_secret = secret
    db.commit()
    return {"message": "MFA enabled"}

@app.post("/users/", response_model=schemas.User)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_active_user)):
    # Permission Check
    # Permission Check
    if current_user.role != models.UserRole.GROUP_HEAD:
        raise HTTPException(status_code=403, detail="Only Group Heads can create users")

    db_user = db.query(models.User).filter(models.User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_password = auth.get_password_hash(user.password)
    db_user = models.User(
        username=user.username, 
        hashed_password=hashed_password,
        role=user.role,
        team_id=user.team_id
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.delete("/users/{user_id}")
def delete_user(user_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_active_user)):
    db_user = db.query(models.User).filter(models.User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    if current_user.role != models.UserRole.GROUP_HEAD:
        raise HTTPException(status_code=403, detail="Only Group Heads can delete users")

    db.delete(db_user)
    db.commit()
    return {"message": "User deleted"}

@app.put("/users/{user_id}", response_model=schemas.User)
@app.put("/users/{user_id}", response_model=schemas.User)
def update_user(user_id: int, user_update: schemas.UserUpdate, db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_active_user)):
    # Authorization Logic
    is_self = current_user.id == user_id
    is_group_head = current_user.role == models.UserRole.GROUP_HEAD

    if not (is_self or is_group_head):
        raise HTTPException(status_code=403, detail="Not authorized")
    
    db_user = db.query(models.User).filter(models.User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Handle Username Update
    if user_update.username and user_update.username != db_user.username:
        # Check if taken
        existing_user = db.query(models.User).filter(models.User.username == user_update.username).first()
        if existing_user:
             raise HTTPException(status_code=400, detail="Username already taken")
        db_user.username = user_update.username

    # Handle Password Update
    if user_update.password:
        db_user.hashed_password = auth.get_password_hash(user_update.password)

    # Handle Role/Team Update (Group Head Only)
    if is_group_head:
        if user_update.team_id is not None:
            db_user.team_id = user_update.team_id
        
        if user_update.role:
            if user_update.role == models.UserRole.UNIT_HEAD:
                # Check if team already has 2 unit heads
                target_team_id = user_update.team_id if user_update.team_id is not None else db_user.team_id
                
                if target_team_id:
                    unit_head_count = db.query(models.User).filter(
                        models.User.team_id == target_team_id,
                        models.User.role == models.UserRole.UNIT_HEAD
                    ).count()
                    
                    if db_user.role != models.UserRole.UNIT_HEAD and unit_head_count >= 1:
                         raise HTTPException(status_code=400, detail="Team already has a Unit Head. Assign as Backup Unit Head instead.")
            db_user.role = user_update.role
    elif (user_update.role or user_update.team_id is not None):
         # Non-admin trying to update role/team
         raise HTTPException(status_code=403, detail="Only Group Heads can update roles and teams")

    db.commit()
    db.refresh(db_user)
    return db_user

@app.post("/teams/", response_model=schemas.Team)
def create_team(team: schemas.TeamCreate, db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_active_user)):
    if current_user.role != models.UserRole.GROUP_HEAD:
        raise HTTPException(status_code=403, detail="Not authorized")
        
    db_team = models.Team(name=team.name)
    db.add(db_team)
    db.commit()
    db.refresh(db_team)
    return db_team

@app.get("/teams/", response_model=List[schemas.Team])
def read_teams(skip: int = 0, limit: int = 100, db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_active_user)):
    teams = db.query(models.Team).offset(skip).limit(limit).all()
    return teams

@app.get("/users/me", response_model=schemas.User)
async def read_users_me(current_user: models.User = Depends(auth.get_current_active_user)):
    return current_user

@app.get("/users/", response_model=List[schemas.User])
def read_users(skip: int = 0, limit: int = 100, db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_active_user)):
    users = db.query(models.User).offset(skip).limit(limit).all()
    return users

@app.post("/tasks/", response_model=schemas.Task)
def create_task(task: schemas.TaskCreate, db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_active_user)):
    if current_user.role == models.UserRole.MEMBER:
         raise HTTPException(status_code=403, detail="Members cannot create tasks")
    
    if task.is_internal and current_user.role not in [models.UserRole.UNIT_HEAD, models.UserRole.BACKUP_UNIT_HEAD]:
         raise HTTPException(status_code=403, detail="Only Unit Heads (or Backups) can create internal tasks")

    db_task = models.Task(**task.dict(), assigner_id=current_user.id)
    db.add(db_task)
    db.commit()
    db.refresh(db_task)
    return db_task

@app.get("/tasks/", response_model=List[schemas.Task])
def read_tasks(skip: int = 0, limit: int = 100, db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_active_user)):
    if current_user.role == models.UserRole.GROUP_HEAD:
        # See all tasks EXCEPT internal ones
        tasks = db.query(models.Task).filter(models.Task.is_internal == False).offset(skip).limit(limit).all()
    elif current_user.role in [models.UserRole.UNIT_HEAD, models.UserRole.BACKUP_UNIT_HEAD]:
        # See tasks assigned to members of their team (including internal)
        if current_user.team_id:
            tasks = db.query(models.Task).join(models.User, models.Task.assignee_id == models.User.id).filter(models.User.team_id == current_user.team_id).offset(skip).limit(limit).all()
        else:
            # Fallback
            tasks = db.query(models.Task).filter(models.Task.assignee_id == current_user.id).offset(skip).limit(limit).all()
    else:
        # Member: See assigned tasks
        tasks = db.query(models.Task).filter(models.Task.assignee_id == current_user.id).offset(skip).limit(limit).all()
    return tasks
@app.put("/tasks/{task_id}", response_model=schemas.Task)
def update_task(task_id: int, task: schemas.TaskUpdate, db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_active_user)):
    db_task = db.query(models.Task).filter(models.Task.id == task_id).first()
    if not db_task:
        raise HTTPException(status_code=404, detail="Task not found")
    
    # Update fields
    task_data = task.dict(exclude_unset=True)
    
    # Track changes for activity log
    changes = []
    if 'status' in task_data and task_data['status'] != db_task.status:
        changes.append(f"Status changed from {db_task.status} to {task_data['status']}")
        # Log activity
        activity = models.TaskActivity(
            task_id=task_id,
            user_id=current_user.id,
            activity_type=models.ActivityType.STATUS_CHANGE,
            description=f"Status changed to {task_data['status']}"
        )
        db.add(activity)
        
    if 'progress_percentage' in task_data and task_data['progress_percentage'] != db_task.progress_percentage:
        # Log activity
        activity = models.TaskActivity(
            task_id=task_id,
            user_id=current_user.id,
            activity_type=models.ActivityType.PROGRESS_UPDATE,
            description=f"Progress updated to {task_data['progress_percentage']}%"
        )
        db.add(activity)

    for key, value in task_data.items():
        setattr(db_task, key, value)
    
    # Auto-set completed_at timestamp when status changes to COMPLETED
    if 'status' in task_data and task_data['status'] == models.TaskStatus.COMPLETED:
        if not db_task.completed_at:
            db_task.completed_at = datetime.utcnow()
            
            # Update member achievements
            achievement = db.query(models.MemberAchievement).filter(models.MemberAchievement.user_id == db_task.assignee_id).first()
            if not achievement:
                achievement = models.MemberAchievement(
                    user_id=db_task.assignee_id,
                    total_completed_tasks=0,
                    critical_tasks_completed=0,
                    on_time_completion_rate=0,
                    current_no_blocker_streak=0
                )
                db.add(achievement)
            
            # Ensure fields are not None before incrementing
            if achievement.total_completed_tasks is None:
                achievement.total_completed_tasks = 0
            if achievement.critical_tasks_completed is None:
                achievement.critical_tasks_completed = 0
                
            achievement.total_completed_tasks += 1
            if db_task.criticality == models.TaskCriticality.HIGH:
                achievement.critical_tasks_completed += 1
            achievement.last_updated = datetime.utcnow()
    
    db.add(db_task)
    db.commit()
    db.refresh(db_task)
    return db_task

@app.post("/tasks/{task_id}/comments/", response_model=schemas.Comment)
def create_comment(task_id: int, comment: schemas.CommentCreate, db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_active_user)):
    db_task = db.query(models.Task).filter(models.Task.id == task_id).first()
    if not db_task:
        raise HTTPException(status_code=404, detail="Task not found")
        
    db_comment = models.Comment(**comment.dict(), task_id=task_id, author_id=current_user.id)
    db.add(db_comment)
    
    # Log activity
    activity = models.TaskActivity(
        task_id=task_id,
        user_id=current_user.id,
        activity_type=models.ActivityType.COMMENT_ADDED,
        description="Added a comment"
    )
    db.add(activity)
    
    db.commit()
    db.refresh(db_comment)
    return db_comment

@app.get("/tasks/{task_id}/comments/", response_model=List[schemas.Comment])
def read_comments(task_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_active_user)):
    comments = db.query(models.Comment).filter(models.Comment.task_id == task_id).order_by(models.Comment.created_at.desc()).all()
    return comments

@app.post("/tasks/{task_id}/help-request", response_model=schemas.HelpRequest)
def create_help_request(task_id: int, request: schemas.HelpRequestCreate, db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_active_user)):
    db_task = db.query(models.Task).filter(models.Task.id == task_id).first()
    if not db_task:
        raise HTTPException(status_code=404, detail="Task not found")
        
    help_req = models.HelpRequest(**request.dict(), task_id=task_id, requester_id=current_user.id)
    db.add(help_req)
    
    # Log activity
    activity = models.TaskActivity(
        task_id=task_id,
        user_id=current_user.id,
        activity_type=models.ActivityType.HELP_REQUESTED,
        description=f"Requested help: {request.reason}"
    )
    db.add(activity)
    
    # Update task status to BLOCKED or NEEDS_REVIEW if appropriate? 
    # For now just log it.
    
    db.commit()
    db.refresh(help_req)
    return help_req

@app.post("/tasks/{task_id}/evidence")
async def upload_evidence(
    task_id: int, 
    file: UploadFile = File(...), 
    db: Session = Depends(get_db), 
    current_user: models.User = Depends(auth.get_current_active_user)
):
    db_task = db.query(models.Task).filter(models.Task.id == task_id).first()
    if not db_task:
        raise HTTPException(status_code=404, detail="Task not found")
        
    # Create uploads directory if not exists
    UPLOAD_DIR = "uploads"
    if not os.path.exists(UPLOAD_DIR):
        os.makedirs(UPLOAD_DIR)
        
    # Generate unique filename
    file_extension = os.path.splitext(file.filename)[1]
    filename = f"evidence_{task_id}_{datetime.utcnow().timestamp()}{file_extension}"
    file_path = os.path.join(UPLOAD_DIR, filename)
    
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
        
    # Update task evidence_url
    evidence_url = f"/uploads/{filename}"
    db_task.evidence_url = evidence_url
    
    # Log activity
    activity = models.TaskActivity(
        task_id=task_id,
        user_id=current_user.id,
        activity_type=models.ActivityType.EVIDENCE_UPLOADED,
        description=f"Uploaded evidence: {file.filename}"
    )
    db.add(activity)
    
    db.commit()
    return {"filename": file.filename, "url": evidence_url}

@app.get("/tasks/{task_id}/timeline", response_model=List[schemas.TaskActivity])
def read_timeline(task_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_active_user)):
    activities = db.query(models.TaskActivity).filter(models.TaskActivity.task_id == task_id).order_by(models.TaskActivity.created_at.desc()).all()
    return activities

@app.get("/users/{user_id}/achievement-stats", response_model=schemas.MemberAchievement)
def get_achievement_stats(user_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_active_user)):
    stats = db.query(models.MemberAchievement).filter(models.MemberAchievement.user_id == user_id).first()
    if not stats:
        # Return empty stats if none exist
        return schemas.MemberAchievement(
            id=0, 
            user_id=user_id, 
            on_time_completion_rate=0,
            total_completed_tasks=0,
            critical_tasks_completed=0,
            current_no_blocker_streak=0,
            last_updated=datetime.utcnow()
        )
    return stats

@app.post("/tasks/{task_id}/update", response_model=schemas.Task)
def update_task_progress(
    task_id: int,
    update_data: schemas.TaskProgressUpdateCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    task = db.query(models.Task).filter(models.Task.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    # Create TaskUpdate record
    task_update = models.TaskUpdate(
        task_id=task_id,
        user_id=current_user.id,
        summary_text=update_data.summary_text,
        progress_percentage=update_data.progress_percentage,
        status=update_data.status
    )
    db.add(task_update)

    # Update Task
    task.progress_percentage = update_data.progress_percentage
    task.status = update_data.status

    # Log Activity
    activity = models.TaskActivity(
        task_id=task_id,
        user_id=current_user.id,
        activity_type=models.ActivityType.PROGRESS_UPDATE,
        description=f"Updated progress to {update_data.progress_percentage}% and status to {update_data.status}. Summary: {update_data.summary_text or 'None'}"
    )
    db.add(activity)
    
    # Note: Completion and achievement updates now happen only via the approve endpoint

    db.commit()
    db.refresh(task)
    return task

@app.post("/tasks/{task_id}/approve", response_model=schemas.Task)
def approve_task(
    task_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    """Approve a task that is pending approval. Implements multi-level approval workflow."""
    task = db.query(models.Task).filter(models.Task.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    
    # Check if user has permission to approve
    if current_user.id != task.assigner_id and current_user.role not in [models.UserRole.UNIT_HEAD, models.UserRole.BACKUP_UNIT_HEAD, models.UserRole.GROUP_HEAD]:
        raise HTTPException(status_code=403, detail="Only the assigner or unit heads can approve tasks")
    
    # Check if task is pending approval (either status)
    if task.status not in [models.TaskStatus.PENDING_APPROVAL, models.TaskStatus.PENDING_GROUP_HEAD_APPROVAL, "pending_approval", "pending_group_head_approval"]:
        raise HTTPException(status_code=400, detail=f"Task is not pending approval. Current status: {task.status}")
    
    # Determine if this is the final approval based on the original assigner's role
    is_final_approval = False
    
    # If the task is already pending group head approval, only group head can give final approval
    if task.status == models.TaskStatus.PENDING_GROUP_HEAD_APPROVAL:
        if current_user.role == models.UserRole.GROUP_HEAD:
            is_final_approval = True
        else:
            raise HTTPException(status_code=403, detail="This task requires Group Head approval")
    else:
        # Task is in pending_approval status
        # Check who the original assigner was
        if task.assigner.role == models.UserRole.GROUP_HEAD:
            # Group head assigned it
            if current_user.role == models.UserRole.GROUP_HEAD:
                # Group head is approving their own task
                is_final_approval = True
            elif current_user.role in [models.UserRole.UNIT_HEAD, models.UserRole.BACKUP_UNIT_HEAD]:
                # Unit head is approving, but it needs to go to group head
                task.status = models.TaskStatus.PENDING_GROUP_HEAD_APPROVAL
                # Log Activity
                activity = models.TaskActivity(
                    task_id=task_id,
                    user_id=current_user.id,
                    activity_type=models.ActivityType.STATUS_CHANGE,
                    description=f"Task approved by {current_user.username}, forwarded to Group Head for final approval"
                )
                db.add(activity)
                db.commit()
                db.refresh(task)
                return task
        elif task.assigner.role in [models.UserRole.UNIT_HEAD, models.UserRole.BACKUP_UNIT_HEAD]:
            # Unit head assigned it, they or group head can give final approval
            if current_user.role in [models.UserRole.UNIT_HEAD, models.UserRole.BACKUP_UNIT_HEAD, models.UserRole.GROUP_HEAD]:
                is_final_approval = True
        else:
            # Member assigned it (shouldn't happen normally, but handle it)
            is_final_approval = True
    
    # If this is the final approval, mark as completed
    if is_final_approval:
        task.status = models.TaskStatus.COMPLETED
        task.completed_at = datetime.utcnow()
        
        # Update achievement stats for the assignee
        if task.assignee_id:
            stats = db.query(models.MemberAchievement).filter(models.MemberAchievement.user_id == task.assignee_id).first()
            if not stats:
                stats = models.MemberAchievement(
                    user_id=task.assignee_id,
                    total_completed_tasks=0,
                    critical_tasks_completed=0,
                    on_time_completion_rate=0,
                    current_no_blocker_streak=0
                )
                db.add(stats)
            
            # Ensure fields are not None before incrementing
            if stats.total_completed_tasks is None:
                stats.total_completed_tasks = 0
            if stats.critical_tasks_completed is None:
                stats.critical_tasks_completed = 0
                
            stats.total_completed_tasks += 1
            if task.criticality == models.TaskCriticality.HIGH:
                stats.critical_tasks_completed += 1
            stats.last_updated = datetime.utcnow()
        
        # Log Activity
        activity = models.TaskActivity(
            task_id=task_id,
            user_id=current_user.id,
            activity_type=models.ActivityType.STATUS_CHANGE,
            description=f"Task approved and marked as completed by {current_user.username}"
        )
        db.add(activity)
    
    db.commit()
    db.refresh(task)
    return task


@app.get("/achievements/{user_id}")
def get_achievements(
    user_id: int,
    period: str = "month",
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    """Get completed tasks (achievements) for a user with optional filtering"""
    # Authorization: users can view their own achievements, unit heads can view team members, group heads can view all
    if current_user.id != user_id:
        if current_user.role == models.UserRole.UNIT_HEAD:
            # Check if user is in the same team
            target_user = db.query(models.User).filter(models.User.id == user_id).first()
            if not target_user or target_user.team_id != current_user.team_id:
                raise HTTPException(status_code=403, detail="Not authorized to view this user's achievements")
        elif current_user.role != models.UserRole.GROUP_HEAD:
            raise HTTPException(status_code=403, detail="Not authorized")
    
    # Base query for completed tasks
    query = db.query(models.Task).filter(
        models.Task.assignee_id == user_id,
        models.Task.status == models.TaskStatus.COMPLETED
    )
    
    # Apply date filtering
    if period == "week":
        start = datetime.now() - timedelta(days=7)
        query = query.filter(models.Task.completed_at >= start)
    elif period == "month":
        start = datetime.now() - timedelta(days=30)
        query = query.filter(models.Task.completed_at >= start)
    elif start_date and end_date:
        try:
            start = datetime.fromisoformat(start_date)
            end = datetime.fromisoformat(end_date)
            query = query.filter(models.Task.completed_at >= start, models.Task.completed_at <= end)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid date format")
    
    tasks = query.order_by(models.Task.completed_at.desc()).all()
    return tasks

@app.get("/achievements/{user_id}/export")
def export_achievements(
    user_id: int,
    format: str = "csv",
    period: str = "month",
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    """Export achievements as CSV or PDF"""
    # Same authorization as get_achievements
    if current_user.id != user_id:
        if current_user.role == models.UserRole.UNIT_HEAD:
            target_user = db.query(models.User).filter(models.User.id == user_id).first()
            if not target_user or target_user.team_id != current_user.team_id:
                raise HTTPException(status_code=403, detail="Not authorized")
        elif current_user.role != models.UserRole.GROUP_HEAD:
            raise HTTPException(status_code=403, detail="Not authorized")
    
    # Get user info
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Base query
    query = db.query(models.Task).filter(
        models.Task.assignee_id == user_id,
        models.Task.status == models.TaskStatus.COMPLETED
    )
    
    # Apply date filtering
    if period == "week":
        start = datetime.now() - timedelta(days=7)
        query = query.filter(models.Task.completed_at >= start)
    elif period == "month":
        start = datetime.now() - timedelta(days=30)
        query = query.filter(models.Task.completed_at >= start)
    elif start_date and end_date:
        try:
            start = datetime.fromisoformat(start_date)
            end = datetime.fromisoformat(end_date)
            query = query.filter(models.Task.completed_at >= start, models.Task.completed_at <= end)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid date format")
    
    tasks = query.order_by(models.Task.completed_at.desc()).all()
    
    # Convert to dict for export functions
    tasks_data = []
    for task in tasks:
        tasks_data.append({
            'title': task.title,
            'description': task.description,
            'completed_at': task.completed_at.isoformat() if task.completed_at else None,
            'criticality': task.criticality.value if task.criticality else 'medium',
            'assigner': {'username': task.assigner.username if task.assigner else 'N/A'}
        })
    
    if format == "csv":
        csv_content = generate_csv(tasks_data, user.username)
        return StreamingResponse(
            io.StringIO(csv_content),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=achievements_{user.username}_{period}.csv"}
        )
    elif format == "pdf":
        pdf_content = generate_pdf(tasks_data, user.username, period)
        return StreamingResponse(
            io.BytesIO(pdf_content),
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=achievements_{user.username}_{period}.pdf"}
        )
    else:
        raise HTTPException(status_code=400, detail="Invalid format. Use 'csv' or 'pdf'")

@app.get("/analytics/")
def get_analytics(db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_active_user)):
    if current_user.role != models.UserRole.GROUP_HEAD:
        raise HTTPException(status_code=403, detail="Not authorized")

    total_tasks = db.query(models.Task).count()
    completed_tasks = db.query(models.Task).filter(models.Task.status == models.TaskStatus.COMPLETED).count()
    pending_tasks = total_tasks - completed_tasks

    # Tasks by Status
    status_counts = db.query(models.Task.status, func.count(models.Task.id)).group_by(models.Task.status).all()
    status_data = [{"name": s.value, "value": c} for s, c in status_counts]

    # Tasks by Team
    # Join Task -> User (assignee) -> Team
    team_counts = db.query(models.Team.name, func.count(models.Task.id)).join(models.User, models.Team.members).join(models.Task, models.User.assigned_tasks).group_by(models.Team.name).all()
    team_data = [{"name": t, "tasks": c} for t, c in team_counts]

    return {
        "total_tasks": total_tasks,
        "completed_tasks": completed_tasks,
        "pending_tasks": pending_tasks,
        "status_data": status_data,
        "team_data": team_data
    }

# Serve Static Files
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os
from pathlib import Path

# Resolve paths relative to this file
BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIST = BASE_DIR.parent / "frontend" / "dist"

# Mount static files
if (FRONTEND_DIST / "assets").exists():
    app.mount("/assets", StaticFiles(directory=str(FRONTEND_DIST / "assets")), name="assets")

# Mount uploads directory
if not os.path.exists("uploads"):
    os.makedirs("uploads")
app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")

@app.get("/{full_path:path}")
async def serve_react_app(full_path: str):
    # Check if file exists in dist (e.g. favicon.ico)
    file_path = FRONTEND_DIST / full_path
    if file_path.exists() and file_path.is_file():
        return FileResponse(file_path)
        
    # Otherwise return index.html for React Router
    index_path = FRONTEND_DIST / "index.html"
    if index_path.exists():
        return FileResponse(index_path)
    
    return {"error": "Frontend not built"}
