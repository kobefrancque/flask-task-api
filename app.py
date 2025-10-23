from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os
from dotenv import load_dotenv
from sqlalchemy import (
    String,
    Boolean,
    DateTime,
    Integer,
    func,
    ForeignKey,
    select,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.schema import PrimaryKeyConstraint
from flask_jwt_extended import (
    JWTManager,
    jwt_required,
    create_access_token,
    get_jwt_identity,
)
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta

### SETUP & CONFIG
load_dotenv()

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("SQLALCHEMY_DATABASE_URI")
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)

db = SQLAlchemy()
jwt = JWTManager()

db.init_app(app)
jwt.init_app(app)


### MODELS
class User(db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True, nullable=False)
    username: Mapped[str] = mapped_column(String(100), nullable=False)
    password: Mapped[str] = mapped_column(String(255), nullable=False)

    # relationship
    tasks: Mapped[list["Task"]] = relationship("Task", back_populates="user")


class Task(db.Model):
    __tablename__ = "tasks"

    id: Mapped[int] = mapped_column(Integer(), nullable=False)
    title: Mapped[str] = mapped_column(String(100), nullable=False)
    content: Mapped[str] = mapped_column(String(1000), nullable=True)
    completed: Mapped[bool] = mapped_column(Boolean(), default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # foreign key: reference to user
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)

    # composite primary key
    __table_args__ = (PrimaryKeyConstraint(id, user_id),)

    # relationship
    user: Mapped["User"] = relationship("User", back_populates="tasks")

    def __repr__(self):
        return f"{self.title} - {self.completed}"


### ROUTES
@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        message = "Enter username and password"
        return jsonify({"message": message}), 400
    elif _get_user(username):
        message = "User already exists"
        return jsonify({"message": message}), 409
    else:
        user = _create_user(username, password)
        message = f"successfully created user - {user.username}"
        access_token = create_access_token(identity=str(user.id))
        return jsonify({"message": message, "access_token": access_token}), 201


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    user = _get_user(username)

    if user and check_password_hash(user.password, password):
        message = f"successfully logged in - {user.username}"
        access_token = create_access_token(identity=str(user.id))
        return jsonify({"message": message, "access_token": access_token}), 200
    elif not user:
        message = "Invalid username"
        return jsonify({"message": message}), 401
    else:
        message = "Invalid credentials"
        return jsonify({"message": message}), 401


@app.route("/tasks", methods=["POST"])
@jwt_required()
def create_task():
    current_user_id = int(get_jwt_identity())
    task_id = _get_next_task_id(current_user_id)
    data = request.get_json()
    title = data.get("title")
    content = data.get("content")
    completed = data.get("completed")

    task = _create_task(id=task_id, title=title, content=content, completed=completed, user_id=current_user_id)

    if task:
        message = f"successfully added task {task.id}"
        return jsonify({"message": message}), 200
    else:
        message = "Could not create task"
        return jsonify({"message": message}), 200


@app.route("/tasks", methods=["GET"])
@jwt_required()
def get_tasks():
    current_user_id = int(get_jwt_identity())
    tasks = _get_tasks(current_user_id)

    output = []
    for task in tasks:
        task_data = {"id": task.id, "title": task.title, "completed": task.completed}
        output.append(task_data)
    return jsonify({"tasks": output}), 200


@app.route("/tasks/<task_id>", methods=["GET"])
@jwt_required()
def get_task_detail(task_id: int):
    current_user_id = int(get_jwt_identity())
    task = _get_task(task_id, current_user_id)

    if task is None:
        message = f"no task with id: {task_id}"
        return jsonify({"message": message}), 404
    elif task.user_id == current_user_id:
        return jsonify(
            {
                "id": task.id,
                "title": task.title,
                "content": task.content,
                "completed": task.completed,
                "created_at": task.created_at.isoformat(),
            }
        ), 200
    else:
        message = f"No permission for task: {task_id}"
        return jsonify({"message": message}), 403


@app.route("/tasks/<task_id>", methods=["DELETE"])
@jwt_required()
def delete_task(task_id: int):
    current_user_id = int(get_jwt_identity())
    task = _get_task(task_id, current_user_id)
    
    if task is None:
        message = f"no task with id: {task_id}"
        return jsonify({"message": message}), 404
    elif task.user_id == current_user_id:
        _delete_task(task)
        message = f"successfully removed task {task.id}"
        return jsonify({"message": message}), 200
    else:
        message = f"No permission for task: {task_id}"
        return jsonify({"message": message}), 403


@app.route("/tasks/<task_id>/complete", methods=["PATCH"])
@jwt_required()
def complete_task(task_id: int):
    current_user_id = int(get_jwt_identity())
    task = _get_task(task_id, current_user_id)
    
    if task is None:
        message = f"no task with id: {task_id}"
        return jsonify({"message": message}), 404
    elif task.user_id == current_user_id:
        if task.completed:
            message = "task already completed"
            return jsonify({"message": message}), 404
        else:
            _complete_task(task)
            message = f"task {task_id} completed"
            return jsonify({"message": message}), 200
    else:
        message = f"No permission for task: {task_id}"
        return jsonify({"message": message}), 403


### CRUD HELPER FUNCTIONS
def _get_user(username: str) -> User | None:
    query = select(User).where(User.username == username)
    user = db.session.execute(query).scalar_one_or_none()
    return user


def _create_user(username: str, password: str) -> User:
    hashed_password = generate_password_hash(
        password=password
    )  # hash password to store in DB
    user = User(username=username, password=hashed_password)
    db.session.add(user)
    db.session.commit()
    return user


def _create_task(id: int, title: str, content: str, completed: bool, user_id: int) -> Task:
    task = Task(id=id, title=title, content=content, completed=completed, user_id=user_id)
    db.session.add(task)
    db.session.commit()
    return task


def _get_tasks(user_id: int) -> list[Task] | None:
    query = select(Task).where(Task.user_id == user_id)
    result = db.session.execute(query)
    tasks = result.scalars().all()
    return tasks


def _get_task(task_id: int, user_id: int) -> Task | None:
    query = select(Task).where(Task.id == task_id, Task.user_id == user_id)
    result = db.session.execute(query)
    task = result.scalar_one_or_none()
    return task


def _get_next_task_id(user_id: int) -> int:
    query = text("SELECT COALESCE(MAX(id), 0) FROM tasks WHERE user_id = :user_id")
    result = db.session.execute(query, {"user_id": user_id})
    next_task_id = result.scalar_one() + 1
    return next_task_id


def _delete_task(task: Task):
    db.session.delete(task)
    db.session.commit()
    
    
def _complete_task(task):
    task.completed = True
    db.session.commit()

### APPLICATION STARTUP
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=5000, debug=True)
