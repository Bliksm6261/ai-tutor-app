# main.py

import os
import psycopg2
from psycopg2.extras import RealDictCursor
from fastapi import FastAPI, HTTPException, status, Depends
from pydantic import BaseModel, EmailStr
from dotenv import load_dotenv
import uvicorn

# --- CORS Imports ---
from fastapi.middleware.cors import CORSMiddleware

# --- Security Imports ---
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta, timezone
from fastapi.security import OAuth2PasswordBearer

# --- Security Setup ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = os.getenv("SECRET_KEY", "a_very_secret_key_for_initial_dev")
SUPER_ADMIN_API_KEY = os.getenv("SUPER_ADMIN_API_KEY", "a_very_secret_admin_key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

load_dotenv()

# --- Database Connection ---
DB_NAME = "ai_tutor_db"
DB_USER = "ai_tutor_user"
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_HOST = "localhost"

def get_db_connection():
    try:
        conn = psycopg2.connect(
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
            host=DB_HOST,
            cursor_factory=RealDictCursor
        )
        return conn
    except psycopg2.OperationalError as e:
        print(f"Error connecting to database: {e}")
        return None

# --- Pydantic Models ---
class UserCreate(BaseModel):
    email: EmailStr
    password: str
    first_name: str
    last_name: str

class StudentCreate(UserCreate):
    class_id: int
    role: str = 'student'

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: str | None = None
    user_id: int | None = None
    role: str | None = None

class AnswerSubmission(BaseModel):
    question_id: int
    answer: str

class SchoolCreate(BaseModel):
    name: str
    max_students: int = 50
    max_teachers: int = 5

class AdminTeacherCreate(UserCreate):
    school_id: int
    role: str = 'admin'

class ClassCreate(BaseModel):
    name: str

# --- Security Utilities ---
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        user_id: int = payload.get("user_id")
        role: str = payload.get("role")
        if email is None or user_id is None or role is None:
            raise credentials_exception
        token_data = TokenData(email=email, user_id=user_id, role=role)
    except JWTError:
        raise credentials_exception
    return token_data

# --- FastAPI App ---
app = FastAPI(
    title="AI Tutor API",
    description="The backend API for the Study Chommie platform.",
    version="0.8.1", # Version bump for the fix
)

# --- CORS Middleware Setup ---
origins = ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- API Endpoints ---
@app.get("/")
def read_root():
    return {"message": "Welcome to the Study Chommie API!"}

@app.post("/login", response_model=Token)
def login_for_access_token(form_data: UserLogin):
    conn = get_db_connection()
    if conn is None: raise HTTPException(status_code=500, detail="Database connection failed.")
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = %s", (form_data.email,))
        user = cursor.fetchone()
    finally:
        if conn: cursor.close(); conn.close()
    if not user or not verify_password(form_data.password, user['password_hash']):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")
    access_token = create_access_token(data={"sub": user['email'], "user_id": user['user_id'], "role": user['role']})
    return {"access_token": access_token, "token_type": "bearer"}

# --- Teacher Endpoints ---
@app.get("/teacher/dashboard")
def get_teacher_dashboard(current_user: TokenData = Depends(get_current_user)):
    if current_user.role not in ['teacher', 'admin']:
        raise HTTPException(status_code=403, detail="Not authorized")

    teacher_id = current_user.user_id
    conn = get_db_connection()
    if conn is None: raise HTTPException(status_code=500, detail="Database connection failed.")

    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT
                u.user_id, u.first_name, u.last_name, u.email,
                COALESCE(AVG(sp.mastery_score), 0.1) as average_mastery
            FROM users u
            JOIN classes c ON u.class_id = c.class_id
            LEFT JOIN student_progress sp ON u.user_id = sp.student_id
            WHERE c.teacher_id = %s AND u.role = 'student'
            GROUP BY u.user_id ORDER BY average_mastery ASC;
            """, (teacher_id,)
        )
        students = cursor.fetchall()
        return students
    finally:
        if conn: cursor.close(); conn.close()

@app.post("/teacher/classes", status_code=status.HTTP_201_CREATED)
def create_class(class_data: ClassCreate, current_user: TokenData = Depends(get_current_user)):
    if current_user.role not in ['teacher', 'admin']:
        raise HTTPException(status_code=403, detail="Not authorized")

    teacher_id = current_user.user_id
    conn = get_db_connection()
    if conn is None: raise HTTPException(status_code=500, detail="Database connection failed.")

    try:
        cursor = conn.cursor()
        # Get the teacher's school_id
        cursor.execute("SELECT school_id FROM users WHERE user_id = %s", (teacher_id,))
        teacher_school = cursor.fetchone()
        if not teacher_school or not teacher_school['school_id']:
            raise HTTPException(status_code=404, detail="Teacher not found or not assigned to a school.")

        school_id = teacher_school['school_id']

        cursor.execute(
            "INSERT INTO classes (name, teacher_id, school_id) VALUES (%s, %s, %s) RETURNING class_id",
            (class_data.name, teacher_id, school_id)
        )
        new_class_id = cursor.fetchone()['class_id']
        conn.commit()
    finally:
        if conn: cursor.close(); conn.close()

    return {"message": "Class created successfully", "class_id": new_class_id}

@app.post("/teacher/students", status_code=status.HTTP_201_CREATED)
def create_student(student: StudentCreate, current_user: TokenData = Depends(get_current_user)):
    if current_user.role not in ['teacher', 'admin']:
        raise HTTPException(status_code=403, detail="Not authorized")

    conn = get_db_connection()
    if conn is None: raise HTTPException(status_code=500, detail="Database connection failed.")

    try:
        cursor = conn.cursor()
        cursor.execute("SELECT school_id FROM users WHERE user_id = %s", (current_user.user_id,))
        teacher_school = cursor.fetchone()
        if not teacher_school:
            raise HTTPException(status_code=404, detail="Teacher not found.")
        school_id = teacher_school['school_id']

        # Subscription Limit Check
        cursor.execute("SELECT COUNT(*) as count FROM users WHERE school_id = %s AND role = 'student'", (school_id,))
        student_count = cursor.fetchone()['count']

        cursor.execute("SELECT max_students FROM schools WHERE school_id = %s", (school_id,))
        school_limits = cursor.fetchone()

        if not school_limits or student_count >= school_limits['max_students']:
            raise HTTPException(status_code=403, detail="Student limit for this school has been reached.")

        # Check if student email already exists
        cursor.execute("SELECT * FROM users WHERE email = %s", (student.email,))
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail="Email already registered")

        hashed_password = get_password_hash(student.password)
        cursor.execute(
            """
            INSERT INTO users (email, password_hash, role, first_name, last_name, school_id, class_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING user_id
            """,
            (student.email, hashed_password, student.role, student.first_name, student.last_name, school_id, student.class_id)
        )
        new_user_id = cursor.fetchone()['user_id']
        conn.commit()
    finally:
        if conn: cursor.close(); conn.close()

    return {"message": "Student created successfully", "user_id": new_user_id}

# ... (Other endpoints like get_student_details, admin endpoints, etc. remain)

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
