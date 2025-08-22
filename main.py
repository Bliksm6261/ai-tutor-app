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
    role: str 
    first_name: str
    last_name: str

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
    version="0.7.0",
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

# --- Student Endpoints (No Changes) ---
@app.get("/questions/next")
def get_next_question(current_user: TokenData = Depends(get_current_user)):
    # ... existing code ...
    pass

@app.post("/questions/answer")
def submit_answer(submission: AnswerSubmission, current_user: TokenData = Depends(get_current_user)):
    # ... existing code ...
    pass

# --- Teacher Endpoints ---
@app.get("/teacher/dashboard")
def get_teacher_dashboard(current_user: TokenData = Depends(get_current_user)):
    # ... existing code ...
    pass

# --- NEW: Student Detail Endpoint for Teachers ---
@app.get("/teacher/students/{student_id}")
def get_student_details(student_id: int, current_user: TokenData = Depends(get_current_user)):
    """
    Gets the detailed progress for a single student.
    Ensures the requesting user is a teacher/admin from the same school.
    """
    if current_user.role not in ['teacher', 'admin']:
        raise HTTPException(status_code=403, detail="Not authorized")

    conn = get_db_connection()
    if conn is None: raise HTTPException(status_code=500, detail="Database connection failed.")

    try:
        cursor = conn.cursor()
        # Security check: Verify the student belongs to the teacher's school
        cursor.execute(
            """
            SELECT s.school_id FROM users s 
            WHERE s.user_id = %s AND s.role = 'student'
            """, (student_id,)
        )
        student_record = cursor.fetchone()

        cursor.execute("SELECT school_id FROM users WHERE user_id = %s", (current_user.user_id,))
        teacher_record = cursor.fetchone()

        if not student_record or not teacher_record or student_record['school_id'] != teacher_record['school_id']:
            raise HTTPException(status_code=404, detail="Student not found in your school.")

        # Fetch detailed progress
        cursor.execute(
            """
            SELECT knowledge_graph_id, mastery_score FROM student_progress
            WHERE student_id = %s ORDER BY knowledge_graph_id;
            """, (student_id,)
        )
        progress = cursor.fetchall()
        
        # Fetch student info
        cursor.execute("SELECT user_id, first_name, last_name, email FROM users WHERE user_id = %s", (student_id,))
        student_info = cursor.fetchone()

        return {"student_info": student_info, "progress": progress}
    finally:
        if conn: cursor.close(); conn.close()


# --- Super Admin Endpoints (No Changes) ---
@app.post("/admin/schools", status_code=status.HTTP_201_CREATED)
def create_school(school: SchoolCreate, admin_key: str):
    # ... existing code ...
    pass

@app.post("/admin/teachers", status_code=status.HTTP_201_CREATED)
def create_admin_teacher(teacher: AdminTeacherCreate, admin_key: str):
    # ... existing code ...
    pass


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
