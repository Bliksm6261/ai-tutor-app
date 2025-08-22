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
    description="The backend API for the AI-powered adaptive learning platform.",
    version="0.5.0",
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
    return {"message": "Welcome to the AI Tutor API!"}

@app.post("/register", status_code=status.HTTP_201_CREATED)
def register_user(user: UserCreate):
    hashed_password = get_password_hash(user.password)
    conn = get_db_connection()
    if conn is None:
        raise HTTPException(status_code=500, detail="Database connection failed.")
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = %s", (user.email,))
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail="Email already registered")
        
        cursor.execute(
            "INSERT INTO users (email, password_hash, role, first_name, last_name) VALUES (%s, %s, %s, %s, %s) RETURNING user_id",
            (user.email, hashed_password, user.role, user.first_name, user.last_name)
        )
        new_user_id = cursor.fetchone()['user_id']
        conn.commit()
    finally:
        if conn:
            cursor.close()
            conn.close()
    return {"message": "User created successfully", "user_id": new_user_id}

@app.post("/login", response_model=Token)
def login_for_access_token(form_data: UserLogin):
    conn = get_db_connection()
    if conn is None:
        raise HTTPException(status_code=500, detail="Database connection failed.")
    
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = %s", (form_data.email,))
        user = cursor.fetchone()
    finally:
        if conn:
            cursor.close()
            conn.close()

    if not user or not verify_password(form_data.password, user['password_hash']):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # UPDATED: Add role to the token
    access_token = create_access_token(
        data={"sub": user['email'], "user_id": user['user_id'], "role": user['role']}
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/questions/next")
def get_next_question(current_user: TokenData = Depends(get_current_user)):
    student_id = current_user.user_id
    conn = get_db_connection()
    if conn is None:
        raise HTTPException(status_code=500, detail="Database connection failed.")

    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT knowledge_graph_id FROM student_progress 
            WHERE student_id = %s ORDER BY mastery_score ASC LIMIT 1;
            """, (student_id,)
        )
        weakest_topic_row = cursor.fetchone()
        
        target_topic = 'trig_ratios'
        if weakest_topic_row:
            target_topic = weakest_topic_row['knowledge_graph_id']

        cursor.execute(
            """
            SELECT question_id, question_text, difficulty FROM questions
            WHERE knowledge_graph_id = %s ORDER BY difficulty ASC LIMIT 1;
            """, (target_topic,)
        )
        question = cursor.fetchone()

        if not question:
            raise HTTPException(status_code=404, detail="No more questions found for this topic.")
        return question
    finally:
        if conn:
            cursor.close()
            conn.close()

@app.post("/questions/answer")
def submit_answer(submission: AnswerSubmission, current_user: TokenData = Depends(get_current_user)):
    student_id = current_user.user_id
    conn = get_db_connection()
    if conn is None:
        raise HTTPException(status_code=500, detail="Database connection failed.")

    try:
        cursor = conn.cursor()
        cursor.execute("SELECT answer, knowledge_graph_id FROM questions WHERE question_id = %s", (submission.question_id,))
        question_data = cursor.fetchone()

        if not question_data:
            raise HTTPException(status_code=404, detail="Question not found.")

        is_correct = submission.answer.lower().strip() == question_data['answer'].lower().strip()
        topic_id = question_data['knowledge_graph_id']
        
        mastery_change = 0.1 if is_correct else -0.05
        
        cursor.execute(
            """
            INSERT INTO student_progress (student_id, knowledge_graph_id, mastery_score)
            VALUES (%s, %s, %s)
            ON CONFLICT (student_id, knowledge_graph_id)
            DO UPDATE SET mastery_score = student_progress.mastery_score + %s;
            """,
            (student_id, topic_id, 0.1 + mastery_change, mastery_change)
        )
        conn.commit()
        
        return {"correct": is_correct, "correct_answer": question_data['answer']}
    finally:
        if conn:
            cursor.close()
            conn.close()

# --- NEW: Teacher Dashboard Endpoint ---
@app.get("/teacher/dashboard")
def get_teacher_dashboard(current_user: TokenData = Depends(get_current_user)):
    """
    Gets the list of students and their progress for the logged-in teacher.
    """
    if current_user.role != 'teacher':
        raise HTTPException(status_code=403, detail="Not authorized")

    teacher_id = current_user.user_id
    conn = get_db_connection()
    if conn is None:
        raise HTTPException(status_code=500, detail="Database connection failed.")

    try:
        cursor = conn.cursor()
        # This query joins the users table with the student_progress table
        # to get all students for a teacher and their average mastery score.
        cursor.execute(
            """
            SELECT 
                u.user_id, 
                u.first_name, 
                u.last_name, 
                u.email,
                COALESCE(AVG(sp.mastery_score), 0.1) as average_mastery
            FROM users u
            LEFT JOIN student_progress sp ON u.user_id = sp.student_id
            WHERE u.teacher_id = %s AND u.role = 'student'
            GROUP BY u.user_id
            ORDER BY average_mastery ASC;
            """,
            (teacher_id,)
        )
        students = cursor.fetchall()
        return students
    finally:
        if conn:
            cursor.close()
            conn.close()

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
