# main.py

import os
import psycopg2
from psycopg2.extras import RealDictCursor, Json
from fastapi import FastAPI, Query, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, Field
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
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login")

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
    password_change_required: bool

class PasswordSet(BaseModel):
    new_password: str = Field(..., min_length=8)

class PasswordReset(BaseModel):
    new_password: str = Field(..., min_length=8)
    
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
    
class TeacherCreate(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    password: str
    role: str = 'teacher'
    
class HintResponse(BaseModel):
    hint_level: int
    raw_hint_text: str | None = None
    enhanced_hint_text: str | None = None

class QuestionForReview(BaseModel):
    question_id: int
    raw_question_text: str | None = None
    question_text: str
    answer: str
    status: str
    hints: list[HintResponse]

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
    
def get_current_admin_user(current_user: TokenData = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to perform this action"
        )
    return current_user

def get_current_active_teacher_or_admin(current_user: TokenData = Depends(get_current_user)):
    if current_user.role not in ["teacher", "admin"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized for this action"
        )
    return current_user

# --- FastAPI App ---
app = FastAPI(
    title="AI Tutor API",
    description="The backend API for the Study Chommie platform.",
    version="1.1.0", # Version bump for analytics
)

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

@app.post("/api/login", response_model=Token)
def login_for_access_token(user_credentials: UserLogin):
    conn = get_db_connection()
    if conn is None: raise HTTPException(status_code=500, detail="Database connection failed.")
    
    user = None
    school = None
    try:
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM users WHERE email = %s", (user_credentials.email,))
        user = cursor.fetchone()
        
        if not user or not verify_password(user_credentials.password, user['password_hash']):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")

        if not user['is_active']:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Your account has been disabled.")

        cursor.execute("SELECT is_active FROM schools WHERE school_id = %s", (user['school_id'],))
        school = cursor.fetchone()
        if not school or not school['is_active']:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Your school's account has been disabled.")

        # --- NEW: Log successful login activity ---
        cursor.execute(
            """
            INSERT INTO activity_log (user_id, school_id, activity_type, details)
            VALUES (%s, %s, 'login', %s)
            """,
            (user['user_id'], user['school_id'], Json({"role": user['role']}))
        )
        conn.commit()
            
    finally:
        if conn: 
            cursor.close()
            conn.close()

    access_token = create_access_token(data={"sub": user['email'], "user_id": user['user_id'], "role": user['role']})
    return {
        "access_token": access_token, 
        "token_type": "bearer",
        "password_change_required": user['password_change_required']
    }

# --- Student Endpoints ---
@app.get("/api/questions/next")
def get_next_question(current_user: TokenData = Depends(get_current_user)):
    student_id = current_user.user_id
    conn = get_db_connection()
    if conn is None: raise HTTPException(status_code=500, detail="Database connection failed.")
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT knowledge_graph_id FROM student_progress WHERE student_id = %s ORDER BY mastery_score ASC LIMIT 1;", (student_id,))
        weakest_topic_row = cursor.fetchone()
        target_topic = 'trig_ratios'
        if weakest_topic_row:
            target_topic = weakest_topic_row['knowledge_graph_id']
        
        cursor.execute("SELECT question_id, question_text, difficulty FROM questions WHERE knowledge_graph_id = %s AND status = 'approved' ORDER BY RANDOM() LIMIT 1;", (target_topic,))
        question = cursor.fetchone()

        if not question:
            cursor.execute("SELECT question_id, question_text, difficulty FROM questions WHERE status = 'approved' ORDER BY RANDOM() LIMIT 1;")
            question = cursor.fetchone()
            if not question:
                 raise HTTPException(status_code=404, detail="No approved questions are available in the system.")
        return question
    finally:
        if conn: cursor.close(); conn.close()

@app.post("/api/questions/answer")
def submit_answer(submission: AnswerSubmission, current_user: TokenData = Depends(get_current_user)):
    student_id = current_user.user_id
    conn = get_db_connection()
    if conn is None: raise HTTPException(status_code=500, detail="Database connection failed.")
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT answer, knowledge_graph_id FROM questions WHERE question_id = %s", (submission.question_id,))
        question_data = cursor.fetchone()
        if not question_data: raise HTTPException(status_code=404, detail="Question not found.")
        is_correct = submission.answer.lower().strip() == question_data['answer'].lower().strip()
        topic_id = question_data['knowledge_graph_id']
        
        if is_correct:
            mastery_change = 0.1
            cursor.execute("INSERT INTO student_progress (student_id, knowledge_graph_id, mastery_score, incorrect_attempts) VALUES (%s, %s, 0.1, 0) ON CONFLICT (student_id, knowledge_graph_id) DO UPDATE SET mastery_score = LEAST(1.0, student_progress.mastery_score + %s), incorrect_attempts = 0;",(student_id, topic_id, mastery_change))
        else:
            mastery_change = -0.05
            cursor.execute("INSERT INTO student_progress (student_id, knowledge_graph_id, mastery_score, incorrect_attempts) VALUES (%s, %s, 0.0, 1) ON CONFLICT (student_id, knowledge_graph_id) DO UPDATE SET mastery_score = GREATEST(0.0, student_progress.mastery_score + %s), incorrect_attempts = student_progress.incorrect_attempts + 1;",(student_id, topic_id, mastery_change))
        
        # --- NEW: Log question answered activity ---
        cursor.execute("SELECT school_id FROM users WHERE user_id = %s", (student_id,))
        user_school = cursor.fetchone()
        cursor.execute(
            """
            INSERT INTO activity_log (user_id, school_id, activity_type, details)
            VALUES (%s, %s, 'question_answered', %s)
            """,
            (student_id, user_school['school_id'], Json({"question_id": submission.question_id, "correct": is_correct}))
        )
        
        conn.commit()
        cursor.execute("SELECT incorrect_attempts FROM student_progress WHERE student_id = %s AND knowledge_graph_id = %s", (student_id, topic_id))
        progress_data = cursor.fetchone()
        incorrect_count = progress_data['incorrect_attempts'] if progress_data else 0
        return {"correct": is_correct, "correct_answer": question_data['answer'], "incorrect_attempts": incorrect_count}
    finally:
        if conn: cursor.close(); conn.close()

# ... (The rest of your file remains the same)
@app.get("/api/questions/hint/{question_id}")
def get_hint_for_question(question_id: int, level: int = Query(..., ge=1), current_user: TokenData = Depends(get_current_user)):
    conn = get_db_connection()
    if conn is None: raise HTTPException(status_code=500, detail="Database connection failed.")
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT enhanced_hint_text FROM hints WHERE question_id = %s AND hint_level = %s", (question_id, level))
        hint = cursor.fetchone()
        if not hint: raise HTTPException(status_code=404, detail=f"Hint level {level} not found for this question.")
        return {"hint_text": hint['enhanced_hint_text']}
    finally:
        if conn: cursor.close(); conn.close()

@app.get("/api/teacher/dashboard")
def get_teacher_dashboard(current_user: TokenData = Depends(get_current_user)):
    if current_user.role not in ['teacher', 'admin']: raise HTTPException(status_code=403, detail="Not authorized")
    teacher_id = current_user.user_id
    conn = get_db_connection()
    if conn is None: raise HTTPException(status_code=500, detail="Database connection failed.")
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT u.user_id, u.first_name, u.last_name, u.email, u.is_active, COALESCE(AVG(sp.mastery_score), 0.0) as average_mastery FROM users u JOIN classes c ON u.class_id = c.class_id LEFT JOIN student_progress sp ON u.user_id = sp.student_id WHERE c.teacher_id = %s AND u.role = 'student' GROUP BY u.user_id ORDER BY u.last_name ASC;", (teacher_id,))
        students = cursor.fetchall()
        return students
    finally:
        if conn: cursor.close(); conn.close()

@app.post("/api/teacher/classes", status_code=status.HTTP_201_CREATED)
def create_class(class_data: ClassCreate, current_user: TokenData = Depends(get_current_user)):
    if current_user.role not in ['teacher', 'admin']: raise HTTPException(status_code=403, detail="Not authorized")
    teacher_id = current_user.user_id
    conn = get_db_connection()
    if conn is None: raise HTTPException(status_code=500, detail="Database connection failed.")
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT school_id FROM users WHERE user_id = %s", (teacher_id,))
        teacher_school = cursor.fetchone()
        if not teacher_school or not teacher_school['school_id']: raise HTTPException(status_code=404, detail="Teacher not found or not assigned to a school.")
        school_id = teacher_school['school_id']
        cursor.execute("INSERT INTO classes (name, teacher_id, school_id) VALUES (%s, %s, %s) RETURNING class_id", (class_data.name, teacher_id, school_id))
        new_class_id = cursor.fetchone()['class_id']
        conn.commit()
        return {"message": "Class created successfully", "class_id": new_class_id}
    finally:
        if conn: cursor.close(); conn.close()

@app.post("/api/teacher/students", status_code=status.HTTP_201_CREATED)
def create_student(student: StudentCreate, current_user: TokenData = Depends(get_current_user)):
    if current_user.role not in ['teacher', 'admin']: raise HTTPException(status_code=403, detail="Not authorized")
    conn = get_db_connection()
    if conn is None: raise HTTPException(status_code=500, detail="Database connection failed.")
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT school_id FROM users WHERE user_id = %s", (current_user.user_id,))
        teacher_school = cursor.fetchone()
        if not teacher_school: raise HTTPException(status_code=404, detail="Teacher not found.")
        school_id = teacher_school['school_id']
        cursor.execute("SELECT COUNT(*) as count FROM users WHERE school_id = %s AND role = 'student'", (school_id,))
        student_count = cursor.fetchone()['count']
        cursor.execute("SELECT max_students FROM schools WHERE school_id = %s", (school_id,))
        school_limits = cursor.fetchone()
        if not school_limits or student_count >= school_limits['max_students']: raise HTTPException(status_code=403, detail="Student limit for this school has been reached.")
        cursor.execute("SELECT * FROM users WHERE email = %s", (student.email,))
        if cursor.fetchone(): raise HTTPException(status_code=400, detail="Email already registered")
        hashed_password = get_password_hash(student.password)
        cursor.execute("INSERT INTO users (email, password_hash, role, first_name, last_name, school_id, class_id) VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING user_id", (student.email, hashed_password, student.role, student.first_name, student.last_name, school_id, student.class_id))
        new_user_id = cursor.fetchone()['user_id']
        conn.commit()
        return {"message": "Student created successfully", "user_id": new_user_id}
    finally:
        if conn: cursor.close(); conn.close()

@app.post("/api/teacher/teachers", status_code=status.HTTP_201_CREATED)
def create_teacher(teacher: TeacherCreate, current_user: TokenData = Depends(get_current_admin_user)):
    conn = get_db_connection()
    if conn is None: raise HTTPException(status_code=500, detail="Database connection failed.")
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT school_id FROM users WHERE user_id = %s", (current_user.user_id,))
        admin_record = cursor.fetchone()
        if not admin_record: raise HTTPException(status_code=404, detail="Admin user not found.")
        school_id = admin_record['school_id']
        cursor.execute("SELECT max_teachers FROM schools WHERE school_id = %s", (school_id,))
        school_limits = cursor.fetchone()
        cursor.execute("SELECT COUNT(*) as count FROM users WHERE school_id = %s AND role IN ('teacher', 'admin')", (school_id,))
        teacher_count = cursor.fetchone()['count']
        if not school_limits or teacher_count >= school_limits['max_teachers']: raise HTTPException(status_code=403, detail="Teacher limit for this school has been reached.")
        cursor.execute("SELECT * FROM users WHERE email = %s", (teacher.email,))
        if cursor.fetchone(): raise HTTPException(status_code=400, detail="Email already registered")
        hashed_password = get_password_hash(teacher.password)
        cursor.execute("INSERT INTO users (email, password_hash, role, first_name, last_name, school_id) VALUES (%s, %s, %s, %s, %s, %s) RETURNING user_id", (teacher.email, hashed_password, teacher.role, teacher.first_name, teacher.last_name, school_id))
        new_user_id = cursor.fetchone()['user_id']
        conn.commit()
        return {"message": "Teacher created successfully", "user_id": new_user_id}
    finally:
        if conn: cursor.close(); conn.close()

@app.get("/api/teacher/students/{student_id}")
def get_student_details(student_id: int, current_user: TokenData = Depends(get_current_user)):
    if current_user.role not in ['teacher', 'admin']: raise HTTPException(status_code=403, detail="Not authorized")
    conn = get_db_connection()
    if conn is None: raise HTTPException(status_code=500, detail="Database connection failed.")
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT school_id FROM users WHERE user_id = %s", (student_id,))
        student_record = cursor.fetchone()
        cursor.execute("SELECT school_id FROM users WHERE user_id = %s", (current_user.user_id,))
        teacher_record = cursor.fetchone()
        if not student_record or not teacher_record or student_record['school_id'] != teacher_record['school_id']: raise HTTPException(status_code=404, detail="Student not found in your school.")
        cursor.execute("SELECT knowledge_graph_id, mastery_score FROM student_progress WHERE student_id = %s ORDER BY knowledge_graph_id;", (student_id,))
        progress = cursor.fetchall()
        cursor.execute("SELECT user_id, first_name, last_name, email FROM users WHERE user_id = %s", (student_id,))
        student_info = cursor.fetchone()
        return {"student_info": student_info, "progress": progress}
    finally:
        if conn: cursor.close(); conn.close()

@app.post("/api/admin/schools", status_code=status.HTTP_201_CREATED)
def create_school(school: SchoolCreate, admin_key: str):
    if admin_key != SUPER_ADMIN_API_KEY: raise HTTPException(status_code=403, detail="Not authorized")
    conn = get_db_connection()
    if conn is None: raise HTTPException(status_code=500, detail="Database connection failed.")
    try:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO schools (name, max_students, max_teachers) VALUES (%s, %s, %s) RETURNING school_id", (school.name, school.max_students, school.max_teachers))
        new_school_id = cursor.fetchone()['school_id']
        conn.commit()
        return {"message": "School created successfully", "school_id": new_school_id}
    finally:
        if conn: cursor.close(); conn.close()

@app.post("/api/admin/teachers", status_code=status.HTTP_201_CREATED)
def create_admin_teacher(teacher: AdminTeacherCreate, admin_key: str):
    if admin_key != SUPER_ADMIN_API_KEY: raise HTTPException(status_code=403, detail="Not authorized")
    hashed_password = get_password_hash(teacher.password)
    conn = get_db_connection()
    if conn is None: raise HTTPException(status_code=500, detail="Database connection failed.")
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = %s", (teacher.email,))
        if cursor.fetchone(): raise HTTPException(status_code=400, detail="Email already registered")
        cursor.execute("SELECT COUNT(*) as count FROM users WHERE school_id = %s AND role IN ('teacher', 'admin')", (teacher.school_id,))
        teacher_count = cursor.fetchone()['count']
        cursor.execute("SELECT max_teachers FROM schools WHERE school_id = %s", (teacher.school_id,))
        school_limits = cursor.fetchone()
        if not school_limits or teacher_count >= school_limits['max_teachers']: raise HTTPException(status_code=403, detail="Teacher limit for this school has been reached.")
        cursor.execute("INSERT INTO users (email, password_hash, role, first_name, last_name, school_id) VALUES (%s, %s, %s, %s, %s, %s) RETURNING user_id", (teacher.email, hashed_password, teacher.role, teacher.first_name, teacher.last_name, teacher.school_id))
        new_user_id = cursor.fetchone()['user_id']
        conn.commit()
        return {"message": "Admin teacher created successfully", "user_id": new_user_id}
    finally:
        if conn: cursor.close(); conn.close()

@app.get("/api/content/review", response_model=list[QuestionForReview])
def get_questions_for_review(admin_key: str):
    if admin_key != SUPER_ADMIN_API_KEY: raise HTTPException(status_code=403, detail="Not authorized")
    conn = get_db_connection()
    if conn is None: raise HTTPException(status_code=500, detail="Database connection failed.")
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM questions WHERE status = 'pending_review' ORDER BY question_id;")
        questions = cursor.fetchall()
        results = []
        for q in questions:
            cursor.execute("SELECT hint_level, raw_hint_text, enhanced_hint_text FROM hints WHERE question_id = %s ORDER BY hint_level;", (q['question_id'],))
            hints = cursor.fetchall()
            q['hints'] = hints 
            results.append(q)
        return results
    finally:
        if conn: cursor.close(); conn.close()

@app.post("/api/content/approve/{question_id}", status_code=status.HTTP_200_OK)
def approve_question(question_id: int, admin_key: str):
    if admin_key != SUPER_ADMIN_API_KEY: raise HTTPException(status_code=403, detail="Not authorized")
    conn = get_db_connection()
    if conn is None: raise HTTPException(status_code=500, detail="Database connection failed.")
    try:
        cursor = conn.cursor()
        cursor.execute("UPDATE questions SET status = 'approved' WHERE question_id = %s;", (question_id,))
        if cursor.rowcount == 0: raise HTTPException(status_code=404, detail="Question not found.")
        conn.commit()
        return {"message": f"Question {question_id} has been approved."}
    finally:
        if conn: cursor.close(); conn.close()

@app.delete("/api/content/reject/{question_id}", status_code=status.HTTP_200_OK)
def reject_question(question_id: int, admin_key: str):
    if admin_key != SUPER_ADMIN_API_KEY: raise HTTPException(status_code=403, detail="Not authorized")
    conn = get_db_connection()
    if conn is None: raise HTTPException(status_code=500, detail="Database connection failed.")
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM hints WHERE question_id = %s;", (question_id,))
        cursor.execute("DELETE FROM questions WHERE question_id = %s;", (question_id,))
        if cursor.rowcount == 0: raise HTTPException(status_code=404, detail="Question not found or already deleted.")
        conn.commit()
        return {"message": f"Question {question_id} and its hints have been rejected and deleted."}
    finally:
        if conn: cursor.close(); conn.close()

@app.patch("/api/teacher/students/{student_id}/disable", status_code=status.HTTP_204_NO_CONTENT)
def disable_student(student_id: int, current_user: TokenData = Depends(get_current_active_teacher_or_admin)):
    conn = get_db_connection()
    if conn is None: raise HTTPException(status_code=500, detail="Database connection failed.")
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT school_id FROM users WHERE user_id = %s", (current_user.user_id,))
        teacher_record = cursor.fetchone()
        cursor.execute("SELECT school_id FROM users WHERE user_id = %s", (student_id,))
        student_record = cursor.fetchone()
        if not student_record: raise HTTPException(status_code=404, detail="Student not found")
        if not teacher_record or teacher_record['school_id'] != student_record['school_id']: raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to manage this student")
        cursor.execute("UPDATE users SET is_active = false WHERE user_id = %s", (student_id,))
        conn.commit()
    finally:
        if conn: cursor.close(); conn.close()

@app.patch("/api/teacher/students/{student_id}/enable", status_code=status.HTTP_204_NO_CONTENT)
def enable_student(student_id: int, current_user: TokenData = Depends(get_current_active_teacher_or_admin)):
    conn = get_db_connection()
    if conn is None: raise HTTPException(status_code=500, detail="Database connection failed.")
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT school_id FROM users WHERE user_id = %s", (current_user.user_id,))
        teacher_record = cursor.fetchone()
        cursor.execute("SELECT school_id FROM users WHERE user_id = %s", (student_id,))
        student_record = cursor.fetchone()
        if not student_record: raise HTTPException(status_code=404, detail="Student not found")
        if not teacher_record or teacher_record['school_id'] != student_record['school_id']: raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to manage this student")
        cursor.execute("UPDATE users SET is_active = true WHERE user_id = %s", (student_id,))
        conn.commit()
    finally:
        if conn: cursor.close(); conn.close()

@app.get("/api/admin/schools/all")
def get_all_schools(admin_key: str):
    if admin_key != SUPER_ADMIN_API_KEY: raise HTTPException(status_code=403, detail="Not authorized")
    conn = get_db_connection()
    if conn is None: raise HTTPException(status_code=500, detail="Database connection failed.")
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT school_id, name, is_active FROM schools ORDER BY name;")
        schools = cursor.fetchall()
        return schools
    finally:
        if conn: cursor.close(); conn.close()

@app.get("/api/admin/teachers/all")
def get_all_teachers(admin_key: str):
    if admin_key != SUPER_ADMIN_API_KEY: raise HTTPException(status_code=403, detail="Not authorized")
    conn = get_db_connection()
    if conn is None: raise HTTPException(status_code=500, detail="Database connection failed.")
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT user_id, first_name, last_name, email, school_id, is_active FROM users WHERE role IN ('teacher', 'admin') ORDER BY last_name;")
        teachers = cursor.fetchall()
        return teachers
    finally:
        if conn: cursor.close(); conn.close()

@app.patch("/api/admin/teachers/{teacher_id}/disable", status_code=status.HTTP_204_NO_CONTENT)
def disable_teacher(teacher_id: int, admin_key: str):
    if admin_key != SUPER_ADMIN_API_KEY: raise HTTPException(status_code=403, detail="Not authorized")
    conn = get_db_connection()
    if conn is None: raise HTTPException(status_code=500, detail="Database connection failed.")
    try:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET is_active = false WHERE user_id = %s AND role IN ('teacher', 'admin')", (teacher_id,))
        if cursor.rowcount == 0: raise HTTPException(status_code=404, detail="Teacher or admin user not found.")
        conn.commit()
    finally:
        if conn: cursor.close(); conn.close()

@app.patch("/api/admin/teachers/{teacher_id}/enable", status_code=status.HTTP_204_NO_CONTENT)
def enable_teacher(teacher_id: int, admin_key: str):
    if admin_key != SUPER_ADMIN_API_KEY: raise HTTPException(status_code=403, detail="Not authorized")
    conn = get_db_connection()
    if conn is None: raise HTTPException(status_code=500, detail="Database connection failed.")
    try:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET is_active = true WHERE user_id = %s AND role IN ('teacher', 'admin')", (teacher_id,))
        if cursor.rowcount == 0: raise HTTPException(status_code=404, detail="Teacher or admin user not found.")
        conn.commit()
    finally:
        if conn: cursor.close(); conn.close()

@app.patch("/api/admin/schools/{school_id}/disable", status_code=status.HTTP_204_NO_CONTENT)
def disable_school(school_id: int, admin_key: str):
    if admin_key != SUPER_ADMIN_API_KEY: raise HTTPException(status_code=403, detail="Not authorized")
    conn = get_db_connection()
    if conn is None: raise HTTPException(status_code=500, detail="Database connection failed.")
    try:
        cursor = conn.cursor()
        cursor.execute("UPDATE schools SET is_active = false WHERE school_id = %s", (school_id,))
        if cursor.rowcount == 0: raise HTTPException(status_code=404, detail="School not found.")
        conn.commit()
    finally:
        if conn: cursor.close(); conn.close()

@app.patch("/api/admin/schools/{school_id}/enable", status_code=status.HTTP_204_NO_CONTENT)
def enable_school(school_id: int, admin_key: str):
    if admin_key != SUPER_ADMIN_API_KEY: raise HTTPException(status_code=403, detail="Not authorized")
    conn = get_db_connection()
    if conn is None: raise HTTPException(status_code=500, detail="Database connection failed.")
    try:
        cursor = conn.cursor()
        cursor.execute("UPDATE schools SET is_active = true WHERE school_id = %s", (school_id,))
        if cursor.rowcount == 0: raise HTTPException(status_code=404, detail="School not found.")
        conn.commit()
    finally:
        if conn: cursor.close(); conn.close()

@app.post("/api/users/me/set-password", status_code=status.HTTP_204_NO_CONTENT)
def set_initial_password(password_data: PasswordSet, current_user: TokenData = Depends(get_current_user)):
    hashed_password = get_password_hash(password_data.new_password)
    conn = get_db_connection()
    if conn is None: raise HTTPException(status_code=500, detail="Database connection failed.")
    try:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password_hash = %s, password_change_required = false WHERE user_id = %s", (hashed_password, current_user.user_id))
        conn.commit()
    finally:
        if conn: cursor.close(); conn.close()

@app.patch("/api/teacher/students/{student_id}/reset-password", status_code=status.HTTP_204_NO_CONTENT)
def reset_student_password(student_id: int, password_data: PasswordReset, current_user: TokenData = Depends(get_current_active_teacher_or_admin)):
    conn = get_db_connection()
    if conn is None: raise HTTPException(status_code=500, detail="Database connection failed.")
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT school_id FROM users WHERE user_id = %s", (student_id,))
        student = cursor.fetchone()
        if not student: raise HTTPException(status_code=404, detail="Student not found")
        cursor.execute("SELECT school_id FROM users WHERE user_id = %s", (current_user.user_id,))
        teacher = cursor.fetchone()
        if student['school_id'] != teacher['school_id']: raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to manage this student")
        hashed_password = get_password_hash(password_data.new_password)
        cursor.execute("UPDATE users SET password_hash = %s, password_change_required = true WHERE user_id = %s", (hashed_password, student_id))
        conn.commit()
    finally:
        if conn: cursor.close(); conn.close()

@app.get("/api/admin/usage/summary")
def get_usage_summary(admin_key: str):
    """Provides a high-level summary of platform usage."""
    if admin_key != SUPER_ADMIN_API_KEY:
        raise HTTPException(status_code=403, detail="Not authorized")

    conn = get_db_connection()
    if conn is None: raise HTTPException(status_code=500, detail="Database connection failed.")
    
    try:
        cursor = conn.cursor()
        
        # Total questions answered in the last 30 days
        cursor.execute("""
            SELECT COUNT(*) as count 
            FROM activity_log 
            WHERE activity_type = 'question_answered' AND timestamp >= NOW() - INTERVAL '30 days';
        """)
        questions_answered = cursor.fetchone()['count']
        
        # Total logins in the last 30 days
        cursor.execute("""
            SELECT COUNT(*) as count 
            FROM activity_log 
            WHERE activity_type = 'login' AND timestamp >= NOW() - INTERVAL '30 days';
        """)
        logins = cursor.fetchone()['count']

        # Total active students
        cursor.execute("SELECT COUNT(*) as count FROM users WHERE role = 'student' AND is_active = true;")
        active_students = cursor.fetchone()['count']

        return {
            "questions_answered_last_30_days": questions_answered,
            "logins_last_30_days": logins,
            "active_students": active_students
        }
    finally:
        if conn: cursor.close(); conn.close()

@app.get("/api/admin/usage/schools")
def get_school_usage(admin_key: str):
    """Provides a breakdown of usage statistics per school for the last 30 days."""
    if admin_key != SUPER_ADMIN_API_KEY:
        raise HTTPException(status_code=403, detail="Not authorized")

    conn = get_db_connection()
    if conn is None: raise HTTPException(status_code=500, detail="Database connection failed.")
    
    try:
        cursor = conn.cursor()
        
        # This single, more advanced query gets all the data we need
        cursor.execute("""
            SELECT 
                s.school_id,
                s.name,
                s.is_active,
                COUNT(DISTINCT a.user_id) FILTER (WHERE a.activity_type = 'login' AND a.timestamp >= NOW() - INTERVAL '30 days') as active_users_last_30_days,
                COUNT(*) FILTER (WHERE a.activity_type = 'question_answered' AND a.timestamp >= NOW() - INTERVAL '30 days') as questions_answered_last_30_days
            FROM 
                schools s
            LEFT JOIN 
                activity_log a ON s.school_id = a.school_id
            GROUP BY 
                s.school_id, s.name, s.is_active
            ORDER BY 
                questions_answered_last_30_days DESC;
        """)
        school_stats = cursor.fetchall()
        
        return school_stats
    finally:
        if conn: cursor.close(); conn.close()

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
