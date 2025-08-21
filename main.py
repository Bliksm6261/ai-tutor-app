# main.py

import os
import psycopg2
from psycopg2.extras import RealDictCursor
from fastapi import FastAPI, HTTPException, status, Depends
from pydantic import BaseModel, EmailStr
from dotenv import load_dotenv
import uvicorn

# --- NEW: CORS Imports ---
from fastapi.middleware.cors import CORSMiddleware

# --- Security Imports ---
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta, timezone

# --- Security Setup ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = os.getenv("SECRET_KEY", "a_very_secret_key_for_initial_dev")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

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

# --- FastAPI App ---
app = FastAPI(
    title="AI Tutor API",
    description="The backend API for the AI-powered adaptive learning platform.",
    version="0.2.0",
)

# --- NEW: CORS Middleware Setup ---
# This list defines which websites are allowed to make requests to your API.
# For development, we allow all origins with "*".
# For production, you would restrict this to your actual frontend domain.
origins = [
    "*", # Allows all origins for now
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"], # Allows all methods (GET, POST, etc.)
    allow_headers=["*"], # Allows all headers
)


# --- API Endpoints ---
@app.get("/")
def read_root():
    return {"message": "Welcome to the AI Tutor API!"}

@app.get("/db-test")
def test_db_connection():
    conn = get_db_connection()
    if conn is None:
        raise HTTPException(status_code=500, detail="Database connection failed.")
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT version();")
        db_version = cursor.fetchone()
        cursor.close()
        conn.close()
        return {"message": "Database connection successful!", "version": db_version['version']}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database query failed: {str(e)}")

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
        cursor.close()
        conn.close()
        return {"message": "User created successfully", "user_id": new_user_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Could not create user: {str(e)}")

@app.post("/login", response_model=Token)
def login_for_access_token(form_data: UserLogin):
    conn = get_db_connection()
    if conn is None:
        raise HTTPException(status_code=500, detail="Database connection failed.")
    
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = %s", (form_data.email,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if not user or not verify_password(form_data.password, user['password_hash']):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token = create_access_token(
        data={"sub": user['email'], "user_id": user['user_id']}
    )
    return {"access_token": access_token, "token_type": "bearer"}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
```text
# requirements.txt
fastapi
uvicorn[standard]
psycopg2-binary
python-dotenv
passlib[bcrypt]
python-jose[cryptography]
pydantic[email]
fastapi-cors
