# main.py

import os
import psycopg2
from fastapi import FastAPI, HTTPException
from dotenv import load_dotenv
import uvicorn

# Load environment variables from a .env file (for local development)
load_dotenv()

# --- Database Connection ---
# Get database credentials from environment variables
DB_NAME = "ai_tutor_db"
DB_USER = "ai_tutor_user"
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_HOST = "localhost" # Since the DB is on the same server

def get_db_connection():
    """Establishes and returns a connection to the database."""
    try:
        conn = psycopg2.connect(
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
            host=DB_HOST
        )
        return conn
    except psycopg2.OperationalError as e:
        # This will help us debug connection issues
        print(f"Error connecting to database: {e}")
        return None

# --- FastAPI App ---
app = FastAPI(
    title="AI Tutor API",
    description="The backend API for the AI-powered adaptive learning platform.",
    version="0.1.0",
)

@app.get("/")
def read_root():
    """Root endpoint that returns a welcome message."""
    return {"message": "Welcome to the AI Tutor API!"}

# --- NEW: Database Test Endpoint ---
@app.get("/db-test")
def test_db_connection():
    """Tests the connection to the PostgreSQL database."""
    conn = get_db_connection()
    if conn is None:
        raise HTTPException(status_code=500, detail="Database connection failed.")
    
    try:
        # Execute a simple query to get the PostgreSQL version
        cursor = conn.cursor()
        cursor.execute("SELECT version();")
        db_version = cursor.fetchone()[0]
        cursor.close()
        conn.close()
        return {"message": "Database connection successful!", "version": db_version}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database query failed: {str(e)}")


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)