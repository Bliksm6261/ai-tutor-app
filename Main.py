# main.py

from fastapi import FastAPI
import uvicorn

# Create the FastAPI app instance
app = FastAPI()

# Define a "route" for the homepage
@app.get("/")
def read_root():
    return {"message": "Welcome to the AI Tutor API!"}

# Define a test route for learners
@app.get("/learners/{learner_id}")
def get_learner(learner_id: int):
    return {"learner_id": learner_id, "status": "profile active"}

# This part allows running the app locally for testing
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)