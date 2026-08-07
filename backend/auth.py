from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
import secrets

router = APIRouter()

# In a real app, this would be in a database with hashed passwords
MOCK_USERS = {
    "admin": "admin",
}

class LoginRequest(BaseModel):
    username: str
    password: str

@router.post("/login")
def login(req: LoginRequest):
    if req.username in MOCK_USERS and MOCK_USERS[req.username] == req.password:
        # Generate a dummy token
        token = secrets.token_hex(16)
        return {"access_token": token, "token_type": "bearer", "username": req.username}
    
    raise HTTPException(status_code=401, detail="Invalid credentials")
