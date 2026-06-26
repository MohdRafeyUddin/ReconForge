print("ROUTER AUTH LOADED")


from datetime import datetime
from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordRequestForm
from bson import ObjectId
from app.database import get_database
from app.auth import get_password_hash, verify_password, create_access_token, get_current_user
from app.models import UserCreate, UserResponse, serialize_doc

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post("/register", response_model=UserResponse)
async def register(user_in: UserCreate):
    db = get_database()
    if db is None:
        raise HTTPException(status_code=500, detail="Database not ready")
        
    existing_username = await db.users.find_one({"username": user_in.username})
    if existing_username:
        raise HTTPException(
            status_code=400,
            detail="Username already registered"
        )
        
    existing_email = await db.users.find_one({"email": user_in.email})
    if existing_email:
        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        )
        
    hashed_password = get_password_hash(user_in.password)
    user_dict = {
        "username": user_in.username,
        "email": user_in.email,
        "hashed_password": hashed_password,
        "created_at": datetime.utcnow()
    }
    
    result = await db.users.insert_one(user_dict)
    user_dict["_id"] = result.inserted_id
    
    return serialize_doc(user_dict)



@router.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    db = get_database()
    if db is None:
        raise HTTPException(status_code=500, detail="Database not ready")
        
    user = await db.users.find_one({"username": form_data.username})
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    access_token = create_access_token(
        data={"sub": user["username"], "id": str(user["_id"])}
    )
    return {
        "access_token": access_token, 
        "token_type": "bearer",
        "user": {
            "username": user["username"],
            "email": user["email"],
            "id": str(user["_id"])
        }
    }

@router.get("/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    return {
        "id": str(current_user["_id"]),
        "username": current_user["username"],
        "email": current_user["email"],
        "created_at": current_user["created_at"].isoformat()
    }
