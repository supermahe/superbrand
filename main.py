# from fastapi import FastAPI, HTTPException, Depends
# from pydantic import BaseModel
# from sqlmodel import SQLModel, Field, create_engine, Session
# from passlib.context import CryptContext
# import jwt
# from datetime import datetime, timedelta
# from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

# # Initialize FastAPI app
# app = FastAPI()

# # Database setup
# database_url = "sqlite:///./test.db"
# engine = create_engine(database_url)

# # Password hashing setup
# pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# # OAuth2 setup
# oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login/")

# # JWT secret key and algorithm
# SECRET_KEY = "f9deeaf52b5b98de8cd1d8cb8ee92e65c20035cfdf773f01da83765c87e8435e"
# ALGORITHM = "HS256"
# ACCESS_TOKEN_EXPIRE_MINUTES = 30

# def hash_password(password: str) -> str:
#     return pwd_context.hash(password)

# def verify_password(plain_password: str, hashed_password: str) -> bool:
#     return pwd_context.verify(plain_password, hashed_password)

# def create_access_token(data: dict, expires_delta: timedelta | None = None):
#     to_encode = data.copy()
#     expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
#     to_encode.update({"exp": expire})
#     return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# # SQLModel class for User
# class User(SQLModel, table=True):
#     id: int = Field(default=None, primary_key=True)
#     name: str
#     hashed_password: str
#     email: str
#     is_active: bool = True

# # Pydantic model for creating user
# class UserCreate(BaseModel):
#     name: str
#     password: str
#     email: str
#     is_active: bool = True

# # Pydantic model for token response
# class Token(BaseModel):
#     access_token: str
#     token_type: str

# # Create database tables
# SQLModel.metadata.create_all(engine)

# @app.post("/create_user/")
# def create_user(user: UserCreate):
#     hashed_password = hash_password(user.password)
#     new_user = User(
#         name=user.name,
#         hashed_password=hashed_password,
#         email=user.email,
#         is_active=user.is_active
#     )
    
#     with Session(engine) as session:
#         existing_user = session.query(User).filter(User.email == user.email).first()
#         if existing_user:
#             raise HTTPException(status_code=400, detail="User with this email already exists.")
        
#         session.add(new_user)
#         session.commit()
#         session.refresh(new_user)

#     return {"message": "User created successfully", "user_id": new_user.id}

# @app.post("/login/", response_model=Token)
# def login(form_data: OAuth2PasswordRequestForm = Depends()):
#     with Session(engine) as session:
#         user = session.query(User).filter(User.name == form_data.username).first()
#         if not user or not verify_password(form_data.password, user.hashed_password):
#             raise HTTPException(status_code=401, detail="Invalid username or password")
        
#         access_token = create_access_token(data={"sub": user.name})
#         return {"access_token": access_token, "token_type": "bearer"}


from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel, Json
from sqlmodel import SQLModel, Field, create_engine, Session,JSON
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import Optional, Dict
import json

# SQLModel class for User
class User(SQLModel, table=True):
    id: int = Field(default=None, primary_key=True)
    name: str
    hashed_password: str
    email: str
    is_active: bool = True

# SQLModel class for Notebook
class Notebook(SQLModel, table=True):
    id: int = Field(default=None, primary_key=True)
    title: str
    page_no: int
    value: str # JSON content as a string
    user_id: int = Field(foreign_key="user.id")
    created_date: datetime = Field(default_factory=datetime.utcnow)
    modified_date: datetime = Field(default_factory=datetime.utcnow)

# Pydantic model for creating user
class UserCreate(BaseModel):
    name: str
    password: str
    email: str
    is_active: bool = True

# Pydantic model for token response
class Token(BaseModel):
    access_token: str
    token_type: str

# Pydantic model for creating/updating notebook
class NotebookCreateUpdate(BaseModel):
    title: str
    value: dict
    page_no: int

    def json_string(self) -> str:
        return json.dumps(self.value)


# Initialize FastAPI app
app = FastAPI()

# Database setup
database_url = "sqlite:///./test.db"
engine = create_engine(database_url)

# Password hashing setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 setup
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login/")

# JWT secret key and algorithm
SECRET_KEY = "3e2e49285a744f789295cb133221377c"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme)) -> UserCreate:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        with Session(engine) as session:
            user = session.query(User).filter(User.name == username).first()
            if user is None:
                raise HTTPException(status_code=401, detail="User not found")
            return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


# Create database tables
SQLModel.metadata.create_all(engine)

@app.post("/create_user/")
def create_user(user: UserCreate):
    hashed_password = hash_password(user.password)
    new_user = User(
        name=user.name,
        hashed_password=hashed_password,
        email=user.email,
        is_active=user.is_active
    )
    
    with Session(engine) as session:
        existing_user = session.query(User).filter(User.email == user.email).first()
        if existing_user:
            raise HTTPException(status_code=400, detail="User with this email already exists.")
        
        session.add(new_user)
        session.commit()
        session.refresh(new_user)

    return {"message": "User created successfully", "user_id": new_user.id}

@app.post("/login/", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    with Session(engine) as session:
        user = session.query(User).filter(User.name == form_data.username).first()
        if not user or not verify_password(form_data.password, user.hashed_password):
            raise HTTPException(status_code=401, detail="Invalid username or password")
        
        access_token = create_access_token(data={"sub": user.name})
        return {"access_token": access_token, "token_type": "bearer"}

@app.post("/create_notebook/")
def create_notebook(notebook: NotebookCreateUpdate, current_user: User = Depends(get_current_user)):
    new_notebook = Notebook(
        title=notebook.title,
        value=notebook.json_string(),
        page_no=notebook.page_no,
        user_id=current_user.id
    )
    
    with Session(engine) as session:
        session.add(new_notebook)
        session.commit()
        session.refresh(new_notebook)
    
    return {"message": "Notebook created successfully", "notebook_id": new_notebook.id}

@app.put("/update_notebook/{notebook_id}")
def update_notebook(title: str, page_no: int, notebook: NotebookCreateUpdate, current_user: User = Depends(get_current_user)):
    print("Received notebook data:", notebook.dict())  # Inspect incoming data

    with Session(engine) as session:
        # existing_notebook = session.query(Notebook).filter(Notebook.id == notebook_id, Notebook.user_id == current_user.id).first()
        existing_notebook = session.query(Notebook).filter(Notebook.page_no == page_no, Notebook.title == title, Notebook.user_id == current_user.id).first()
        if not existing_notebook:
            raise HTTPException(status_code=404, detail="Notebook not found or not authorized")
        
        existing_notebook.title = notebook.title
        existing_notebook.value = notebook.json_string()
        existing_notebook.page_no = notebook.page_no
        existing_notebook.modified_date = datetime.utcnow()
        # existing_notebook.value = json.dumps(notebook.value)
        session.add(existing_notebook)
        session.commit()
        session.refresh(existing_notebook)
    
    return {"message": "Notebook updated successfully", "notebook_id": existing_notebook.id}

@app.delete("/delete_notebook/{notebook_id}")
def delete_notebook(notebook_id: int, current_user: User = Depends(get_current_user)):
    with Session(engine) as session:
        existing_notebook = session.query(Notebook).filter(Notebook.id == notebook_id, Notebook.user_id == current_user.id).first()
        if not existing_notebook:
            raise HTTPException(status_code=404, detail="Notebook not found or not authorized")
        
        session.delete(existing_notebook)
        session.commit()
    
    return {"message": "Notebook deleted successfully"}

def get_all_notebooks(current_user: User = Depends(get_current_user)):
    with Session(engine) as session:
        notebooks = session.query(Notebook).filter(Notebook.user_id == current_user.id).all()
        return notebooks

@app.get("/get_notebook/")
def get_notebook(notebook_id: Optional[int] = None, title: Optional[str] = None, page_no: Optional[int] = None, current_user: User = Depends(get_current_user)):
    with Session(engine) as session:
        query = session.query(Notebook).filter(Notebook.user_id == current_user.id)
        if notebook_id:
            query = query.filter(Notebook.id == notebook_id)
        # elif title:
        #     query = query.filter(Notebook.title == title)
        elif title and page_no:
            query = query.filter(Notebook.title == title, Notebook.page_no == page_no)
        else:
            raise HTTPException(status_code=400, detail="Must provide either notebook_id or title and page_no")
        
        notebook = query.first()
        if not notebook:
            raise HTTPException(status_code=404, detail="Notebook not found")
        notebook.value = json.loads(notebook.value)
        # print(json.dumps(notebook.value))
        return notebook

