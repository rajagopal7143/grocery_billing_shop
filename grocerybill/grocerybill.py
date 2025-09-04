import uvicorn
from fastapi import FastAPI, Form, Request, Depends, HTTPException, status, Body, Path, Query
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, FileResponse, StreamingResponse
from fastapi.security import OAuth2PasswordBearer
from fastapi.templating import Jinja2Templates
from sqlalchemy import create_engine, Column, Integer, String, Float, ForeignKey, DateTime, func, extract, PrimaryKeyConstraint, text
from sqlalchemy.orm import sessionmaker, Session, declarative_base, relationship
from passlib.context import CryptContext
from jose import JWTError, jwt
from pydantic import BaseModel, EmailStr, PositiveInt, constr
from datetime import datetime, timedelta
from typing import Optional
from starlette.status import HTTP_303_SEE_OTHER
from flask_sqlalchemy import SQLAlchemy
from flask import Flask, render_template, request, redirect, url_for, flash
from sqlalchemy.exc import IntegrityError, OperationalError
from auth import get_current_user, User 
from fastapi.requests import Request
# <-- Also corrected
import qrcode
import io, csv
# -------------------------------------------------------------------
# 1. Configuration & Database Setup
# -------------------------------------------------------------------
app = FastAPI()
# --- IMPORTANT ---
# Update this connection string with your actual MySQL database details.
# Format: "mysql+pymysql://<user>:<password>@<host>/<database_name>"
DATABASE_URL = "mysql+pymysql://fastapi_user:your_password@localhost/grocery_shop_db"

# JWT Configuration
SECRET_KEY = "a_very_secret_key_that_should_be_changed"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

templates = Jinja2Templates(directory="templates")

# SQLAlchemy Engine & Session
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for declarative models
Base = declarative_base()

# -------------------------------------------------------------------
# 2. SQLAlchemy Models
db = SQLAlchemy()

class Product(db.Model):
    __tablename__ = 'products'
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(20), unique=True, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    image_url = db.Column(db.String(255))
    price = db.Column(db.Float, nullable=False)
    sales = db.relationship('Sale', backref='product', cascade="all, delete", passive_deletes=True)

class Sale(db.Model):
    __tablename__ = 'sales'
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id', ondelete="CASCADE"))
    quantity = db.Column(db.Integer, nullable=False)
    total_price = db.Column(db.Float, nullable=False)
    date = db.Column(db.DateTime, nullable=False)
# -------------------------------------------------------------------

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    hashed_password = Column(String(100), nullable=False)
    sales = relationship("Sale", back_populates="user")

class Product(Base):
    __tablename__ = "products"
    id = Column(Integer, primary_key=True, index=True)
    code = Column(String(10), unique=True, index=True, nullable=False)
    category = Column(String(50), nullable=False)
    name = Column(String(100), nullable=False)
    image_url = Column(String(250), nullable=False)
    price = Column(Float, nullable=False)


class Sale(Base):
    __tablename__ = "sales"

    # --- FIX: ADD primary_key=True ---
    # This tells SQLAlchemy that the 'id' column is the primary key for the 'sales' table.
    id = Column(Integer, primary_key=True, index=True)

    # --- Ensure other columns are correct ---
    product_id = Column(Integer, ForeignKey("products.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    quantity = Column(Integer)
    total_price = Column(Float)
    payment_method = Column(String(50))
    sale_date = Column(DateTime, default=datetime.utcnow)

    # --- Relationships ---
    user = relationship("User", back_populates="sales")
    product = relationship("Product")


class Customer(Base):
    __tablename__ = "customers"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    email = Column(String(100), unique=True, index=True)
    phone = Column(String(20), nullable=True)
    address = Column(String(250), nullable=True)
    registered_on = Column(DateTime, default=datetime.utcnow)

class Payment(Base):
    __tablename__ = "payments"
    id = Column(Integer, primary_key=True, index=True)
    order_id = Column(String(50), unique=True, index=True)
    amount = Column(Float, nullable=False)
    status = Column(String(50), nullable=False)  # e.g., initiated, success, failed
    payment_gateway_id = Column(String(100))     # gateway's payment ID
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# -------------------------------------------------------------------
# 3. Pydantic Models (Data Schemas)
# -------------------------------------------------------------------
class ProductBase(BaseModel):
    category: str
    name: str
    image_url: str
    price: float

class ProductCreate(ProductBase):
    code: str

class ProductUpdate(ProductBase):
    pass

class CustomerCreate(BaseModel):
    name: str
    email: EmailStr
    phone: Optional[str] = None
    address: Optional[str] = None

class PurchaseItem(BaseModel):
    code: str
    quantity: int

class CustomerInfo(BaseModel):
    name: str
    email: EmailStr
    phone: Optional[str] = None
    address: Optional[str] = None

class NewCustomer(BaseModel):
    name: str
    email: EmailStr
    phone: str | None = None
    address: str | None = None

class PurchasePayload(BaseModel):
    items: list[PurchaseItem]
    customer: CustomerInfo

# -------------------------------------------------------------------
# 4. Security & Utility Functions
# -------------------------------------------------------------------

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# -------------------------------------------------------------------
# 5. Initial Product Data & Loading Function
# -------------------------------------------------------------------

products_data = [  ]

def load_products_data():
    db: Session = SessionLocal()
    try:
        for prod in products_data:
            exists = db.query(Product).filter_by(code=prod["code"]).first()
            if not exists:
                db.add(Product(**prod))
        db.commit()
        print("Product data loaded successfully.")
    except Exception as e:
        db.rollback()
        print(f"Error loading product data: {e}")
    finally:
        db.close()

# -------------------------------------------------------------------
# 6. FastAPI Application Initialization
# -------------------------------------------------------------------

app = FastAPI(title="Grocery Shop API")

# Add a startup event to create DB tables and load initial data
@app.on_event("startup")
def on_startup():
    print("Application starting up...")
    try:
        Base.metadata.create_all(bind=engine)
        print("Database tables created.")
        load_products_data()
    except Exception as e:
        print(f"An error occurred during startup: {e}")

# -------------------------------------------------------------------
# 7. Dependencies
# -------------------------------------------------------------------

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_user(db: Session, username: str):
    return db.query(User).filter(User.username == username).first()

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: Optional[str] = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = get_user(db, username)
    if not user:
        raise credentials_exception
    return user

# -------------------------------------------------------------------
# 8. Routes / Endpoints
# -------------------------------------------------------------------

# Home Page
@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <html>
    <head>
        <title>Fresh Grocery Shop</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
        <style>
            body {
                margin: 0;
                min-height: 100vh;
                font-family: 'Segoe UI', 'Roboto', Arial, sans-serif;
                background: linear-gradient(120deg, #f0354e 0%, #6f82a6 100%);
                display: flex;
                justify-content: center;
                align-items: center;
            }
            .centerbox {
                background: rgba(255,255,255,0.95);
                border-radius: 20px;
                box-shadow: 0 6px 32px rgba(44, 108, 70, 0.09);
                text-align: center;
                padding: 54px 36px 38px 36px;
                max-width: 420px;
                width: 95%;
                animation: floatIn 1.3s cubic-bezier(.31,.57,.54,.99);
            }
            @keyframes floatIn {
                from { transform: translateY(-30px) scale(0.94); opacity: 0; }
                to { transform: translateY(0) scale(1); opacity: 1; }
            }
            .headline {
                font-size: 2.5em;
                font-weight: 700;
                color: #199660;
                margin-bottom: 16px;
                line-height: 1.2;
                letter-spacing: 1px;
            }
            .subtext {
                color: #222;
                font-size: 1.14em;
                margin-bottom: 34px;
                font-weight: 400;
                opacity: 0.9;
            }
            .anim {
                width: 130px;
                margin: 10px auto 30px auto;
                animation: float 2.8s ease-in-out infinite alternate;
                display: block;
            }
            @keyframes float {
                from { transform: translateY(0); }
                to { transform: translateY(-22px); }
            }
            .button-row {
                display: flex;
                justify-content: center;
                gap: 22px;
                margin-top: 14px;
            }
            .bbtn {
                background: linear-gradient(90deg, #34e89e 0%, #0fbe69 100%);
                color: white;
                border: none;
                outline: none;
                font-weight: 600;
                font-size: 1.17em;
                border-radius: 8px;
                padding: 12px 38px;
                cursor: pointer;
                box-shadow: 0 4px 19px rgba(44, 108, 70, 0.11);
                text-decoration: none;
                letter-spacing: 0.2px;
                transition: background 0.3s, transform 0.16s;
                position: relative;
                overflow: hidden;
            }
            .bbtn:hover {
                background: linear-gradient(92deg, #22a86b 0%, #23c386 100%);
                transform: translateY(-2px) scale(1.04);
            }
            @media (max-width: 600px) {
                .centerbox { padding: 27px 5vw 26px 5vw;}
                .headline { font-size: 1.5em; }
                .subtext { font-size: 1em; }
            }
        </style>
    </head>
    <body>
        <div class="centerbox">
            <svg class="anim" viewBox="0 0 140 90" fill="none" xmlns="http://www.w3.org/2000/svg">
                <ellipse cx="70" cy="80" rx="56" ry="9" fill="#e6f9ee" />
                <circle cx="70" cy="42" r="36" fill="#43e19c" fill-opacity="0.8"/>
                <ellipse cx="70" cy="46" rx="32" ry="12" fill="white" fill-opacity="0.8"/>
                <ellipse cx="70" cy="35" rx="18" ry="8" fill="#31ca85" />
            </svg>
            <div class="headline">Welcome to Fresh Grocery Shop</div>
            <div class="subtext">Your one-stop destination for farm-fresh products, delivered fast and affordably.</div>
            <div class="button-row">
                <a class="bbtn" href="/register">Register</a>
                <a class="bbtn" href="/login">Login</a>
            </div>
        </div>
    </body>
    </html>
    """

# Registration page
@app.get("/register", response_class=HTMLResponse)
def register_form():
    return """
    <html>
    <head>
        <title>User Registration</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
        <style>
            body {
                margin: 0;
                min-height: 100vh;
                font-family: 'Segoe UI', 'Roboto', Arial, sans-serif;
                background: linear-gradient(120deg, #f4fcfa 0%, #d6f8ee 100%);
                display: flex;
                justify-content: center;
                align-items: center;
            }
            .register-card {
                background: rgba(255,255,255,0.97);
                border-radius: 18px;
                box-shadow: 0 8px 28px rgba(50,130,110,0.09);
                padding: 48px 32px 38px 32px;
                text-align: center;
                max-width: 350px;
                width: 100%;
                animation: floatIn 1.1s cubic-bezier(.31,.57,.54,.99);
            }
            @keyframes floatIn {
                from { transform: translateY(26px) scale(0.95); opacity: 0; }
                to { transform: translateY(0) scale(1.01); opacity: 1; }
            }
            .register-card h2 {
                color: #2dbc6f;
                font-size: 2em;
                margin-bottom: 16px;
                letter-spacing: 0.5px;
            }
            .anim {
                width: 78px;
                margin: 0 auto 23px auto;
                animation: floatIcon 2.2s infinite alternate ease-in-out;
                display: block;
            }
            @keyframes floatIcon {
                from { transform: translateY(0);}
                to { transform: translateY(-18px);}
            }
            .input-field {
                margin-bottom: 20px;
                width: 90%;
            }
            input[type="text"], input[type="password"] {
                width: 100%;
                padding: 10px 13px;
                margin-top: 6px;
                border: 1.5px solid #d0e5d7;
                border-radius: 7px;
                font-size: 1em;
                background: #f6fffc;
                transition: border-color 0.2s, box-shadow 0.2s;
                box-shadow: 0 1.5px 0 #eee;
                color: #1a3828;
            }
            input[type="text"]:focus, input[type="password"]:focus {
                outline: none;
                border-color: #2dbc6f;
                box-shadow: 0 0 0 2.5px #dcfaec;
            }
            button {
                width: 100%;
                background: linear-gradient(93deg, #49e397 0%, #1dbc6b 100%);
                color: white;
                font-weight: 600;
                border: none;
                border-radius: 7px;
                font-size: 1.13em;
                padding: 11px 0 12px 0;
                margin-top: 13px;
                margin-bottom: 6px;
                box-shadow: 0 4px 21px rgba(44, 108, 70, 0.09);
                cursor: pointer;
                transition: background 0.16s, transform 0.08s;
                letter-spacing: 0.3px;
            }
            button:hover {
                background: linear-gradient(93deg, #23c177 0%, #21b572 100%);
                transform: scale(1.035);
            }
            .back-link {
                font-size: 0.97em;
                color: #18995e;
                text-decoration: none;
                margin-top: 7px;
                display: inline-block;
                transition: text-decoration 0.2s;
            }
            .back-link:hover { text-decoration: underline; }
            #message {
                margin-top: 14px;
                font-weight: 600;
                min-height: 24px;
                font-size: 1em;
                transition: all 0.3s ease;
            }
            @media (max-width: 580px) {
                .register-card { padding: 28px 4vw 24px 4vw;}
                .register-card h2 { font-size: 1.3em;}
            }
        </style>
    </head>
    <body>
        <div class="register-card">
            <svg class="anim" viewBox="0 0 80 65" fill="none" xmlns="http://www.w3.org/2000/svg">
                <ellipse cx="40" cy="63" rx="33" ry="4" fill="#cef9df"/>
                <rect x="23" y="18" width="34" height="22" rx="8" fill="#57db97" />
                <rect x="18" y="16" width="44" height="7" rx="3" fill="#29be6a"/>
                <circle cx="29" cy="47" r="6" fill="#28c97d"/>
                <circle cx="51" cy="47" r="6" fill="#28c97d"/>
                <rect x="33" y="7" width="14" height="11" rx="5" fill="#e3ffe7"/>
                <rect x="21.5" y="24" width="9" height="2.5" rx="1" fill="#e4ffe9"/>
                <rect x="49.5" y="24" width="9" height="2.5" rx="1" fill="#e4ffe7"/>
            </svg>
            <h2>User Registration</h2>
            <form id="registerForm">
                <div class="input-field">
                    <input id="username" name="username" type="text" placeholder="Username" required/>
                </div>
                <div class="input-field">
                    <input id="password" name="password" type="password" placeholder="Password" required/>
                </div>
                <button type="submit">Register</button>
                <div id="message"></div>
            </form>
            <a href="/" class="back-link">&#8592; Back to Home</a>
        </div>

        <script>
            const registerForm = document.getElementById('registerForm');
            const messageDiv = document.getElementById('message');

            registerForm.addEventListener('submit', async (e) => {
                e.preventDefault();
                messageDiv.style.color = '#000';
                messageDiv.textContent = 'Processing registration...';

                const data = {
                    username: registerForm.username.value,
                    password: registerForm.password.value
                };

                try {
                    const response = await fetch('/register', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(data)
                    });

                    const result = await response.json();

                    if (response.ok) {
                        messageDiv.style.color = '#2e7d32';
                        messageDiv.textContent = 'Registration successful! You can now log in.';
                        registerForm.reset();
                    } else {
                        messageDiv.style.color = '#d32f2f';
                        messageDiv.textContent = result.detail || 'Registration failed. Try again.';
                    }
                } catch (err) {
                    messageDiv.style.color = '#d32f2f';
                    messageDiv.textContent = 'Unexpected error occurred. Please try again.';
                }
            });
        </script>
    </body>
    </html>
    """

@app.post("/register")
async def register(request: Request, db: Session = Depends(get_db)):
    data = await request.json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return JSONResponse(status_code=400, content={"detail": "Username and password required"})

    db_user = get_user(db, username)
    if db_user:
        return JSONResponse(status_code=400, content={"detail": "Username already registered"})

    hashed_password = get_password_hash(password)
    new_user = User(username=username, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return JSONResponse(status_code=201, content={"msg": "User created successfully"})

# Login page
@app.get("/login", response_class=HTMLResponse)
def login_form():
    return """
    <html>
    <head>
        <title>User Login</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
        <style>
            body {
                margin: 0;
                min-height: 100vh;
                font-family: 'Segoe UI', 'Roboto', Arial, sans-serif;
                background: linear-gradient(120deg, #e6f6fb 0%, #b9e7ff 100%);
                display: flex;
                justify-content: center;
                align-items: center;
            }
            .login-card {
                background: rgba(255,255,255,0.96);
                border-radius: 18px;
                box-shadow: 0 8px 28px rgba(38,137,186,0.1);
                padding: 48px 32px 38px 32px;
                text-align: center;
                max-width: 350px;
                width: 100%;
                animation: floatIn 1.1s cubic-bezier(.31,.57,.54,.99);
            }
            @keyframes floatIn {
                from { transform: translateY(26px) scale(0.95); opacity: 0; }
                to { transform: translateY(0) scale(1); opacity: 1; }
            }
            .login-card h2 {
                color: #1a7bbd;
                font-size: 2em;
                margin-bottom: 16px;
                letter-spacing: 0.6px;
            }
            .anim {
                width: 72px;
                margin: 0 auto 24px auto;
                animation: floatIcon 2.4s infinite alternate ease-in-out;
                display: block;
            }
            @keyframes floatIcon {
                from { transform: translateY(0);}
                to { transform: translateY(-20px);}
            }
            .input-field {
                margin-bottom: 20px;
                width: 90%;
            }
            input[type="text"], input[type="password"] {
                width: 100%;
                padding: 10px 13px;
                margin-top: 6px;
                border: 1.5px solid #c5d7e2;
                border-radius: 7px;
                font-size: 1em;
                background: #f7fbff;
                color: #114a71;
                transition: border-color 0.2s, box-shadow 0.2s;
                box-shadow: 0 1.5px 0 #e3f0ff;
            }
            input[type="text"]:focus, input[type="password"]:focus {
                outline: none;
                border-color: #1976d2;
                box-shadow: 0 0 0 3px #a5cdfc;
            }
            button {
                width: 100%;
                background: linear-gradient(92deg, #1a73e8 0%, #155cbf 100%);
                color: white;
                font-weight: 600;
                border: none;
                border-radius: 7px;
                font-size: 1.13em;
                padding: 12px 0 12px 0;
                margin-top: 13px;
                box-shadow: 0 4px 22px rgba(26,83,163,0.3);
                cursor: pointer;
                transition: background 0.2s, transform 0.1s;
                letter-spacing: 0.3px;
            }
            button:hover {
                background: linear-gradient(92deg, #145eba 0%, #123e75 100%);
                transform: scale(1.04);
            }
            .back-link {
                font-size: 0.95em;
                color: #145eba;
                text-decoration: none;
                margin-top: 9px;
                display: inline-block;
                transition: text-decoration 0.2s;
            }
            .back-link:hover { text-decoration: underline; }
            #message {
                margin-top: 14px;
                font-size: 1em;
                font-weight: 600;
                min-height: 24px;
                color: #d32f2f;
                transition: all 0.3s ease;
            }
            @media (max-width: 580px) {
                .login-card { padding: 28px 5vw 24px 5vw;}
                .login-card h2 { font-size: 1.4em;}
            }
        </style>
    </head>
    <body>
        <div class="login-card">
            <svg class="anim" viewBox="0 0 80 80" fill="none" xmlns="http://www.w3.org/2000/svg">
                <circle cx="40" cy="40" r="38" fill="#a5d0ff" fill-opacity="0.35" />
                <rect x="26" y="38" width="28" height="8" rx="4" fill="#1a73e8"/>
                <circle cx="28" cy="36" r="6" fill="#1976d2" />
                <rect x="38" y="30" width="10" height="30" rx="3" fill="#144e9a" />
                <circle cx="52" cy="40" r="6" fill="#366abe" />
            </svg>

            <h2>User Login</h2>
            <form id="loginForm">
                <div class="input-field">
                    <input id="username" name="username" type="text" placeholder="Username" required/>
                </div>
                <div class="input-field">
                    <input id="password" name="password" type="password" placeholder="Password" required/>
                </div>
                <button type="submit">Login</button>
                <div id="message"></div>
            </form>
            <a href="/" class="back-link">&#8592; Back to Home</a>
        </div>

        <script>
            const loginForm = document.getElementById("loginForm");
            const messageDiv = document.getElementById("message");

            loginForm.addEventListener("submit", async (e) => {
                e.preventDefault();
                messageDiv.style.color = "#000";
                messageDiv.textContent = "Checking credentials...";

                const formData = new URLSearchParams();
                formData.append("username", loginForm.username.value);
                formData.append("password", loginForm.password.value);

                try {
                    const response = await fetch("/login", {
                        method: "POST",
                        headers: { "Content-Type": "application/x-www-form-urlencoded" },
                        body: formData.toString()
                    });
                    const result = await response.json();

                    if (response.ok && result.access_token) {
                        // SAVE TOKEN!
                        localStorage.setItem("access_token", result.access_token);
                        messageDiv.style.color = "#2e7d32";
                        messageDiv.textContent = "Login successful! Redirecting...";
                        setTimeout(() => window.location.href = "/profile", 1000);
                    } else {
                        messageDiv.style.color = "#d32f2f";
                        messageDiv.textContent = result.detail || "Invalid username or password.";
                    }
                } catch (error) {
                    messageDiv.style.color = "#d32f2f";
                    messageDiv.textContent = "Unexpected error. Please try again.";
                }
            });
        </script>
    </body>
    </html>
    """

@app.post("/login", deprecated=True) # Note: Form-based login is used by the frontend
def login_form_data(username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = get_user(db, username)
    if not user or not verify_password(password, user.hashed_password):
        return JSONResponse({"detail": "Invalid username or password"}, status_code=400)
    
    expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    token = create_access_token(data={"sub": username}, expires_delta=expires)
    return JSONResponse({"access_token": token, "token_type": "bearer"})

# Profile/Dashboard Page
@app.get("/profile", response_class=HTMLResponse)
async def profile():
    return """
    <html>
    <head>
        <title>Dashboard - Fresh Grocery Shop</title>
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;700&display=swap');
            * {
                box-sizing: border-box;
            }
            body {
                margin: 0;
                font-family: 'Inter', sans-serif;
                background: #f0f5f9;
                color: #333;
                display: flex;
                min-height: 100vh;
                overflow-x: hidden;
            }
            nav.sidebar {
                width: 260px;
                background: #1a7bbd;
                color: white;
                display: flex;
                flex-direction: column;
                padding: 20px;
                position: fixed;
                height: 100vh;
                left: 0;
                top: 0;
                box-shadow: 2px 0 10px rgba(0,0,0,0.15);
                transition: width 0.3s ease;
            }
            nav.sidebar h2 {
                font-weight: 700;
                font-size: 1.5em;
                margin-bottom: 40px;
                text-align: center;
                letter-spacing: 1.2px;
                text-transform: uppercase;
                user-select: none;
            }
            nav.sidebar a {
                color: white;
                text-decoration: none;
                padding: 12px 20px;
                border-radius: 8px;
                margin-bottom: 14px;
                display: block;
                font-weight: 600;
                transition: background-color 0.3s ease;
                user-select: none;
                outline-offset: 2px;
            }
            nav.sidebar a:focus {
                outline: 2px solid #f0f5f9;
                outline-offset: 3px;
            }
            nav.sidebar a:hover {
                background-color: #155c9a;
            }
            nav.sidebar a.logout {
                margin-top: auto;
                background: #d32f2f;
                font-weight: 700;
            }
            nav.sidebar a.logout:hover,
            nav.sidebar a.logout:focus {
                background: #b02727;
            }
            main.content {
                margin-left: 260px;
                flex-grow: 1;
                padding: 24px 40px;
                background: #f0f5f9;
                min-height: 100vh;
                animation: fadeInContent 0.7s ease forwards;
                overflow-y: auto;
                outline-offset: 4px;
            }
            main.content:focus {
                outline: 3px solid #1a7bbd;
            }
            @keyframes fadeInContent {
                from { opacity: 0; transform: translateY(20px); }
                to { opacity: 1; transform: translateY(0); }
            }
            main.content h1 {
                font-weight: 700;
                color: #1a7bbd;
                margin-bottom: 20px;
                user-select: none;
            }
            .cards-container {
                display: grid;
                grid-template-columns: repeat(auto-fill, minmax(230px, 1fr));
                gap: 28px;
            }
            .card {
                background: white;
                border-radius: 14px;
                padding: 30px 25px;
                box-shadow: 0 8px 20px rgba(26, 83, 163, 0.1);
                transition: box-shadow 0.3s ease, transform 0.25s ease;
                cursor: default;
                user-select: none;
                position: relative;
                overflow: hidden;
                outline-offset: 4px;
            }
            .card:focus {
                outline: 3px solid #1a7bbd;
            }
            .card:hover {
                transform: translateY(-8px);
                box-shadow: 0 14px 40px rgba(26, 83, 163, 0.16);
            }
            .card h3 {
                font-weight: 700;
                margin: 0 0 15px 0;
                font-size: 1.25em;
                color: #155c9a;
            }
            .card .stat {
                font-size: 2.8em;
                font-weight: 700;
                color: #1a7bbd;
                letter-spacing: 0.05em;
                line-height: 1;
            }
            .icon {
                position: absolute;
                top: -20px;
                right: -20px;
                width: 80px;
                height: 80px;
                opacity: 0.1;
                user-select: none;
                pointer-events: none;
            }
            .card:nth-child(1) {
                animation: floatUpDown 3.3s ease-in-out infinite;
            }
            .card:nth-child(2) {
                animation: floatUpDown 3.5s ease-in-out infinite;
                animation-delay: 0.2s;
            }
            .card:nth-child(3) {
                animation: floatUpDown 3.7s ease-in-out infinite;
                animation-delay: 0.4s;
            }
            @keyframes floatUpDown {
                0%, 100% { transform: translateY(0); }
                50% { transform: translateY(-10px); }
            }
            @media (max-width: 720px) {
                nav.sidebar {
                    width: 60px;
                    padding: 15px;
                }
                nav.sidebar h2 {
                    display: none;
                }
                nav.sidebar a {
                    font-size: 0;
                    padding: 10px;
                    margin-bottom: 18px;
                }
                nav.sidebar a.logout {
                    margin-top: 24px;
                }
                main.content {
                    margin-left: 60px;
                    padding: 20px 20px;
                }
            }
        </style>
    </head>
    <body>
        <nav class="sidebar" aria-label="Main Navigation">
            <h2>Grocery Shop</h2>
            <a href="/dashboard" tabindex="0">Dashboard</a>
            <a href="/products" tabindex="0">Products</a>
            <a href="/products/add" tabindex="0">Add Product</a>
            <a href="/sales" tabindex="0">Sales</a>
            <a href="/customers" tabindex="0">Customers details</a>
            <a href="/customers/add" tabindex="0">Add Customer</a>
            <a href="/barcode-generator" tabindex="0">Barcode Generator</a>
            <a href="#" class="logout" onclick="logout()" tabindex="0">Logout</a>
        </nav>
        <main class="content" tabindex="0" role="main" aria-live="polite" aria-atomic="true">
            <div class="welcome-container" style="max-width: 700px; margin: 0 auto 40px auto; text-align: center; padding: 20px 15px; background: white; border-radius: 14px; box-shadow: 0 8px 25px rgba(26, 83, 163, 0.15);">
                <h1 id="welcomeMessage" style="font-size: 2.8em; color: #155c9a; font-weight: 800; margin-bottom: 12px; user-select: none; letter-spacing: 0.05em;">
                    Loading profile...
                </h1>
                <p style="font-size: 1.3em; color: #2c3e50; margin-bottom: 12px; font-weight: 600;">
                    Freshness Delivered to Your Doorstep!
                </p>
                <p style="font-size: 1.1em; color: #455a64; line-height: 1.5; margin-bottom: 0;">
                    Explore our wide selection of quality groceries and unbeatable deals. Shop now and experience convenience and freshness like never before!
                </p>
            </div>
            <div class="cards-container" aria-label="User stats and info">
                <!-- Existing cards here -->
            </div>
        </main>

        <script>
            async function loadProfile() {
                const token = localStorage.getItem("access_token");
                if (!token) {
                    alert("Not logged in, please login.");
                    window.location.href = "/login";
                    return;
                }
                try {
                    const response = await fetch("/profile/user", {
                        headers: {
                            "Authorization": "Bearer " + token
                        }
                    });
                    if (!response.ok) {
                        throw new Error("Not authenticated");
                    }
                    const data = await response.json();
                    document.getElementById("welcomeMessage").innerText = `Welcome, ${data.username}!`;
                } catch (error) {
                    alert("Session expired or unauthorized. Please login again.");
                    localStorage.removeItem("access_token");
                    window.location.href = "/login";
                }
            }
            window.onload = loadProfile;
                        // In your login page's <script> tag...
            async function handleLogin(event) {
                event.preventDefault();
                // ... code to get username and password
                
                const response = await fetch("/token", { /* ... login request details ... */ });

                if (response.ok) {
                    const data = await response.json();
                    localStorage.setItem("access_token", data.access_token);
                    // Change the destination to the dashboard
                    window.location.href = "/dashboard"; 
                } else {
                    // ... handle login error
                }
            }

            function logout() {
                localStorage.removeItem("access_token");
                window.location.href = "/";
            }
        </script>
    </body>
    </html>
    """

@app.get("/profile/user")
async def profile_user(current_user: User = Depends(get_current_user)):
    return {"username": current_user.username}

# --- NEW: Live Dashboard Routes ---
# Place this code inside your grocerybill.py file

@app.get("/dashboard", response_class=HTMLResponse)
def get_dashboard_page():
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>Live Dashboard</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body {
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                background-color: #f7f9fc;
                margin: 0;
                padding: 30px 40px;
                color: #2c3e50;
                min-height: 100vh;
                display: flex;
                flex-direction: column;
                align-items: center;
            }
            a.back-link {
                padding: 12px 28px;
                margin-bottom: 24px;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                text-decoration: none;
                color: #1877f2;
                background-color: #e5f1ff;
                border-radius: 30px;
                font-weight: 600;
                box-shadow: 0 4px 8px rgba(24, 119, 242, 0.15);
                transition: background-color 0.25s ease, color 0.25s ease;
            }
            a.back-link:hover,
            a.back-link:focus {
                background-color: #d0e4ff;
                color: #0f49a5;
                outline: none;
            }
            h1 {
                color: #1a237e;
                font-weight: 700;
                font-size: 2.8rem;
                margin-bottom: 32px;
                text-align: center;
                user-select: none;
            }
            .dashboard-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
                gap: 28px;
                width: 100%;
                max-width: 1200px;
            }
            .card {
                background-color: white;
                border-radius: 12px;
                box-shadow: 0 10px 25px rgba(33, 150, 243, 0.1);
                padding: 26px 22px 30px 22px;
                transition: box-shadow 0.3s ease, transform 0.25s ease;
                display: flex;
                flex-direction: column;
                justify-content: center;
                cursor: default;
                user-select: none;
            }
            .card:hover {
                transform: translateY(-6px);
                box-shadow: 0 15px 40px rgba(33, 150, 243, 0.2);
            }
            .card h2 {
                font-size: 1.3em;
                margin: 0 0 14px 0;
                color: #3f51b5;
                font-weight: 700;
                user-select: text;
            }
            .card .stat {
                font-size: 3em;
                font-weight: 700;
                color: #2196f3;
                user-select: text;
            }
            .chart-container {
                grid-column: 1 / -1;
                padding-top: 15px;
                height: 360px;
            }
            table {
                width: 100%;
                border-collapse: collapse;
                margin-top: 18px;
                font-size: 0.95rem;
                user-select: text;
            }
            th, td {
                text-align: left;
                padding: 12px 14px;
                border-bottom: 1px solid #e0e0e0;
            }
            th {
                background-color: #f2f6fc;
                color: #394548;
                font-weight: 600;
            }
            tbody tr:hover {
                background-color: #f9fbff;
            }
            @media (max-width: 600px) {
                body {
                    padding: 20px 15px;
                }
                .card .stat {
                    font-size: 2.3em;
                }
                .chart-container {
                    height: 280px;
                }
            }
            .sr-only { 
                position: absolute;
                width: 1px; 
                height: 1px; 
                padding: 0; 
                overflow: hidden; 
                clip: rect(0, 0, 0, 0); 
                white-space: nowrap;
                border: 0;
            }
        </style>
    </head>
    <body>
        <a href="/profile" class="back-link" aria-label="Back to Home">&larr; Back to Home</a>
        <h1>Live Dashboard</h1>
        <div class="dashboard-grid" role="region" aria-label="Dashboard statistics and charts">
            <div class="card" tabindex="0" aria-label="Total revenue">
                <h2>Total Revenue</h2>
                <p class="stat" id="total-revenue">Loading...</p>
            </div>
            <div class="card" tabindex="0" aria-label="Total sales">
                <h2>Total Sales</h2>
                <p class="stat" id="sales-count">Loading...</p>
            </div>
            <div class="card" tabindex="0" aria-label="Total products">
                <h2>Total Products</h2>
                <p class="stat" id="product-count">Loading...</p>
            </div>
            <div class="card" tabindex="0" aria-label="Total customers">
                <h2>Total Customers</h2>
                <p class="stat" id="customer-count">Loading...</p>
            </div>
            <div class="card chart-container" aria-label="Top Selling Products Pie Chart" tabindex="0">
                <h2>Top Selling Products (by Quantity)</h2>
                <canvas id="topProductsChart" role="img" aria-describedby="descTopProducts"></canvas>
                <p id="descTopProducts" class="sr-only">Pie chart showing top selling products by quantity sold.</p>
            </div>
            <div class="card chart-container" aria-label="Recent Sales Table" tabindex="0">
                <h2>Recent Sales</h2>
                <table id="recent-sales-table" aria-live="polite" aria-relevant="all" aria-label="Recent Sales Table">
                    <thead>
                        <tr>
                            <th scope="col">Product</th>
                            <th scope="col">Quantity</th>
                            <th scope="col">Total Price</th>
                            <th scope="col">Date</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr><td colspan="4" style="text-align:center; font-style:italic;">Loading...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
        <script>
            async function fetchDashboardData() {
                const token = localStorage.getItem('access_token');
                if (!token) {
                    document.body.innerHTML = "<h1>Please login.</h1>";
                    return;
                }
                try {
                    const response = await fetch('/api/dashboard-stats', {
                        headers: { 'Authorization': 'Bearer ' + token }
                    });
                    if (!response.ok) throw new Error('Failed to load dashboard data');
                    const data = await response.json();

                    document.getElementById('total-revenue').textContent = `₹${data.total_revenue.toFixed(2)}`;
                    document.getElementById('sales-count').textContent = data.sales_count;
                    document.getElementById('product-count').textContent = data.product_count;
                    document.getElementById('customer-count').textContent = data.customer_count;

                    renderTopProductsChart(data.top_products);
                    renderRecentSales(data.recent_sales);
                } catch (error) {
                    console.error("Dashboard Error:", error);
                }
            }

            function renderTopProductsChart(topProducts) {
                const ctx = document.getElementById('topProductsChart').getContext('2d');
                if(window.topProductsChartInstance) {
                    window.topProductsChartInstance.destroy();
                }

                const colors = [
                    '#42a5f5', '#66bb6a', '#ffa726', '#ab47bc', '#26c6da', '#ef5350', '#8d6e63', '#d4e157'
                ];
                window.topProductsChartInstance = new Chart(ctx, {
                    type: 'pie',
                    data: {
                        labels: topProducts.map(p => p.name),
                        datasets: [{
                            label: 'Quantity Sold',
                            data: topProducts.map(p => p.total_quantity),
                            backgroundColor: colors.slice(0, topProducts.length),
                            borderColor: '#fff',
                            borderWidth: 2,
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: { position: 'right', labels: { boxWidth: 16, padding: 14 } }
                        }
                    }
                });
            }

            function renderRecentSales(recentSales) {
                const tbody = document.querySelector("#recent-sales-table tbody");
                tbody.innerHTML = "";
                if(recentSales.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; font-style: italic;">No recent sales.</td></tr>';
                    return;
                }
                recentSales.forEach(sale => {
                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td>${sale.product_name}</td>
                        <td>${sale.quantity}</td>
                        <td>₹${sale.total_price.toFixed(2)}</td>
                        <td>${new Date(sale.sale_date).toLocaleString()}</td>
                    `;
                    tbody.appendChild(tr);
                });
            }

            document.addEventListener('DOMContentLoaded', fetchDashboardData);
        </script>
    </body>
    </html>
    """

@app.get("/api/dashboard-stats")
def get_dashboard_stats(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    total_revenue = db.query(func.sum(Sale.total_price)).scalar() or 0
    sales_count = db.query(func.count(Sale.id)).scalar() or 0
    product_count = db.query(func.count(Product.id)).scalar() or 0
    customer_count = db.query(func.count(Customer.id)).scalar() or 0

    top_products_query = db.query(
        Product.name,
        func.sum(Sale.quantity).label('total_quantity')
    ).join(Sale).group_by(Product.name).order_by(func.sum(Sale.quantity).desc()).limit(5).all()

    top_products = [{"name": name, "total_quantity": qty} for name, qty in top_products_query]

    recent_sales_query = db.query(Sale).order_by(Sale.sale_date.desc()).limit(5).all()
    recent_sales = [{
        "product_name": sale.product.name,
        "quantity": sale.quantity,
        "total_price": sale.total_price,
        "sale_date": sale.sale_date.isoformat()
    } for sale in recent_sales_query]

    return {
        "total_revenue": total_revenue,
        "sales_count": sales_count,
        "product_count": product_count,
        "customer_count": customer_count,
        "top_products": top_products,
        "recent_sales": recent_sales
    }
# --- END NEW DASHBOARD ROUTES ---

@app.get("/products", response_class=HTMLResponse)
def sales_page(request: Request):
    return templates.TemplateResponse("products.html", {"request": request})

@app.get("/api/products")
def api_products(db: Session = Depends(get_db)):
    products = db.query(Product).all()
    return [{
        "code": p.code,
        "category": p.category,
        "name": p.name,
        "image_url": p.image_url,
        "price": p.price,
    } for p in products]

@app.get("/products/add", response_class=HTMLResponse)
def add_product_form():
    return """
    <html>
    <head>
        <title>Manage Product</title>
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <style>
            body { font-family: 'Segoe UI', sans-serif; background-color: #f4f7f8; margin: 0; padding: 20px; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
            .container { background: white; padding: 2.5rem 3rem; border-radius: 10px; box-shadow: 0 10px 25px rgba(0,0,0,0.1); max-width: 450px; width: 100%; }
            h2 { text-align: center; margin-bottom: 1.8rem; color: #333; }
            label { font-weight: 600; display: block; margin-top: 1.2rem; color: #555; }
            input[type="text"], input[type="number"] { width: 100%; padding: 0.7rem 1rem; border: 1.6px solid #ddd; border-radius: 6px; margin-top: 0.4rem; transition: border-color 0.3s ease; font-size: 1rem; box-sizing: border-box; }
            input:focus { border-color: #28a745; outline: none; box-shadow: 0 0 6px #28a745aa; }
            input:read-only { background-color: #e9ecef; cursor: not-allowed; }
            button { margin-top: 2rem; width: 100%; padding: 0.85rem; font-size: 1.1rem; font-weight: 600; color: white; background-color: #28a745; border: none; border-radius: 8px; cursor: pointer; box-shadow: 0 5px 15px #28a745aa; transition: background-color 0.3s ease, box-shadow 0.3s ease; }
            button:hover { background-color: #218838; box-shadow: 0 6px 18px #218838cc; }
            button:disabled { background-color: #aaa; cursor: not-allowed; }
            .back-link { display: block; text-align: center; margin-top: 1.5rem; color: #28a745; font-weight: 600; text-decoration: none; font-size: 0.95rem; }
            .back-link:hover { text-decoration: underline; }
            #message { text-align: center; margin-top: 15px; font-weight: bold; min-height: 22px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2 id="form-title">Add New Product</h2>
            <form id="productForm" autocomplete="off">
                <label for="code">Product Code</label>
                <input id="code" type="text" name="code" maxlength="10" required placeholder="e.g., PRD001" />
                
                <label for="category">Category</label>
                <input id="category" type="text" name="category" maxlength="50" required placeholder="e.g., Fruits" />
                
                <label for="name">Product Name</label>
                <input id="name" type="text" name="name" maxlength="100" required placeholder="e.g., Fresh Apple" />
                
                <label for="image_url">Image URL</label>
                <input id="image_url" type="text" name="image_url" maxlength="250" required placeholder="https://example.com/image.jpg" />
                
                <label for="price">Price (₹)</label>
                <input id="price" type="number" step="0.01" min="0" name="price" required placeholder="e.g., 1.99" />
                
                <button type="submit" id="submit-btn">Add Product</button>
            </form>
            <div id="message"></div>
            <a class="back-link" href="/products">&#8592; Back to Product Catalog</a>
        </div>
        <script>
            const form = document.getElementById('productForm');
            const messageDiv = document.getElementById('message');
            const title = document.getElementById('form-title');
            const submitBtn = document.getElementById('submit-btn');
            const codeInput = document.getElementById('code');

            let editMode = false;
            let productCode = null;

            document.addEventListener('DOMContentLoaded', async () => {
                const path = window.location.pathname;
                if (path.startsWith('/products/edit/')) {
                    const parts = path.split('/');
                    productCode = parts[parts.length - 1];
                    if(productCode) {
                        editMode = true;
                        await loadProductData(productCode);
                    }
                }
            });

            async function loadProductData(code) {
                title.textContent = 'Edit Product';
                submitBtn.textContent = 'Update Product';

                // 1. Get the token from local storage
                const token = localStorage.getItem("access_token");
                if (!token) {
                    messageDiv.style.color = 'red';
                    messageDiv.textContent = "Authentication error. Please login.";
                    submitBtn.disabled = true;
                    return;
                }

            try {
                // 2. Add the token to the fetch request headers
                const response = await fetch(`/api/products/${code}`, {
                    headers: {
                        'Authorization': `Bearer ${token}`
                    }
                });

                if (response.status === 401) {
                    throw new Error('Unauthorized. Your session may have expired.');
                }
                if (!response.ok) {
                    throw new Error('Product not found.');
                }
                
                const product = await response.json();
                
                codeInput.value = product.code;
                codeInput.readOnly = true;
                document.getElementById('category').value = product.category;
                document.getElementById('name').value = product.name;
                document.getElementById('image_url').value = product.image_url;
                document.getElementById('price').value = product.price;
            } catch (err) {
                messageDiv.style.color = 'red';
                messageDiv.textContent = `Error: ${err.message}`;
                submitBtn.disabled = true;
            }
        }
 
            form.addEventListener('submit', async (e) => {
                e.preventDefault();
                messageDiv.textContent = 'Submitting...';
                
                const token = localStorage.getItem("access_token");
                if (!token) {
                    messageDiv.style.color = 'red';
                    messageDiv.textContent = "Authentication error. Please login.";
                    return;
                }

                const formData = new FormData(form);
                const data = Object.fromEntries(formData.entries());
                data.price = parseFloat(data.price);

                const headers = {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                };

                let url = '/api/products/add';
                let method = 'POST';
                if (editMode) {
                    url = `/api/products/edit/${productCode}`;
                    method = 'PUT';
                }

                try {
                    const response = await fetch(url, { method, headers, body: JSON.stringify(data) });
                    const result = await response.json();
                    if (response.ok) {
                        messageDiv.style.color = 'green';
                        messageDiv.textContent = result.message;
                        if (!editMode) form.reset();
                    } else {
                        messageDiv.style.color = 'red';
                        messageDiv.textContent = `Error: ${result.detail}`;
                    }
                } catch (err) {
                    messageDiv.style.color = 'red';
                    messageDiv.textContent = 'An unexpected error occurred.';
                }
            });
        </script>
    </body>
    </html>
    """

# New route for editing, re-uses the same form-serving function
@app.get("/products/edit/{code}", response_class=HTMLResponse)
def edit_product_form(code: str):
    return add_product_form()


@app.post("/api/products/add")
def add_product_api(
    product_data: ProductCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    existing = db.query(Product).filter(Product.code == product_data.code).first()
    if existing:
        raise HTTPException(status_code=400, detail=f"Product code '{product_data.code}' already exists.")
    
    try:
        new_product = Product(**product_data.dict())
        db.add(new_product)
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error adding product: {str(e)}")
    
    return JSONResponse(status_code=201, content={"message": "Product added successfully!"})


@app.get("/api/products/{code}")
def get_product_details(code: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    print(f"Received request to get product with code: {code}")
    product = db.query(Product).filter(Product.code == code).first()
    if not product:
        print(f"Product with code {code} not found in DB.")
        raise HTTPException(status_code=404, detail="Product not found")
    return product



@app.put("/api/products/edit/{code}")
def update_product(
    code: str,
    product_update: ProductUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    product = db.query(Product).filter(Product.code == code).first()
    if not product: 
        raise HTTPException(status_code=404, detail="Product not found")
    
    # Update model instance with new data
    update_data = product_update.dict(exclude_unset=True)
    for key, value in update_data.items():
        setattr(product, key, value)
        
    db.add(product)
    db.commit()
    db.refresh(product)
    return JSONResponse(content={"message": "Product updated successfully!"})

@app.delete("/api/products/delete/{code}")
def delete_product(
    code: str = Path(..., title="The code of the product to delete"),
    db: Session = Depends(get_db),
    get_current_user: User = Depends(get_current_user)
):
    product = db.query(Product).filter(Product.code == code).first()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    try:
        db.delete(product)
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Could not delete product: {e}")

    return JSONResponse(content={"message": "Product deleted successfully"})

#-----product routes & edit and delete routes end here-----
@app.route('/products/edit/<string:prod_code>', methods=['GET', 'POST'])
def edit_product(prod_code):
    product = Product.query.filter_by(code=prod_code).first()
    if not product:
        flash('Error: Product not found', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        product.code = request.form.get('code')
        product.category = request.form.get('category')
        product.name = request.form.get('name')
        product.image_url = request.form.get('image_url')
        try:
            product.price = float(request.form.get('price', 0))
        except ValueError:
            flash('Invalid price value', 'danger')
            return render_template('edit_product.html', product=product)

        try:
            db.session.commit()
            flash('Product updated successfully!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash('Error updating product: {}'.format(str(e)), 'danger')

    return render_template('edit_product.html', product=product)


@app.route('/delete_product/<int:prod_id>', methods=['POST'])
def delete_product(prod_id):
    product = Product.query.get_or_404(prod_id)
    try:
        db.session.delete(product)
        db.session.commit()
        flash('Product deleted successfully!', 'success')
    except IntegrityError:
        db.session.rollback()
        flash('Cannot delete product. There are sales referencing this product.', 'danger')
    return redirect(url_for('dashboard'))


# Sales Page
@app.get("/sales", response_class=HTMLResponse)
def sales_page(request: Request):
    return templates.TemplateResponse("sales.html", {"request": request})
# In grocerybill.py - Replace the existing api_sales function

@app.get("/api/sales")
def api_sales(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    sales = db.query(Sale).join(Product).order_by(Sale.sale_date.desc()).all()
    return [{
        "id": s.id,
        "product_name": s.product.name,
        "quantity": s.quantity,
        "total_price": s.total_price,
        "sale_date": s.sale_date.isoformat(),
    } for s in sales]

# Customers Page
@app.get("/customers", response_class=HTMLResponse)
def customers_page():
    return """
    <html>
    <head>
        <title>Customers details- Grocery Shop</title>
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <style>
            body { font-family: Arial, sans-serif; background: #f9fafb; margin: 0; padding: 20px; color: #333;}
            h1 {color:#1a7bbd; text-align:center; margin-bottom:20px;}
            table {border-collapse:collapse; width:90%; max-width:900px; margin:auto; background:white; border-radius:8px; box-shadow: 0 4px 16px rgba(0,0,0,0.1);}
            th, td {padding:14px 20px; text-align:left; border-bottom:1px solid #eee;}
            th {background-color:#1a7bbd; color:white;}
            tr:hover {background-color:#f1f5fb;}
            .back-link {
                display: inline-block;
                margin: 15px 20px 10px;
                padding: 8px 14px;
                background-color: #8592b4;
                color: white; text-decoration: none; font-weight: 600; border-radius: 6px;
            }
            @media (max-width:600px){
                table, thead, tbody, th, td, tr {display:block;}
                th {position:sticky; top:0;}
                td {padding-left:50%; position:relative;}
                td::before {position:absolute; top:14px; left:14px; width:45%; white-space:nowrap; font-weight:bold;}
                td:nth-of-type(1)::before {content: "Name";}
                td:nth-of-type(2)::before {content: "Email";}
                td:nth-of-type(3)::before {content: "Phone";}
                td:nth-of-type(4)::before {content: "Address";}
                td:nth-of-type(5)::before {content: "Registered On";}
            }
        </style>
    </head>
    <body>
        <a href="/profile" class="back-link">&#8592; Back to Dashboard</a>
        <h1>Customer List</h1>
        <table id="customersTable">
            <thead>
                <tr>
                    <th>Name</th><th>Email</th><th>Phone</th><th>Address</th><th>Registered On</th>
                </tr>
            </thead>
            <tbody><tr><td colspan="5" style="text-align:center;">Loading customers...</td></tr></tbody>
        </table>
        <script>
            async function loadCustomers() {
                try {
                    const token = localStorage.getItem("access_token");
                    const resp = await fetch('/api/customers', {
                         headers: { "Authorization": "Bearer " + token }
                    });
                    if (!resp.ok) throw new Error("Failed to fetch customers");
                    const customers = await resp.json();

                    const tbody = document.querySelector('#customersTable tbody');
                    tbody.innerHTML = '';

                    customers.forEach(c => {
                        const tr = document.createElement('tr');
                        tr.innerHTML = `
                            <td>${c.name}</td>
                            <td>${c.email}</td>
                            <td>${c.phone || ''}</td>
                            <td>${c.address || ''}</td>
                            <td>${new Date(c.registered_on).toLocaleDateString()}</td>
                        `;
                        tbody.appendChild(tr);
                    });
                } catch(e) {
                    const tbody = document.querySelector('#customersTable tbody');
                    tbody.innerHTML = '<tr><td colspan="5" style="color:red; text-align:center">Failed to load customers. Please login.</td></tr>';
                    console.error('Failed to load customers:', e);
                }
            }
            loadCustomers();
        </script>
    </body>
    </html>
    """

@app.get("/api/customers")
def api_customers(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    customers = db.query(Customer).order_by(Customer.registered_on.desc()).all()
    return [{
        "id": c.id,
        "name": c.name,
        "email": c.email,
        "phone": c.phone,
        "address": c.address,
        "registered_on": c.registered_on.isoformat(),
    } for c in customers]

# Add Customer Page
@app.get("/customers/add", response_class=HTMLResponse)
def add_customer_form():
    return """
    <html>
    <head>
        <title>Add Customer - Grocery Shop</title>
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <style>
            body { font-family: Arial, sans-serif; background: #f9fafb; padding: 20px; color: #333; }
            .form-container {
                max-width: 500px;
                margin: 30px auto;
                background: white;
                padding: 30px;
                border-radius: 8px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.1);
            }
            h1 { text-align: center; color: #1a7bbd; margin-bottom: 20px; }
            label { display: block; margin-top: 15px; font-weight: 600; }
            input, textarea {
                width: 100%;
                padding: 8px 10px;
                margin-top: 6px;
                border: 1.5px solid #ccc;
                border-radius: 6px;
                font-size: 1em;
            }
            button {
                margin-top: 20px;
                background: #1a7bbd;
                color: white;
                font-weight: 700;
                border: none;
                padding: 12px;
                width: 100%;
                border-radius: 6px;
                cursor: pointer;
                font-size: 1.1em;
                transition: background 0.3s;
            }
            button:hover { background: #155c9a; }
            a.back-link {
                display: inline-block;
                margin-top: 20px;
                color: #1a7bbd;
                text-decoration: none;
                font-weight: 600;
            }
            a.back-link:hover { text-decoration: underline; }
            #message {
                margin-top: 15px;
                font-weight: 600;
            }
        </style>
    </head>
    <body>
        <div class="form-container">
            <h1>Add Customer</h1>
            <form id="customerForm">
                <label for="name">Name*</label>
                <input type="text" id="name" name="name" required />

                <label for="email">Email*</label>
                <input type="email" id="email" name="email" required />

                <label for="phone">Phone</label>
                <input type="text" id="phone" name="phone" />

                <label for="address">Address</label>
                <textarea id="address" name="address" rows="3"></textarea>

                <button type="submit">Add Customer</button>
                <div id="message"></div>
            </form>
            <a href="/customers" class="back-link">&#8592; Back to Customer List</a>
        </div>

        <script>
            const form = document.getElementById('customerForm');
            const messageDiv = document.getElementById('message');

            form.addEventListener('submit', async e => {
                e.preventDefault();
                messageDiv.textContent = '';
                messageDiv.style.color = '#000';

                const data = {
                    name: form.name.value.trim(),
                    email: form.email.value.trim(),
                    phone: form.phone.value.trim(),
                    address: form.address.value.trim()
                };

                if (!data.name || !data.email) {
                    messageDiv.textContent = 'Name and Email are required!';
                    messageDiv.style.color = 'red';
                    return;
                }

                try {
                    const token = localStorage.getItem("access_token");
                    const response = await fetch('/api/customers', {
                        method: 'POST',
                        headers: { 
                            'Content-Type': 'application/json',
                            "Authorization": "Bearer " + token
                        },
                        body: JSON.stringify(data)
                    });

                    if (response.ok) {
                        messageDiv.textContent = 'Customer added successfully! ';
                        messageDiv.style.color = 'green';
                        setTimeout(() => window.location.href = '/customers', 1500);
                    } else {
                        const err = await response.json();
                        messageDiv.style.color = 'red';
                        messageDiv.textContent = err.detail || 'Failed to add customer.';
                    }
                } catch (error) {
                    messageDiv.style.color = 'red';
                    messageDiv.textContent = 'An error occurred. Please try again.';
                }
            });
        </script>
    </body>
    </html>
    """

@app.post("/api/customers")
def create_customer(
    customer_data: CustomerCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    existing = db.query(Customer).filter(Customer.email == customer_data.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered.")

    new_customer = Customer(**customer_data.dict())
    db.add(new_customer)
    db.commit()
    db.refresh(new_customer)
    return {"msg": "Customer added successfully", "id": new_customer.id}


@app.post("/api/check_customer")
def check_customer(request: dict, db: Session = Depends(get_db)):
    try:
        identifier = request.get("identifier", "").strip()
        customer = db.query(Customer).filter(
            (Customer.email == identifier) | (Customer.phone == identifier)
        ).first()
        if customer:
            return {"exists": True, "customer": {
                "name": customer.name,
                "email": customer.email,
                "phone": customer.phone,
                "address": customer.address,
            }}
        else:
            return {"exists": False}
    except Exception as e:
        print(f"Error in check_customer: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
    
@app.post("/api/add_customer")
def add_customer(customer: NewCustomer, db: Session = Depends(get_db)):
    existing = db.query(Customer).filter(
        (Customer.email == customer.email) | (Customer.phone == customer.phone)
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="Customer already exists")

    db_customer = Customer(
        name=customer.name,
        email=customer.email,
        phone=customer.phone,
        address=customer.address,
        registered_on=datetime.utcnow()
    )
    db.add(db_customer)
    db.commit()
    db.refresh(db_customer)
    return {"detail": "Customer added successfully"}

@app.post("/checkout")
async def checkout(request: Request, cart_data: str = Form(...)):
    # You can store cart data in a session or a database here.
    # For now, we'll proceed directly to the customer type page.
    return RedirectResponse(url="customer_type.html", status_code=status.HTTP_303_SEE_OTHER)

@app.get("/customer_type", response_class=HTMLResponse)
async def customer_type_page(request: Request):
    return templates.TemplateResponse("customer_type.html", {"request": request})

@app.get("/payment_method", response_class=HTMLResponse)
async def payment_method_page(request: Request, total_amount: float = Query(...)):
    return templates.TemplateResponse("payment.html", {"request": request, "total_amount": total_amount})
    

@app.get("/invoice", response_class=HTMLResponse)
async def invoice_page(request: Request, payment_method: str = Query(None)):
    return templates.TemplateResponse("invoice.html", {"request": request, "payment_method": payment_method})

# Helper function to generate a QR code image
def generate_qr_code(qr_data: str):
    img = qrcode.make(qr_data)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return Response(content=buf.getvalue(), media_type="image/png")

@app.get("/barcode-generator", response_class=HTMLResponse)
async def barcode_generator_page(request: Request):
    return templates.TemplateResponse("barcode_generator.html", {"request": request})

# -------------------------------------------------------------------
# 9. Main execution block
# -------------------------------------------------------------------
if __name__ == "__main__":
    print("To run the application, use the command:")
    print("python -m uvicorn grocerybill:app --reload")
    uvicorn.run(app, host="127.0.0.1", port=8000)
