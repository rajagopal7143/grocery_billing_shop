import uvicorn
from fastapi import FastAPI, Form, Request, Depends, HTTPException, status, Body, Path, Query, APIRouter
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, FileResponse, StreamingResponse
from fastapi.security import OAuth2PasswordBearer
from fastapi.templating import Jinja2Templates
from sqlalchemy import create_engine, Column, Integer, String, Float, ForeignKey, DateTime, func, extract, PrimaryKeyConstraint, text
from sqlalchemy.orm import sessionmaker, Session, declarative_base, relationship, joinedload
from passlib.context import CryptContext
from jose import JWTError, jwt
from pydantic import BaseModel, EmailStr, PositiveInt, constr
from datetime import datetime, timedelta
from typing import Optional, List
from starlette.status import HTTP_303_SEE_OTHER
from flask_sqlalchemy import SQLAlchemy
from flask import Flask, render_template, request, redirect, url_for, flash
from sqlalchemy.exc import IntegrityError, OperationalError
from auth import get_current_user, User 
from fastapi.requests import Request
from starlette.responses import StreamingResponse
import qrcode
import io, csv
# -------------------------------------------------------------------
# 1. Configuration & Database Setup
# -------------------------------------------------------------------
app = FastAPI()
# --- IMPORTANT ---
router = APIRouter()
# Update this connection string with your actual MySQL database details.
# Format: "mysql+pymysql://<user>:<password>@<host>/<database_name>"
DATABASE_URL = "mysql+pymysql://fastapi_user:your_password@localhost/grocery_shop_db"
SECRET_KEY = "a_very_secret_key_that_should_be_changed"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

app = FastAPI(title="Grocery Shop API")
templates = Jinja2Templates(directory="templates")

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# -------------------------------------------------------------------
# 2. SQLAlchemy Models
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
    code = Column(String(20), unique=True, index=True, nullable=False)
    category = Column(String(50), nullable=False)
    name = Column(String(100), nullable=False)
    image_url = Column(String(255), nullable=True)
    price = Column(Float, nullable=False)
    sales = relationship("Sale", back_populates="product")

class Customer(Base):
    __tablename__ = "customers"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    email = Column(String(100), unique=True, index=True)
    phone = Column(String(20), nullable=True)
    address = Column(String(250), nullable=True)
    registered_on = Column(DateTime, default=func.now())

class Sale(Base):
    __tablename__ = "sales"
    id = Column(Integer, primary_key=True, index=True)
    invoice_number = Column(String(50), index=True)
    product_id = Column(Integer, ForeignKey("products.id"))
    user_id = Column(Integer, ForeignKey("users.id")) # Staff who made the sale
    quantity = Column(Integer, nullable=False)
    total_price = Column(Float, nullable=False)
    payment_method = Column(String(50))
    sale_date = Column(DateTime, default=func.now())
    
    product = relationship("Product", back_populates="sales")
    user = relationship("User", back_populates="sales")

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

class NewCustomer(BaseModel):
    name: str
    email: EmailStr
    phone: str | None = None
    address: str | None = None

# Models for the new /api/record_purchase endpoint
class PurchaseItemPayload(BaseModel):
    code: str
    name: str
    price: float
    quantity: int

class CustomerPayload(BaseModel):
    name: str
    email: EmailStr
    phone: Optional[str] = None
    address: Optional[str] = None

class RecordPurchasePayload(BaseModel):
    items: List[PurchaseItemPayload]
    customer: CustomerPayload
    payment_method: str
    invoice_number: str
    total_amount: float

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
def home(request: Request):
    return templates.TemplateResponse("home_page.html", {"request": request})


# Registration page
@app.get("/register", response_class=HTMLResponse)
def register_form(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

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
def login_form(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

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
def profile_page(request: Request):
    return templates.TemplateResponse("profile.html", {"request": request})

@app.get("/profile/user")
async def profile_user(current_user: User = Depends(get_current_user)):
    return {"username": current_user.username}

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard_page(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})

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
def add_product_form(request: Request):
    return templates.TemplateResponse("add_products.html", {"request": request})


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

@app.post("/api/record_purchase")
def record_purchase(
    payload: RecordPurchasePayload,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # 1. Find or Create Customer (optional - if you still want customers)
    customer = db.query(Customer).filter(Customer.email == payload.customer.email).first()
    if not customer:
        customer = Customer(
            name=payload.customer.name,
            email=payload.customer.email,
            phone=payload.customer.phone,
            address=payload.customer.address
        )
        db.add(customer)
        db.commit()
        db.refresh(customer)

    # 2. Record each item as a sale
    for item in payload.items:
        # ✅ Safer lookup - use product.id if frontend sends it
        product = db.query(Product).filter(Product.code == item.code).first()
        if not product:
            db.rollback()
            raise HTTPException(status_code=404, detail=f"Product with code {item.code} not found.")
        
        sale_entry = Sale(
            product_id=product.id,   # ✅ Correct column in Sale model
            user_id=current_user.id,
            quantity=item.quantity,
            total_price=(product.price * item.quantity),  # ✅ use DB price, not frontend
            payment_method=payload.payment_method,
            invoice_number=payload.invoice_number,
        )
        db.add(sale_entry)

    try:
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

    return {"message": "Purchase recorded successfully"}


# Sales Page
@app.get("/sales", response_class=HTMLResponse)
def sales_page(request: Request):
    return templates.TemplateResponse("sales.html", {"request": request})
# In grocerybill.py - Replace the existing api_sales function

@app.get("/api/sales")
def api_sales(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    sales_query = db.query(Sale).options(
        joinedload(Sale.product), 
    ).order_by(Sale.sale_date.desc()).all()

    return [{
        "id": s.id,
        "product_name": s.product.name if s.product else "N/A",
        "quantity": s.quantity,
        "total_price": s.total_price,
        "sale_date": s.sale_date.isoformat(),
        "invoice_number": s.invoice_number,
        "payment_method": s.payment_method
    } for s in sales_query]

@router.get("/api/sales")
def api_sales(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    try:
        # Aggregate sales grouped by invoice_number and payment_method
        sales_data = (
            db.query(
                Sale.invoice_number,
                func.sum(Sale.quantity).label("total_quantity"),
                func.sum(Sale.total_price).label("total_price"),
                Sale.payment_method,
                func.max(Sale.sale_date).label("sale_date")
            )
            .group_by(Sale.invoice_number, Sale.payment_method)
            .order_by(func.max(Sale.sale_date).desc())
            .all()
        )

        # Return list of dicts per invoice aggregation
        result = []
        for s in sales_data:
            result.append(
                {
                    "invoice_number": s.invoice_number,
                    "total_quantity": s.total_quantity,
                    "total_price": s.total_price,
                    "payment_method": s.payment_method,
                    "sale_date": s.sale_date.isoformat() if s.sale_date else None,
                }
            )
        return result

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching sales: {str(e)}")
    

@router.get("/api/monthly_sales_report")
def monthly_sales_report(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    try:
        # Group by year and month extracted from sale_date
        monthly_data = (
            db.query(
                func.strftime("%Y-%m", Sale.sale_date).label("month"),  # For SQLite/PostgreSQL use this sqlite format. For MySQL, use func.date_format(...)
                func.sum(Sale.quantity).label("total_quantity"),
                func.sum(Sale.total_price).label("total_revenue"),
            )
            .group_by("month")
            .order_by("month DESC")
            .all()
        )

        # Format results as list of dicts
        result = []
        for row in monthly_data:
            result.append(
                {
                    "month": row.month,  # e.g. "2025-09"
                    "total_quantity": row.total_quantity,
                    "total_revenue": row.total_revenue,
                }
            )
        return result

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching monthly sales report: {str(e)}")
    
# Customers Page
@app.get("/customers", response_class=HTMLResponse)
def customers_page(request: Request):
    return templates.TemplateResponse("customers.html", {"request": request})

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
def add_customer_form(request: Request):
    return templates.TemplateResponse("add_customers.html", {"request": request})

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


@app.get("/invoice-details.html")
def invoice_details(request: Request, invoice: str, db: Session = Depends(get_db)):
    # Query sales with the invoice number, eager load product relationship
    invoice_items = (
        db.query(Sale)
        .options(joinedload(Sale.product), joinedload(Sale.customer))
        .filter(Sale.invoice_number == invoice)
        .all()
    )
    if not invoice_items:
        raise HTTPException(status_code=404, detail="Invoice not found")

    # Assume all items share the same customer and sale_date for simplicity
    customer = invoice_items[0].customer if invoice_items[0].customer else None

    # Build invoice dict for template
    invoice_data = {
        "invoice_number": invoice,
        "date": invoice_items[0].sale_date,
        "customer": {
            "name": customer.name if customer else "N/A",
            "email": customer.email if customer else "N/A",
            "phone": customer.phone if customer else "N/A",
        },
        "items": [
            {
                "product_name": item.product.name if item.product else "N/A",
                "unit_price": (item.total_price / item.quantity) if item.quantity else 0,
                "quantity": item.quantity,
                "total_price": item.total_price,
            }
            for item in invoice_items
        ],
        "total_price": sum(item.total_price for item in invoice_items),
    }

    return templates.TemplateResponse("invoice-details.html", {"request": request, "invoice": invoice_data})


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
