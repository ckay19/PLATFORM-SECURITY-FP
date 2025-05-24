from app import app, db
from models import User, Transaction
from werkzeug.security import generate_password_hash
import os

with app.app_context():
    # Drop tables
    print("Dropping all tables...")
    db.drop_all()
    
    # Create tables
    print("Creating tables with updated schema...")
    db.create_all()
    
    # Create admin
    print("Creating admin user...")
    admin_user = User(
        username="admin",
        email="admin@bankapp.com",
        account_number="0000000001",
        status="active",
        is_admin=True,
        balance=0.0
    )
    admin_user.set_password("admin123")
    db.session.add(admin_user)
    db.session.commit()
    print("Database reset complete!")