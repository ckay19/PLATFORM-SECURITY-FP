import os
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_login import current_user, login_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
from dotenv import load_dotenv
from itsdangerous import URLSafeTimedSerializer
import secrets
import pymysql
from flask_wtf.csrf import CSRFProtect
from flask_limiter.errors import RateLimitExceeded
from flask_mail import Mail, Message
import logging
from flask_migrate import Migrate

# Import extensions
from extensions import db, login_manager, bcrypt, limiter

# Load environment variables
load_dotenv()

# Initialize CSRF protection
csrf = CSRFProtect()

# MySQL connection
pymysql.install_as_MySQLdb()

# Initialize Mail
mail = Mail()

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Create Flask application
def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_hex(16)

    # CSRF Protection
    csrf.init_app(app)

    # Database configuration

    # Construct the MySQL URL from individual environment variables if DATABASE_URL is not provided
    # Use defaults to avoid None values
    mysql_user = os.environ.get('MYSQL_USER', '')
    mysql_password = os.environ.get('MYSQL_PASSWORD', '')
    mysql_host = os.environ.get('MYSQL_HOST', '')  # Default to localhost if not set
    mysql_port = os.environ.get('MYSQL_PORT', '3306')
    mysql_database = os.environ.get('MYSQL_DATABASE', '')
    
    # Make sure all values are strings
    mysql_port = str(mysql_port)
    
    # Check if required parameters are set
    if not mysql_host or not mysql_user or not mysql_database:
        print(f"WARNING: Missing database configuration. Host: {mysql_host}, User: {mysql_user}, Database: {mysql_database}")
    
    db_uri = f"mysql+pymysql://{mysql_user}:{mysql_password}@{mysql_host}:{mysql_port}/{mysql_database}"
    print(f"Database URI: {db_uri}")
    app.config['SQLALCHEMY_DATABASE_URI'] = db_uri

    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Email configuration
    app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
    app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True') == 'True'
    app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
    app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')
    
    # Initialize extensions with app
    db.init_app(app)
    login_manager.init_app(app)
    bcrypt.init_app(app)
    limiter.init_app(app)
    mail.init_app(app)
    
    # Initialize Flask-Migrate
    migrate = Migrate(app, db)
    
    # Register custom error handler for rate limiting
    @app.errorhandler(RateLimitExceeded)
    def handle_rate_limit_exceeded(e):
        # Check if it's an API request (expecting JSON)
        if request.path.startswith('/api/') or request.headers.get('Accept') == 'application/json':
            return jsonify({"error": "Rate limit exceeded", "message": str(e)}), 429
        # Otherwise, return the HTML template
        return render_template('rate_limit_error.html', message=str(e)), 429

    return app

def send_email(to, subject, template):
    """
    Send an email with the given parameters
    """
    msg = Message(
        subject,
        recipients=[to],
        html=template,
        sender=app.config['MAIL_DEFAULT_SENDER']
    )
    mail.send(msg)
    
def generate_verification_token(email):
    """Generate a secure token for email verification"""
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt='email-verification-salt')

def confirm_verification_token(token, expiration=3600):
    """Confirm the token for email verification"""
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            salt='email-verification-salt',
            max_age=expiration
        )
    except:
        return None
    return email

# Create Flask app
app = create_app()

# Import models - must be after db initialization
from models import User, Transaction

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Import routes after app creation
from routes import *

# Database initialization function
def init_db():
    """Initialize the database with required tables and default admin user."""
    with app.app_context():
        # Use raw SQL to check for admin without relying on model
        from sqlalchemy import text
        with db.engine.connect() as conn:
            result = conn.execute(text("SELECT COUNT(*) FROM user WHERE is_admin = TRUE"))
            admin_count = result.scalar()
            
            if not admin_count:
                # Create admin user with SQL
                conn.execute(
                    text("INSERT INTO user (username, email, account_number, status, is_admin, balance, password_hash) "
                         "VALUES (:username, :email, :account, :status, :is_admin, :balance, :password)"),
                    {
                        "username": "admin",
                        "email": "admin@bankapp.com",
                        "account": "0000000001",
                        "status": "active",
                        "is_admin": True,
                        "balance": 0.0,
                        "password": generate_password_hash("admin123")
                    }
                )
                conn.commit()
                print("Created admin user with username 'admin' and password 'admin123'")

def update_db_schema():
    """Add missing columns to existing tables"""
    with app.app_context():
        try:
            # Use text() for raw SQL with SQLAlchemy 2.0+
            from sqlalchemy import text
            
            # Create a connection
            with db.engine.connect() as conn:
                # Add PIN columns if they don't exist
                result = conn.execute(text("SHOW COLUMNS FROM user LIKE 'pin_hash'"))
                if not result.fetchone():
                    conn.execute(text("ALTER TABLE user ADD COLUMN pin_hash VARCHAR(128)"))
                    print("Added pin_hash column")
                
                result = conn.execute(text("SHOW COLUMNS FROM user LIKE 'pin_set'"))
                if not result.fetchone():
                    conn.execute(text("ALTER TABLE user ADD COLUMN pin_set BOOLEAN DEFAULT FALSE"))
                    print("Added pin_set column")
                
                # Add profile columns if they don't exist
                for column in ['first_name', 'last_name', 'phone_number', 'address', 'profile_complete']:
                    result = conn.execute(text(f"SHOW COLUMNS FROM user LIKE '{column}'"))
                    if not result.fetchone():
                        if column == 'profile_complete':
                            conn.execute(text(f"ALTER TABLE user ADD COLUMN {column} BOOLEAN DEFAULT FALSE"))
                        else:
                            conn.execute(text(f"ALTER TABLE user ADD COLUMN {column} VARCHAR(200)"))
                        print(f"Added {column} column")
                
                # Date of birth column requires special handling
                result = conn.execute(text("SHOW COLUMNS FROM user LIKE 'date_of_birth'"))
                if not result.fetchone():
                    conn.execute(text("ALTER TABLE user ADD COLUMN date_of_birth DATE"))
                    print("Added date_of_birth column")
                
                # Commit all changes
                conn.commit()
                
            print("Schema updated successfully")
        except Exception as e:
            print(f"Error updating schema: {e}")
            import traceback
            traceback.print_exc()

# For newer WTForms versions
from wtforms.fields import StringField, PasswordField, SubmitField, BooleanField, DecimalField, RadioField, TextAreaField
from wtforms.fields import DateField  # Import DateField from wtforms.fields for WTForms >=3.0

if __name__ == '__main__':
    print("Starting application...")
    print(f"Environment variables:")
    print(f"MYSQL_HOST: {os.environ.get('MYSQL_HOST')}")
    print(f"MYSQL_USER: {os.environ.get('MYSQL_USER')}")
    print(f"MYSQL_DATABASE: {os.environ.get('MYSQL_DATABASE')}")
    
    with app.app_context():
        # First create tables that don't exist yet
        print("Creating database tables...")
        db.create_all()
        
        # Then update the schema to add missing columns
        print("Updating schema with new columns...")
        update_db_schema()
        
        # Only after schema is updated, initialize admin
        print("Initializing admin user...")
        init_db()
    
    print("Starting Flask server...")
    # HTTPS SAFETY:
    # For local development, use adhoc SSL for testing HTTPS:
    #   app.run(debug=True, ssl_context='adhoc')
    # For production, DO NOT use Flask's built-in server for HTTPS.
    # Instead, use a WSGI server (gunicorn, uWSGI, etc.) behind a reverse proxy (nginx, Apache) with a valid SSL certificate.
    import sys
    if os.environ.get("FLASK_ENV") == "production":
        print("WARNING: Do NOT use Flask's built-in server for production HTTPS. Use a WSGI server behind a reverse proxy with a valid SSL certificate.")
        app.run(debug=False)  # Should only be used for debugging, not production
    else:
        # Local development: safe to use adhoc SSL for testing
        app.run(debug=True, ssl_context='adhoc')
