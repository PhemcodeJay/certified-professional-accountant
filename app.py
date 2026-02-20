# app.py - Production-ready CPA Tax Services & Audit Application
import logging
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, g
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField, SelectField, DateField, FloatField, TextAreaField, BooleanField
from wtforms.validators import DataRequired, Email, Length, Optional, Regexp, EqualTo, ValidationError
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
from dotenv import load_dotenv
from datetime import datetime, timedelta
import sqlite3
import json
import secrets
import hashlib
from werkzeug.utils import secure_filename
from functools import wraps
import time

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(32))
app.config['SECURITY_PASSWORD_SALT'] = os.getenv('SECURITY_PASSWORD_SALT', secrets.token_hex(16))
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
app.config['ALLOWED_EXTENSIONS'] = {'pdf', 'doc', 'docx', 'xls', 'xlsx', 'csv', 'jpg', 'png', 'tiff'}
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=14)
app.config['REMEMBER_COOKIE_SECURE'] = True
app.config['REMEMBER_COOKIE_HTTPONLY'] = True

# Initialize extensions
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'warning'
csrf = CSRFProtect(app)

# Create upload folder
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Email configuration
EMAIL_HOST = os.getenv('EMAIL_HOST', 'smtp.gmail.com')
EMAIL_PORT = int(os.getenv('EMAIL_PORT', 587))
EMAIL_USER = os.getenv('EMAIL_USER', '')
EMAIL_PASS = os.getenv('EMAIL_PASS', '')
EMAIL_USE_TLS = os.getenv('EMAIL_USE_TLS', 'True').lower() == 'true'
ADMIN_EMAIL = os.getenv('ADMIN_EMAIL', 'admin@greencpapartners.com')
FIRM_NAME = os.getenv('FIRM_NAME', 'Pacific Green Partners, LLP')
FIRM_PHONE = os.getenv('FIRM_PHONE', '(213) 555-0123')
FIRM_ADDRESS = os.getenv('FIRM_ADDRESS', '123 Financial District Blvd, Los Angeles, CA 90012')
CPA_LICENSE = os.getenv('CPA_LICENSE', 'CPA License #123456')

# Database connection helper
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect('users.db')
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    """Initialize database with all required tables"""
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        full_name TEXT NOT NULL,
        company TEXT,
        phone TEXT,
        ein TEXT,
        business_type TEXT,
        tax_year_end DATE,
        role TEXT DEFAULT 'client',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP,
        last_ip TEXT,
        is_active BOOLEAN DEFAULT 1,
        email_verified BOOLEAN DEFAULT 0,
        verification_token TEXT,
        reset_token TEXT,
        reset_token_expiry TIMESTAMP,
        two_factor_enabled BOOLEAN DEFAULT 0,
        two_factor_secret TEXT
    )''')
    
    # User profiles with JSON fields
    c.execute('''CREATE TABLE IF NOT EXISTS user_profiles (
        user_id INTEGER PRIMARY KEY,
        tax_data TEXT DEFAULT '{}',
        esg_data TEXT DEFAULT '{}',
        preferences TEXT DEFAULT '{"theme": "light", "notifications": true, "email_updates": true}',
        tax_status TEXT DEFAULT 'pending',
        audit_status TEXT DEFAULT 'not_scheduled',
        last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    )''')
    
    # Documents table
    c.execute('''CREATE TABLE IF NOT EXISTS documents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        filename TEXT NOT NULL,
        original_filename TEXT NOT NULL,
        category TEXT,
        upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        file_size INTEGER,
        file_path TEXT,
        mime_type TEXT,
        checksum TEXT,
        status TEXT DEFAULT 'pending',
        reviewed_by INTEGER,
        reviewed_date TIMESTAMP,
        review_notes TEXT,
        is_deleted BOOLEAN DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
        FOREIGN KEY (reviewed_by) REFERENCES users (id)
    )''')
    
    # Tax filings table
    c.execute('''CREATE TABLE IF NOT EXISTS tax_filings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        tax_year INTEGER NOT NULL,
        filing_type TEXT NOT NULL,
        form_type TEXT NOT NULL,
        status TEXT DEFAULT 'draft',
        submitted_date TIMESTAMP,
        due_date TIMESTAMP,
        amount_due DECIMAL(10,2),
        amount_paid DECIMAL(10,2),
        payment_date TIMESTAMP,
        payment_method TEXT,
        documents TEXT DEFAULT '[]',
        notes TEXT,
        preparer_id INTEGER,
        reviewed_by INTEGER,
        reviewed_date TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
        FOREIGN KEY (preparer_id) REFERENCES users (id),
        FOREIGN KEY (reviewed_by) REFERENCES users (id)
    )''')
    
    # Audits table
    c.execute('''CREATE TABLE IF NOT EXISTS audits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        audit_type TEXT NOT NULL,
        audit_year INTEGER NOT NULL,
        audit_scope TEXT NOT NULL,
        status TEXT DEFAULT 'scheduled',
        scheduled_date TIMESTAMP,
        completion_date TIMESTAMP,
        auditor_assigned TEXT,
        auditor_id INTEGER,
        findings TEXT DEFAULT '[]',
        recommendations TEXT DEFAULT '[]',
        documents TEXT DEFAULT '[]',
        notes TEXT,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
        FOREIGN KEY (auditor_id) REFERENCES users (id)
    )''')
    
    # Services table
    c.execute('''CREATE TABLE IF NOT EXISTS services (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        service_type TEXT NOT NULL,
        service_name TEXT NOT NULL,
        status TEXT DEFAULT 'active',
        start_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        end_date TIMESTAMP,
        renewal_date TIMESTAMP,
        monthly_fee DECIMAL(10,2),
        billing_cycle TEXT DEFAULT 'monthly',
        documents TEXT DEFAULT '[]',
        notes TEXT,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    )''')
    
    # Messages table
    c.execute('''CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER NOT NULL,
        receiver_id INTEGER NOT NULL,
        subject TEXT NOT NULL,
        message TEXT NOT NULL,
        read BOOLEAN DEFAULT 0,
        read_date TIMESTAMP,
        sent_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        attachments TEXT DEFAULT '[]',
        is_deleted_sender BOOLEAN DEFAULT 0,
        is_deleted_receiver BOOLEAN DEFAULT 0,
        FOREIGN KEY (sender_id) REFERENCES users (id) ON DELETE CASCADE,
        FOREIGN KEY (receiver_id) REFERENCES users (id) ON DELETE CASCADE
    )''')
    
    # Activity log for audit trail
    c.execute('''CREATE TABLE IF NOT EXISTS activity_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        details TEXT,
        ip_address TEXT,
        user_agent TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
    )''')
    
    # Create indexes for performance
    c.execute('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_documents_user_id ON documents(user_id)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_tax_filings_user_id ON tax_filings(user_id)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_audits_user_id ON audits(user_id)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_messages_receiver_id ON messages(receiver_id)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_activity_log_user_id ON activity_log(user_id)')
    
    # Create admin user if not exists
    admin_password = bcrypt.generate_password_hash('Admin@123').decode('utf-8')
    try:
        c.execute('''INSERT OR IGNORE INTO users 
            (username, email, password, full_name, company, role, is_active, email_verified) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)''', 
            ('admin', 'admin@greencpapartners.com', admin_password, 
             'System Administrator', 'Pacific Green Partners, LLP', 'admin', 1, 1))
        
        # Get admin ID
        c.execute('SELECT id FROM users WHERE username = ?', ('admin',))
        admin_id = c.fetchone()[0]
        
        # Create sample client user
        sample_password = bcrypt.generate_password_hash('Client@123').decode('utf-8')
        c.execute('''INSERT OR IGNORE INTO users 
            (username, email, password, full_name, company, phone, ein, business_type, tax_year_end, role, is_active, email_verified) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', 
            ('client', 'client@example.com', sample_password, 'John Smith', 
             'ABC Manufacturing Inc.', '555-123-4567', '12-3456789', 'LLC', '2025-12-31', 'client', 1, 1))
        
        # Get client ID
        c.execute('SELECT id FROM users WHERE username = ?', ('client',))
        client_id = c.fetchone()[0]
        
        # Sample profile data
        sample_tax_data = json.dumps({
            'income': 850000,
            'deductions': 420000,
            'credits': 28500,
            'filing_status': 'corporation',
            'tax_year': 2025,
            'estimated_tax': 85450
        })
        
        sample_esg_data = json.dumps({
            'environmental_score': 82,
            'social_score': 78,
            'governance_score': 85,
            'overall_score': 81.7,
            'carbon_footprint': '245 tCO2e',
            'carbon_reduction': '15%',
            'energy_consumption': '150,000 kWh',
            'renewable_energy': '65%',
            'waste_recycled': '92%',
            'employee_satisfaction': '4.2/5',
            'community_investment': '$25,000',
            'diversity_index': 78,
            'sustainability_goals': ['Net Zero by 2030', '100% Renewable by 2028'],
            'gri_compliance': '100%',
            'sasb_compliance': '85%',
            'tcfd_alignment': '70%'
        })
        
        c.execute('''INSERT OR IGNORE INTO user_profiles 
            (user_id, tax_data, esg_data, tax_status, audit_status) 
            VALUES (?, ?, ?, ?, ?)''', 
            (client_id, sample_tax_data, sample_esg_data, 'in_progress', 'scheduled'))
        
        # Sample tax filing
        c.execute('''INSERT OR IGNORE INTO tax_filings 
            (user_id, tax_year, filing_type, form_type, status, due_date, amount_due) 
            VALUES (?, ?, ?, ?, ?, ?, ?)''',
            (client_id, 2025, 'business', '1120', 'draft', '2026-03-15', 85450.00))
        
        # Sample audit
        c.execute('''INSERT OR IGNORE INTO audits 
            (user_id, audit_type, audit_year, audit_scope, status, scheduled_date, auditor_assigned) 
            VALUES (?, ?, ?, ?, ?, ?, ?)''',
            (client_id, 'Financial', 2025, 'business', 'scheduled', '2026-04-15', 'Michael Chen, CPA'))
        
        # Sample service
        c.execute('''INSERT OR IGNORE INTO services 
            (user_id, service_type, service_name, monthly_fee) 
            VALUES (?, ?, ?, ?)''',
            (client_id, 'tax', 'Tax Preparation & Planning', 250.00))
        
        conn.commit()
        logger.info("Database initialized successfully")
    except Exception as e:
        conn.rollback()
        logger.error(f"Database initialization error: {e}")
    finally:
        conn.close()

# User class
class User(UserMixin):
    def __init__(self, id, username, email, role, full_name, company=None):
        self.id = id
        self.username = username
        self.email = email
        self.role = role
        self.full_name = full_name
        self.company = company
    
    def is_admin(self):
        return self.role == 'admin'
    
    def is_client(self):
        return self.role == 'client'

@login_manager.user_loader
def load_user(user_id):
    try:
        conn = sqlite3.connect('users.db')
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute('SELECT id, username, email, role, full_name, company FROM users WHERE id = ? AND is_active = 1', (user_id,))
        user_data = c.fetchone()
        conn.close()
        if user_data:
            return User(
                id=user_data['id'],
                username=user_data['username'],
                email=user_data['email'],
                role=user_data['role'],
                full_name=user_data['full_name'],
                company=user_data['company']
            )
    except Exception as e:
        logger.error(f"Error loading user {user_id}: {e}")
    return None

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('Access denied. Administrator privileges required.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# Log activity decorator
def log_activity(action):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            result = f(*args, **kwargs)
            try:
                conn = get_db()
                c = conn.cursor()
                c.execute('''INSERT INTO activity_log (user_id, action, details, ip_address, user_agent) 
                            VALUES (?, ?, ?, ?, ?)''',
                         (current_user.id if current_user.is_authenticated else None,
                          action,
                          request.endpoint,
                          request.remote_addr,
                          request.user_agent.string))
                conn.commit()
            except Exception as e:
                logger.error(f"Error logging activity: {e}")
            return result
        return decorated_function
    return decorator

# Forms
class LoginForm(FlaskForm):
    username = StringField('Username or Email', validators=[DataRequired(), Length(min=3, max=100)])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=50)])
    email = StringField('Email Address', validators=[DataRequired(), Email(), Length(max=100)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, message='Password must be at least 8 characters')])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match')])
    full_name = StringField('Full Legal Name', validators=[DataRequired(), Length(max=100)])
    company = StringField('Company Name (if business)', validators=[Optional(), Length(max=100)])
    phone = StringField('Phone Number', validators=[Optional(), Length(max=20)])
    ein = StringField('EIN / Tax ID', validators=[Optional(), Regexp(r'^\d{2}-\d{7}$', message='Invalid EIN format. Use XX-XXXXXXX')])
    business_type = SelectField('Business Type', choices=[
        ('', 'Select business type...'),
        ('sole_proprietor', 'Sole Proprietor'),
        ('llc', 'LLC'),
        ('s_corporation', 'S Corporation'),
        ('c_corporation', 'C Corporation'),
        ('partnership', 'Partnership'),
        ('nonprofit', 'Nonprofit'),
        ('individual', 'Individual'),
        ('other', 'Other')
    ])
    tax_year_end = DateField('Tax Year End Date', validators=[Optional()])
    terms = BooleanField('I agree to the Terms of Service and Privacy Policy', validators=[DataRequired()])
    submit = SubmitField('Create Account')
    
    def validate_username(self, username):
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT id FROM users WHERE username = ?', (username.data.lower(),))
        if c.fetchone():
            raise ValidationError('Username already taken. Please choose another.')
    
    def validate_email(self, email):
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT id FROM users WHERE email = ?', (email.data.lower(),))
        if c.fetchone():
            raise ValidationError('Email already registered. Please use another or login.')

class TaxFilingForm(FlaskForm):
    tax_year = StringField('Tax Year', validators=[DataRequired(), Regexp(r'^\d{4}$', message='Enter a valid 4-digit year')])
    filing_type = SelectField('Filing Type', choices=[
        ('', 'Select filing type...'),
        ('personal', 'Personal'),
        ('business', 'Business'),
        ('partnership', 'Partnership'),
        ('nonprofit', 'Nonprofit')
    ], validators=[DataRequired()])
    form_type = StringField('Form Type (e.g., 1040, 1120, 1065)', validators=[DataRequired(), Length(max=20)])
    amount_due = FloatField('Estimated Amount Due ($)', validators=[Optional()])
    notes = TextAreaField('Additional Notes', validators=[Optional(), Length(max=1000)])
    submit = SubmitField('Save Tax Draft')
    
    def validate_tax_year(self, tax_year):
        year = int(tax_year.data)
        current_year = datetime.now().year
        if year < 2000 or year > current_year + 1:
            raise ValidationError(f'Tax year must be between 2000 and {current_year + 1}')

class AuditForm(FlaskForm):
    audit_year = StringField('Audit Year', validators=[DataRequired(), Regexp(r'^\d{4}$', message='Enter a valid 4-digit year')])
    audit_type = SelectField('Audit Type', choices=[
        ('', 'Select audit type...'),
        ('IRS', 'IRS Tax Audit'),
        ('financial', 'Financial Statement Audit'),
        ('compliance', 'Compliance Audit'),
        ('esg', 'ESG/Sustainability Audit'),
        ('internal', 'Internal Audit')
    ], validators=[DataRequired()])
    audit_scope = SelectField('Scope', choices=[
        ('', 'Select scope...'),
        ('personal', 'Personal'),
        ('business', 'Business'),
        ('both', 'Both Personal & Business')
    ], validators=[DataRequired()])
    scheduled_date = DateField('Preferred Start Date', validators=[DataRequired()])
    notes = TextAreaField('Additional Information', validators=[Optional(), Length(max=1000)])
    submit = SubmitField('Schedule Audit Consultation')
    
    def validate_scheduled_date(self, scheduled_date):
        if scheduled_date.data < datetime.now().date():
            raise ValidationError('Scheduled date must be in the future')

class ProfileForm(FlaskForm):
    full_name = StringField('Full Name', validators=[DataRequired(), Length(max=100)])
    company = StringField('Company', validators=[Optional(), Length(max=100)])
    phone = StringField('Phone', validators=[Optional(), Length(max=20)])
    ein = StringField('EIN/Tax ID', validators=[Optional(), Regexp(r'^\d{2}-\d{7}$', message='Invalid EIN format')])
    business_type = SelectField('Business Type', choices=[
        ('', 'Select...'),
        ('sole_proprietor', 'Sole Proprietor'),
        ('llc', 'LLC'),
        ('s_corporation', 'S Corporation'),
        ('c_corporation', 'C Corporation'),
        ('partnership', 'Partnership'),
        ('nonprofit', 'Nonprofit'),
        ('individual', 'Individual'),
        ('other', 'Other')
    ])
    tax_year_end = DateField('Tax Year End', validators=[Optional()])
    submit = SubmitField('Update Profile')

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Change Password')

class ContactForm(FlaskForm):
    name = StringField('Full Name', validators=[DataRequired(), Length(max=100)])
    email = StringField('Email Address', validators=[DataRequired(), Email()])
    phone = StringField('Phone Number', validators=[Optional(), Length(max=20)])
    service = SelectField('Service Interested In', choices=[
        ('', 'Select a service...'),
        ('tax', 'Tax Preparation & Planning'),
        ('audit', 'Audit & Assurance'),
        ('esg', 'ESG & Sustainability'),
        ('advisory', 'Financial Advisory'),
        ('other', 'Other')
    ])
    message = TextAreaField('How can we help you?', validators=[DataRequired(), Length(min=10, max=2000)])
    honeypot = StringField('Leave this blank')  # Spam protection
    submit = SubmitField('Send Message')

# Helper functions
def send_email(to, subject, body, html=None):
    """Send email with proper error handling"""
    if not EMAIL_USER or not EMAIL_PASS:
        logger.warning("Email credentials not configured")
        return False
    
    try:
        msg = MIMEMultipart('alternative')
        msg['From'] = f"{FIRM_NAME} <{EMAIL_USER}>"
        msg['To'] = to
        msg['Subject'] = subject
        
        # Add plain text version
        msg.attach(MIMEText(body, 'plain'))
        
        # Add HTML version if provided
        if html:
            msg.attach(MIMEText(html, 'html'))
        
        # Send email
        server = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT)
        if EMAIL_USE_TLS:
            server.starttls()
        server.login(EMAIL_USER, EMAIL_PASS)
        server.send_message(msg)
        server.quit()
        
        logger.info(f"Email sent to {to}: {subject}")
        return True
    except Exception as e:
        logger.error(f"Email error to {to}: {e}")
        return False

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def calculate_file_checksum(file_path):
    """Calculate SHA-256 checksum of file"""
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for block in iter(lambda: f.read(4096), b''):
            sha256.update(block)
    return sha256.hexdigest()

def calculate_tax(income, deductions=0, credits=0, filing_status='single', tax_year=2025):
    """Calculate estimated tax using current IRS brackets"""
    taxable_income = max(0, income - deductions)
    
    # 2025 IRS tax brackets (projected, adjust as needed)
    brackets = {
        'single': [
            (11925, 0.10),
            (48475, 0.12),
            (103350, 0.22),
            (197300, 0.24),
            (250525, 0.32),
            (626350, 0.35),
            (float('inf'), 0.37)
        ],
        'married_joint': [
            (23850, 0.10),
            (96950, 0.12),
            (206700, 0.22),
            (394600, 0.24),
            (501050, 0.32),
            (751550, 0.35),
            (float('inf'), 0.37)
        ],
        'married_separate': [
            (11925, 0.10),
            (48475, 0.12),
            (103350, 0.22),
            (197300, 0.24),
            (250525, 0.32),
            (375775, 0.35),
            (float('inf'), 0.37)
        ],
        'head_of_household': [
            (17000, 0.10),
            (64850, 0.12),
            (103350, 0.22),
            (197300, 0.24),
            (250525, 0.32),
            (626350, 0.35),
            (float('inf'), 0.37)
        ],
        'corporation': [(float('inf'), 0.21)]  # Flat 21% corporate rate
    }
    
    # Get appropriate brackets
    rates = brackets.get(filing_status, brackets['single'])
    
    # Calculate tax
    tax = 0
    remaining_income = taxable_income
    previous_limit = 0
    
    for limit, rate in rates:
        if remaining_income <= 0:
            break
        taxable_in_bracket = min(remaining_income, limit - previous_limit)
        tax += taxable_in_bracket * rate
        remaining_income -= taxable_in_bracket
        previous_limit = limit
    
    # Apply credits
    tax_after_credits = max(0, tax - credits)
    
    # Calculate effective rate
    effective_rate = (tax_after_credits / income * 100) if income > 0 else 0
    
    return {
        'taxable_income': round(taxable_income, 2),
        'tax_before_credits': round(tax, 2),
        'tax_after_credits': round(tax_after_credits, 2),
        'effective_rate': round(effective_rate, 2),
        'credits_applied': round(credits, 2),
        'tax_savings': round(credits, 2)
    }

# Routes
@app.route('/')
def index():
    return render_template('index.html', 
                         firm_name=FIRM_NAME,
                         firm_phone=FIRM_PHONE,
                         cpa_license=CPA_LICENSE)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('portal'))
    
    form = LoginForm()
    if form.validate_on_submit():
        try:
            conn = get_db()
            c = conn.cursor()
            c.execute('''SELECT id, username, email, password, full_name, company, role, is_active 
                        FROM users WHERE (username = ? OR email = ?)''', 
                     (form.username.data.lower(), form.username.data.lower()))
            user = c.fetchone()
            
            if user and bcrypt.check_password_hash(user['password'], form.password.data):
                if not user['is_active']:
                    flash('This account has been deactivated. Please contact support.', 'danger')
                    return render_template('login.html', form=form)
                
                # Update last login
                c.execute('''UPDATE users SET last_login = CURRENT_TIMESTAMP, last_ip = ? 
                            WHERE id = ?''', (request.remote_addr, user['id']))
                conn.commit()
                
                # Log activity
                c.execute('''INSERT INTO activity_log (user_id, action, ip_address, user_agent) 
                            VALUES (?, ?, ?, ?)''',
                         (user['id'], 'login', request.remote_addr, request.user_agent.string))
                conn.commit()
                
                user_obj = User(
                    id=user['id'],
                    username=user['username'],
                    email=user['email'],
                    role=user['role'],
                    full_name=user['full_name'],
                    company=user['company']
                )
                
                login_user(user_obj, remember=form.remember_me.data)
                
                flash(f'Welcome back, {user["full_name"]}!', 'success')
                
                next_page = request.args.get('next')
                if user['role'] == 'admin':
                    return redirect(next_page) if next_page else redirect(url_for('admin_dashboard'))
                return redirect(next_page) if next_page else redirect(url_for('portal'))
            else:
                flash('Invalid username/email or password.', 'danger')
        except Exception as e:
            logger.error(f"Login error: {e}")
            flash('An error occurred. Please try again.', 'danger')
    
    return render_template('login.html', form=form, firm_name=FIRM_NAME)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('portal'))
    
    form = RegisterForm()
    if form.validate_on_submit():
        try:
            conn = get_db()
            c = conn.cursor()
            
            # Hash password
            hashed_pw = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            
            # Generate verification token
            verification_token = secrets.token_urlsafe(32)
            
            # Format tax year end if provided
            tax_year_end_str = form.tax_year_end.data.strftime('%Y-%m-%d') if form.tax_year_end.data else None
            
            # Insert user
            c.execute('''INSERT INTO users 
                (username, email, password, full_name, company, phone, ein, business_type, tax_year_end, verification_token) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (form.username.data.lower(), form.email.data.lower(), hashed_pw, 
                 form.full_name.data, form.company.data, form.phone.data, 
                 form.ein.data, form.business_type.data, tax_year_end_str, verification_token))
            
            user_id = c.lastrowid
            
            # Create profile
            c.execute('INSERT INTO user_profiles (user_id) VALUES (?)', (user_id,))
            
            conn.commit()
            
            # Send welcome email
            subject = f"Welcome to {FIRM_NAME}"
            body = f"""
            Dear {form.full_name.data},
            
            Thank you for registering with {FIRM_NAME}. Your account has been created successfully.
            
            Please verify your email address by clicking the link below:
            {url_for('verify_email', token=verification_token, _external=True)}
            
            Important Disclaimers:
            - This portal is for informational purposes only
            - All tax calculations are estimates and not official filings
            - Please consult with your assigned CPA for official tax advice
            - Audit services are subject to engagement letter agreement
            
            We look forward to serving your financial needs.
            
            Sincerely,
            The {FIRM_NAME} Team
            {FIRM_PHONE} | {FIRM_ADDRESS}
            """
            
            send_email(form.email.data, subject, body)
            
            flash('Registration successful! Please check your email to verify your account.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Registration error: {e}")
            flash('Registration failed. Please try again.', 'danger')
    
    return render_template('register.html', form=form, firm_name=FIRM_NAME)

@app.route('/verify-email/<token>')
def verify_email(token):
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute('UPDATE users SET email_verified = 1, verification_token = NULL WHERE verification_token = ?', (token,))
        if c.rowcount > 0:
            conn.commit()
            flash('Email verified successfully! You can now log in.', 'success')
        else:
            flash('Invalid or expired verification link.', 'danger')
    except Exception as e:
        logger.error(f"Email verification error: {e}")
        flash('An error occurred. Please try again.', 'danger')
    
    return redirect(url_for('login'))

@app.route('/portal')
@login_required
@log_activity('view_portal')
def portal():
    try:
        conn = get_db()
        c = conn.cursor()
        
        # Get user profile
        c.execute('''SELECT up.*, u.company, u.full_name, u.email, u.phone, u.ein, u.business_type 
                    FROM user_profiles up 
                    JOIN users u ON u.id = up.user_id 
                    WHERE up.user_id = ?''', (current_user.id,))
        profile = c.fetchone()
        
        # Get recent tax filings
        c.execute('''SELECT * FROM tax_filings WHERE user_id = ? ORDER BY submitted_date DESC LIMIT 5''', (current_user.id,))
        tax_filings = c.fetchall()
        
        # Get upcoming audits
        c.execute('''SELECT * FROM audits WHERE user_id = ? AND status IN ('scheduled', 'in_progress') ORDER BY scheduled_date LIMIT 5''', (current_user.id,))
        audits = c.fetchall()
        
        # Get recent documents
        c.execute('''SELECT * FROM documents WHERE user_id = ? AND is_deleted = 0 ORDER BY upload_date DESC LIMIT 10''', (current_user.id,))
        documents = c.fetchall()
        
        # Get unread messages
        c.execute('''SELECT COUNT(*) as count FROM messages WHERE receiver_id = ? AND read = 0 AND is_deleted_receiver = 0''', (current_user.id,))
        unread_count = c.fetchone()['count']
        
        # Get active services
        c.execute('''SELECT * FROM services WHERE user_id = ? AND status = 'active' ORDER BY start_date''', (current_user.id,))
        services = c.fetchall()
        
        return render_template('portal.html',
                             profile=profile,
                             tax_filings=tax_filings,
                             audits=audits,
                             documents=documents,
                             unread_count=unread_count,
                             services=services,
                             firm_name=FIRM_NAME,
                             cpa_license=CPA_LICENSE,
                             disclaimer="IMPORTANT: All tax calculations and estimates are for planning purposes only. Not official IRS filings. Please consult with your assigned CPA.")
    except Exception as e:
        logger.error(f"Portal error for user {current_user.id}: {e}")
        flash('Error loading portal data. Please try again.', 'danger')
        return redirect(url_for('index'))

@app.route('/upload', methods=['POST'])
@login_required
@log_activity('upload_document')
def upload():
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'message': 'No file selected'})
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'message': 'No file selected'})
        
        if not allowed_file(file.filename):
            return jsonify({'success': False, 'message': 'File type not allowed'})
        
        category = request.form.get('category', 'other')
        
        # Secure filename
        original_filename = file.filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        secure_name = secure_filename(f"{current_user.id}_{timestamp}_{original_filename}")
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_name)
        
        # Save file
        file.save(file_path)
        
        # Calculate checksum
        checksum = calculate_file_checksum(file_path)
        
        # Get file size
        file_size = os.path.getsize(file_path)
        
        # Save to database
        conn = get_db()
        c = conn.cursor()
        c.execute('''INSERT INTO documents 
            (user_id, filename, original_filename, category, file_size, file_path, mime_type, checksum) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
            (current_user.id, secure_name, original_filename, category, file_size, 
             file_path, file.mimetype, checksum))
        conn.commit()
        
        # Log activity
        c.execute('''INSERT INTO activity_log (user_id, action, details, ip_address) 
                    VALUES (?, ?, ?, ?)''',
                 (current_user.id, 'upload_document', f"Uploaded: {original_filename}", request.remote_addr))
        conn.commit()
        
        return jsonify({
            'success': True, 
            'message': 'File uploaded successfully',
            'filename': original_filename,
            'size': file_size,
            'id': c.lastrowid
        })
        
    except Exception as e:
        logger.error(f"Upload error: {e}")
        return jsonify({'success': False, 'message': 'Upload failed. Please try again.'})

@app.route('/file_tax', methods=['GET', 'POST'])
@login_required
@log_activity('file_tax')
def file_tax():
    form = TaxFilingForm()
    
    if form.validate_on_submit():
        try:
            conn = get_db()
            c = conn.cursor()
            
            due_date = datetime(int(form.tax_year.data), 3, 15) if form.filing_type.data == 'business' else datetime(int(form.tax_year.data) + 1, 4, 15)
            
            c.execute('''INSERT INTO tax_filings 
                (user_id, tax_year, filing_type, form_type, amount_due, notes, due_date, status) 
                VALUES (?, ?, ?, ?, ?, ?, ?, 'draft')''',
                (current_user.id, form.tax_year.data, form.filing_type.data, 
                 form.form_type.data, form.amount_due.data, form.notes.data, due_date))
            
            conn.commit()
            
            # Notify admin
            send_email(
                ADMIN_EMAIL,
                f"New Tax Filing Draft - {current_user.full_name}",
                f"Client: {current_user.full_name}\nYear: {form.tax_year.data}\nType: {form.filing_type.data}\nForm: {form.form_type.data}"
            )
            
            flash('Tax filing draft saved successfully. A CPA will review your submission.', 'success')
            return redirect(url_for('portal'))
            
        except Exception as e:
            logger.error(f"Tax filing error: {e}")
            flash('Error saving tax filing. Please try again.', 'danger')
    
    return render_template('file_tax.html', form=form, firm_name=FIRM_NAME)

@app.route('/schedule_audit', methods=['GET', 'POST'])
@login_required
@log_activity('schedule_audit')
def schedule_audit():
    form = AuditForm()
    
    if form.validate_on_submit():
        try:
            conn = get_db()
            c = conn.cursor()
            
            scheduled_date_str = form.scheduled_date.data.strftime('%Y-%m-%d')
            
            c.execute('''INSERT INTO audits 
                (user_id, audit_year, audit_type, audit_scope, scheduled_date, status) 
                VALUES (?, ?, ?, ?, ?, 'scheduled')''',
                (current_user.id, form.audit_year.data, form.audit_type.data, 
                 form.audit_scope.data, scheduled_date_str))
            
            conn.commit()
            
            # Notify admin
            send_email(
                ADMIN_EMAIL,
                f"New Audit Request - {current_user.full_name}",
                f"Client: {current_user.full_name}\nYear: {form.audit_year.data}\nType: {form.audit_type.data}\nDate: {scheduled_date_str}"
            )
            
            flash('Audit consultation scheduled. An auditor will contact you within 2 business days.', 'success')
            return redirect(url_for('portal'))
            
        except Exception as e:
            logger.error(f"Audit scheduling error: {e}")
            flash('Error scheduling audit. Please try again.', 'danger')
    
    return render_template('schedule_audit.html', form=form, firm_name=FIRM_NAME)

@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    try:
        conn = get_db()
        c = conn.cursor()
        
        # Statistics
        c.execute('SELECT COUNT(*) as count FROM users WHERE role = "client" AND is_active = 1')
        total_clients = c.fetchone()['count']
        
        c.execute('SELECT COUNT(*) as count FROM tax_filings WHERE status IN ("draft", "pending", "in_review")')
        pending_tax = c.fetchone()['count']
        
        c.execute('SELECT COUNT(*) as count FROM audits WHERE status IN ("scheduled", "in_progress")')
        active_audits = c.fetchone()['count']
        
        c.execute('SELECT COUNT(*) as count FROM messages WHERE read = 0')
        unread_messages = c.fetchone()['count']
        
        c.execute('SELECT COUNT(*) as count FROM documents WHERE status = "pending"')
        pending_documents = c.fetchone()['count']
        
        c.execute('SELECT COUNT(*) as count FROM users WHERE email_verified = 0')
        unverified_users = c.fetchone()['count']
        
        # Recent activity
        c.execute('''SELECT al.*, u.full_name, u.email 
                    FROM activity_log al 
                    LEFT JOIN users u ON u.id = al.user_id 
                    ORDER BY al.timestamp DESC LIMIT 20''')
        recent_activity = c.fetchall()
        
        # Recent tax filings
        c.execute('''SELECT tf.*, u.full_name, u.company, u.email 
                    FROM tax_filings tf 
                    JOIN users u ON tf.user_id = u.id 
                    ORDER BY tf.submitted_date DESC NULLS LAST LIMIT 10''')
        recent_filings = c.fetchall()
        
        # Recent registrations
        c.execute('''SELECT id, full_name, email, company, created_at 
                    FROM users WHERE role = "client" 
                    ORDER BY created_at DESC LIMIT 10''')
        recent_clients = c.fetchall()
        
        return render_template('admin_dashboard.html',
                             total_clients=total_clients,
                             pending_tax=pending_tax,
                             active_audits=active_audits,
                             unread_messages=unread_messages,
                             pending_documents=pending_documents,
                             unverified_users=unverified_users,
                             recent_activity=recent_activity,
                             recent_filings=recent_filings,
                             recent_clients=recent_clients,
                             firm_name=FIRM_NAME)
    except Exception as e:
        logger.error(f"Admin dashboard error: {e}")
        flash('Error loading dashboard', 'danger')
        return redirect(url_for('portal'))

@app.route('/api/tax_calculator', methods=['POST'])
@login_required
def tax_calculator_api():
    try:
        data = request.get_json()
        
        income = float(data.get('income', 0))
        deductions = float(data.get('deductions', 0))
        credits = float(data.get('credits', 0))
        filing_status = data.get('filing_status', 'single')
        tax_year = int(data.get('tax_year', datetime.now().year))
        
        result = calculate_tax(income, deductions, credits, filing_status, tax_year)
        
        result['disclaimer'] = 'This is an estimate for planning purposes only. Actual tax liability may vary. Consult with your CPA.'
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Tax calculator error: {e}")
        return jsonify({'error': 'Calculation failed'}), 400

@app.route('/profile', methods=['GET', 'POST'])
@login_required
@log_activity('view_profile')
def profile():
    form = ProfileForm()
    
    if request.method == 'GET':
        conn = get_db()
        c = conn.cursor()
        c.execute('''SELECT full_name, company, phone, ein, business_type, tax_year_end 
                    FROM users WHERE id = ?''', (current_user.id,))
        user = c.fetchone()
        
        if user:
            form.full_name.data = user['full_name']
            form.company.data = user['company']
            form.phone.data = user['phone']
            form.ein.data = user['ein']
            form.business_type.data = user['business_type']
            if user['tax_year_end']:
                form.tax_year_end.data = datetime.strptime(user['tax_year_end'], '%Y-%m-%d').date()
    
    if form.validate_on_submit():
        try:
            conn = get_db()
            c = conn.cursor()
            
            tax_year_end_str = form.tax_year_end.data.strftime('%Y-%m-%d') if form.tax_year_end.data else None
            
            c.execute('''UPDATE users SET 
                full_name = ?, company = ?, phone = ?, ein = ?, business_type = ?, tax_year_end = ? 
                WHERE id = ?''',
                (form.full_name.data, form.company.data, form.phone.data, 
                 form.ein.data, form.business_type.data, tax_year_end_str, current_user.id))
            
            conn.commit()
            
            flash('Profile updated successfully', 'success')
            return redirect(url_for('portal'))
            
        except Exception as e:
            logger.error(f"Profile update error: {e}")
            flash('Error updating profile', 'danger')
    
    return render_template('profile.html', form=form, firm_name=FIRM_NAME)

@app.route('/change-password', methods=['POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    
    if form.validate_on_submit():
        try:
            conn = get_db()
            c = conn.cursor()
            
            c.execute('SELECT password FROM users WHERE id = ?', (current_user.id,))
            user = c.fetchone()
            
            if bcrypt.check_password_hash(user['password'], form.current_password.data):
                new_hashed = bcrypt.generate_password_hash(form.new_password.data).decode('utf-8')
                c.execute('UPDATE users SET password = ? WHERE id = ?', (new_hashed, current_user.id))
                conn.commit()
                
                flash('Password changed successfully', 'success')
            else:
                flash('Current password is incorrect', 'danger')
                
        except Exception as e:
            logger.error(f"Password change error: {e}")
            flash('Error changing password', 'danger')
    
    return redirect(url_for('profile'))

@app.route('/contact', methods=['POST'])
def contact():
    form = ContactForm()
    
    # Honeypot check
    if form.honeypot.data:
        # Spam bot detected
        return redirect(url_for('index'))
    
    if form.validate_on_submit():
        try:
            # Send email to admin
            subject = f"Contact Form: {form.name.data} - {form.service.data}"
            body = f"""
            Name: {form.name.data}
            Email: {form.email.data}
            Phone: {form.phone.data or 'Not provided'}
            Service: {form.service.data}
            
            Message:
            {form.message.data}
            
            IP: {request.remote_addr}
            User Agent: {request.user_agent.string}
            """
            
            send_email(ADMIN_EMAIL, subject, body)
            
            # Send auto-reply to user
            user_subject = f"Thank you for contacting {FIRM_NAME}"
            user_body = f"""
            Dear {form.name.data},
            
            Thank you for reaching out to {FIRM_NAME}. We have received your inquiry regarding {form.service.data or 'our services'}.
            
            A team member will respond to your message within 1-2 business days.
            
            For immediate assistance, please call us at {FIRM_PHONE}.
            
            Sincerely,
            The {FIRM_NAME} Team
            """
            
            send_email(form.email.data, user_subject, user_body)
            
            flash('Thank you for your message. We\'ll contact you soon.', 'success')
            
        except Exception as e:
            logger.error(f"Contact form error: {e}")
            flash('Error sending message. Please try again or call us.', 'danger')
    
    return redirect(url_for('index') + '#contact')

@app.route('/api/esg_report')
@login_required
def get_esg_report():
    try:
        conn = get_db()
        c = conn.cursor()
        
        c.execute('SELECT esg_data, tax_data FROM user_profiles WHERE user_id = ?', (current_user.id,))
        profile = c.fetchone()
        
        if profile and profile['esg_data']:
            esg_data = json.loads(profile['esg_data'])
            
            # Calculate overall score
            env_score = esg_data.get('environmental_score', 75)
            social_score = esg_data.get('social_score', 75)
            gov_score = esg_data.get('governance_score', 75)
            overall = round((env_score + social_score + gov_score) / 3, 1)
            
            report = {
                'company': current_user.company or current_user.full_name,
                'report_date': datetime.now().strftime('%Y-%m-%d'),
                'overall_score': overall,
                'environmental_score': env_score,
                'social_score': social_score,
                'governance_score': gov_score,
                'metrics': esg_data,
                'disclaimer': 'ESG scores are estimates based on available data. For internal use only.'
            }
            
            return jsonify(report)
        
        return jsonify({'error': 'No ESG data available'}), 404
        
    except Exception as e:
        logger.error(f"ESG report error: {e}")
        return jsonify({'error': 'Failed to generate report'}), 500

@app.route('/documents')
@login_required
def documents():
    try:
        conn = get_db()
        c = conn.cursor()
        
        c.execute('''SELECT * FROM documents 
                    WHERE user_id = ? AND is_deleted = 0 
                    ORDER BY upload_date DESC''', (current_user.id,))
        docs = c.fetchall()
        
        return render_template('documents.html', documents=docs, firm_name=FIRM_NAME)
        
    except Exception as e:
        logger.error(f"Documents error: {e}")
        flash('Error loading documents', 'danger')
        return redirect(url_for('portal'))

@app.route('/documents/<int:doc_id>/delete', methods=['POST'])
@login_required
def delete_document(doc_id):
    try:
        conn = get_db()
        c = conn.cursor()
        
        # Verify ownership
        c.execute('SELECT file_path FROM documents WHERE id = ? AND user_id = ?', (doc_id, current_user.id))
        doc = c.fetchone()
        
        if doc:
            # Soft delete
            c.execute('UPDATE documents SET is_deleted = 1 WHERE id = ?', (doc_id,))
            conn.commit()
            
            # Optionally delete file
            # if os.path.exists(doc['file_path']):
            #     os.remove(doc['file_path'])
            
            flash('Document deleted successfully', 'success')
        else:
            flash('Document not found', 'danger')
            
    except Exception as e:
        logger.error(f"Document deletion error: {e}")
        flash('Error deleting document', 'danger')
    
    return redirect(url_for('documents'))

@app.route('/logout')
@login_required
@log_activity('logout')
def logout():
    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('index'))

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html', firm_name=FIRM_NAME), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}")
    return render_template('500.html', firm_name=FIRM_NAME), 500

@app.before_request
def before_request():
    # Update session timeout
    session.permanent = True
    app.permanent_session_lifetime = app.config['PERMANENT_SESSION_LIFETIME']
    
    # Add security headers
    @app.after_request
    def add_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        return response

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)