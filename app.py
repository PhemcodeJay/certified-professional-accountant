# app.py - Enhanced version with automated services
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
from dotenv import load_dotenv
from datetime import datetime, timedelta
import sqlite3
import json
import hashlib
import secrets
import csv
import io
from werkzeug.utils import secure_filename
import pandas as pd

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', secrets.token_hex(32))
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'pdf', 'doc', 'docx', 'xls', 'xlsx', 'csv', 'jpg', 'png'}

# Initialize extensions
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Email configuration
EMAIL_HOST = os.getenv('EMAIL_HOST', 'smtp.gmail.com')
EMAIL_PORT = int(os.getenv('EMAIL_PORT', 587))
EMAIL_USER = os.getenv('EMAIL_USER', 'your-email@gmail.com')
EMAIL_PASS = os.getenv('EMAIL_PASS', 'your-app-password')
ADMIN_EMAIL = os.getenv('ADMIN_EMAIL', 'admin@greencpapartners.com')

# Database initialization
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    # Users table
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            full_name TEXT,
            company TEXT,
            phone TEXT,
            ein TEXT,
            business_type TEXT,
            tax_year_end DATE,
            role TEXT DEFAULT 'client',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            is_active BOOLEAN DEFAULT 1
        )
    ''')
    
    # User profiles table
    c.execute('''
        CREATE TABLE IF NOT EXISTS user_profiles (
            user_id INTEGER PRIMARY KEY,
            tax_data TEXT DEFAULT '{}',
            esg_data TEXT DEFAULT '{}',
            preferences TEXT DEFAULT '{"theme": "light", "notifications": true}',
            tax_status TEXT DEFAULT 'pending',
            audit_status TEXT DEFAULT 'not_scheduled',
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # User documents table
    c.execute('''
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            category TEXT,
            upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            file_size INTEGER,
            file_path TEXT,
            status TEXT DEFAULT 'pending',
            reviewed_by TEXT,
            reviewed_date TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Tax filings table
    c.execute('''
        CREATE TABLE IF NOT EXISTS tax_filings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            tax_year INTEGER,
            filing_type TEXT,
            form_type TEXT,
            status TEXT DEFAULT 'draft',
            submitted_date TIMESTAMP,
            due_date TIMESTAMP,
            amount_due DECIMAL(10,2),
            amount_paid DECIMAL(10,2),
            documents TEXT DEFAULT '[]',
            notes TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Audits table
    c.execute('''
        CREATE TABLE IF NOT EXISTS audits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            audit_type TEXT,
            audit_year INTEGER,
            status TEXT DEFAULT 'scheduled',
            scheduled_date TIMESTAMP,
            completion_date TIMESTAMP,
            auditor_assigned TEXT,
            findings TEXT DEFAULT '[]',
            recommendations TEXT DEFAULT '[]',
            documents TEXT DEFAULT '[]',
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Services table
    c.execute('''
        CREATE TABLE IF NOT EXISTS services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            service_type TEXT,
            service_name TEXT,
            status TEXT DEFAULT 'active',
            start_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            end_date TIMESTAMP,
            renewal_date TIMESTAMP,
            monthly_fee DECIMAL(10,2),
            documents TEXT DEFAULT '[]',
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Messages table
    c.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER,
            receiver_id INTEGER,
            subject TEXT,
            message TEXT,
            read BOOLEAN DEFAULT 0,
            sent_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            attachments TEXT DEFAULT '[]',
            FOREIGN KEY (sender_id) REFERENCES users (id),
            FOREIGN KEY (receiver_id) REFERENCES users (id)
        )
    ''')
    
    # Create admin user if not exists
    admin_password = bcrypt.generate_password_hash('Admin@123').decode('utf-8')
    try:
        c.execute('''
            INSERT OR IGNORE INTO users 
            (username, email, password, full_name, company, role) 
            VALUES (?, ?, ?, ?, ?, ?)
        ''', ('admin', 'admin@greencpapartners.com', admin_password, 'System Administrator', 'Pacific Green Partners', 'admin'))
    except:
        pass
    
    conn.commit()
    conn.close()

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, email, full_name, company, phone, ein, business_type, tax_year_end, role):
        self.id = id
        self.username = username
        self.email = email
        self.full_name = full_name
        self.company = company
        self.phone = phone
        self.ein = ein
        self.business_type = business_type
        self.tax_year_end = tax_year_end
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user_data = c.fetchone()
    conn.close()
    
    if user_data:
        return User(
            id=user_data[0],
            username=user_data[1],
            email=user_data[2],
            full_name=user_data[4],
            company=user_data[5],
            phone=user_data[6],
            ein=user_data[7],
            business_type=user_data[8],
            tax_year_end=user_data[9],
            role=user_data[10]
        )
    return None

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def send_email(to_email, subject, body, is_html=True):
    """Send email using SMTP"""
    try:
        msg = MIMEMultipart()
        msg['From'] = f"Pacific Green Partners, LLP <{EMAIL_USER}>"
        msg['To'] = to_email
        msg['Subject'] = subject
        
        if is_html:
            msg.attach(MIMEText(body, 'html'))
        else:
            msg.attach(MIMEText(body, 'plain'))
        
        with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as server:
            server.starttls()
            server.login(EMAIL_USER, EMAIL_PASS)
            server.send_message(msg)
        
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

def update_last_login(user_id):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()

def get_user_dashboard_data(user_id):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    # Get tax filings
    c.execute('SELECT COUNT(*) FROM tax_filings WHERE user_id = ? AND status = "pending"', (user_id,))
    pending_tax = c.fetchone()[0]
    
    c.execute('SELECT COUNT(*) FROM tax_filings WHERE user_id = ? AND status = "submitted"', (user_id,))
    submitted_tax = c.fetchone()[0]
    
    # Get audits
    c.execute('SELECT COUNT(*) FROM audits WHERE user_id = ? AND status IN ("scheduled", "in_progress")', (user_id,))
    active_audits = c.fetchone()[0]
    
    # Get documents
    c.execute('SELECT COUNT(*) FROM documents WHERE user_id = ?', (user_id,))
    total_docs = c.fetchone()[0]
    
    # Get upcoming deadlines
    today = datetime.now().date()
    next_month = today + timedelta(days=30)
    c.execute('SELECT COUNT(*) FROM tax_filings WHERE user_id = ? AND due_date BETWEEN ? AND ?', 
             (user_id, today, next_month))
    upcoming_deadlines = c.fetchone()[0]
    
    conn.close()
    
    return {
        'pending_tax': pending_tax,
        'submitted_tax': submitted_tax,
        'active_audits': active_audits,
        'total_docs': total_docs,
        'upcoming_deadlines': upcoming_deadlines
    }

# Routes
@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('portal'))
    return redirect(url_for('index'))

@app.route('/index', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        phone = request.form.get('phone', '').strip()
        service = request.form.get('service', '').strip()
        message = request.form.get('message', '').strip()
        honeypot = request.form.get('honeypot', '')
        
        if honeypot:
            return "Spam detected", 400
        
        errors = []
        if len(name) < 2:
            errors.append("Name must be at least 2 characters.")
        if '@' not in email or '.' not in email:
            errors.append("Valid email is required.")
        if not service:
            errors.append("Please select a service.")
        if len(message) < 10:
            errors.append("Message must be at least 10 characters.")
        
        if errors:
            flash('Please correct the errors below.', 'danger')
            return render_template('index.html', 
                                 name=name, email=email, phone=phone,
                                 service=service, message=message,
                                 errors=errors)
        
        # Email to admin
        admin_subject = f"New Contact Form: {service}"
        admin_body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <div style="background: #0d6efd; color: white; padding: 20px; text-align: center;">
                    <h2>New Contact Form Submission</h2>
                </div>
                <div style="background: #f8f9fa; padding: 20px; border: 1px solid #ddd;">
                    <p><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                    <p><strong>Name:</strong> {name}</p>
                    <p><strong>Email:</strong> {email}</p>
                    <p><strong>Phone:</strong> {phone if phone else 'Not provided'}</p>
                    <p><strong>Service:</strong> {service}</p>
                    <p><strong>Message:</strong></p>
                    <div style="padding: 10px; background: white; border: 1px solid #eee;">
                        {message.replace('\n', '<br>')}
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Email to client
        client_subject = "Thank you for contacting Pacific Green Partners, LLP"
        client_body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <div style="background: #0d6efd; color: white; padding: 20px; text-align: center;">
                    <h2>Thank You for Contacting Us!</h2>
                </div>
                <div style="background: #f8f9fa; padding: 20px; border: 1px solid #ddd;">
                    <p>Dear {name},</p>
                    <p>Thank you for contacting <strong>Pacific Green Partners, LLP</strong>. We have received your inquiry regarding <strong>{service}</strong> and will respond within 24 hours during business hours.</p>
                    <p>If you need immediate assistance, please call us at <strong>(213) 555-0123</strong>.</p>
                    <p>Best regards,<br>The Pacific Green Partners Team</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        admin_sent = send_email(ADMIN_EMAIL, admin_subject, admin_body)
        client_sent = send_email(email, client_subject, client_body)
        
        if admin_sent:
            flash('Thank you! Your message has been sent. We will contact you soon.', 'success')
            return redirect(url_for('index'))
        else:
            flash('Sorry, there was an error sending your message. Please try again later.', 'danger')
            return redirect(url_for('index'))
    
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('portal'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        if not username or not password:
            flash('Please enter both username and password', 'danger')
            return render_template('login.html')
        
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        
        # Search by username OR email
        c.execute('SELECT * FROM users WHERE username = ? OR email = ?', (username, username))
        user = c.fetchone()
        conn.close()
        
        if user and bcrypt.check_password_hash(user[3], password):
            if not user[12]:  # is_active field
                flash('Account is deactivated. Please contact support.', 'danger')
                return render_template('login.html')
            
            user_obj = User(
                id=user[0],
                username=user[1],
                email=user[2],
                full_name=user[4],
                company=user[5],
                phone=user[6],
                ein=user[7],
                business_type=user[8],
                tax_year_end=user[9],
                role=user[10]
            )
            login_user(user_obj)
            update_last_login(user[0])
            flash('Login successful!', 'success')
            
            # Redirect based on role
            if user[10] == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('portal'))
        else:
            flash('Invalid username/email or password', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('portal'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        full_name = request.form.get('full_name')
        company = request.form.get('company')
        phone = request.form.get('phone')
        ein = request.form.get('ein', '')
        business_type = request.form.get('business_type', '')
        tax_year_end = request.form.get('tax_year_end', '')
        
        errors = []
        
        # Validation
        if not username or len(username) < 3:
            errors.append("Username must be at least 3 characters long.")
        if not password or len(password) < 6:
            errors.append("Password must be at least 6 characters long.")
        if password != confirm_password:
            errors.append("Passwords do not match.")
        if not email or '@' not in email or '.' not in email:
            errors.append("Valid email is required.")
        if not full_name or len(full_name) < 2:
            errors.append("Full name is required.")
        
        if errors:
            for error in errors:
                flash(error, 'danger')
            return render_template('register.html', 
                                 username=username, email=email, 
                                 full_name=full_name, company=company, 
                                 phone=phone, ein=ein, 
                                 business_type=business_type, tax_year_end=tax_year_end)
        
        try:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            
            # Check if username or email already exists
            c.execute('SELECT id FROM users WHERE username = ? OR email = ?', (username, email))
            existing_user = c.fetchone()
            
            if existing_user:
                flash('Username or email already exists.', 'danger')
                return render_template('register.html', 
                                     username=username, email=email, 
                                     full_name=full_name, company=company, 
                                     phone=phone, ein=ein, 
                                     business_type=business_type, tax_year_end=tax_year_end)
            
            # Insert user with proper handling of optional fields
            c.execute('''INSERT INTO users 
                       (username, email, password, full_name, company, phone, ein, business_type, tax_year_end) 
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                     (username, email, hashed_password, full_name, company or '', phone or '', 
                      ein or '', business_type or '', tax_year_end or ''))
            
            # Get the user ID
            user_id = c.lastrowid
            
            # Create user profile with default JSON
            default_preferences = json.dumps({"theme": "light", "notifications": True})
            c.execute('INSERT INTO user_profiles (user_id, preferences) VALUES (?, ?)', 
                     (user_id, default_preferences))
            
            conn.commit()
            conn.close()
            
            # Send welcome email
            try:
                welcome_subject = "Welcome to Pacific Green Partners Client Portal"
                welcome_body = f"""
                <html>
                <body style="font-family: Arial, sans-serif; line-height: 1.6;">
                    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                        <div style="background: #2e7d32; color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0;">
                            <h2>Welcome to Pacific Green Partners!</h2>
                        </div>
                        <div style="background: #f8f9fa; padding: 20px; border: 1px solid #ddd; border-radius: 0 0 10px 10px;">
                            <p>Dear {full_name},</p>
                            <p>Thank you for registering for our client portal. You can now:</p>
                            <ul>
                                <li>Access your financial documents securely</li>
                                <li>Track your tax status and deadlines</li>
                                <li>Monitor ESG metrics and sustainability reports</li>
                                <li>Communicate directly with your CPA team</li>
                            </ul>
                            <p>Login to get started: <a href="{request.host_url}login">Client Portal Login</a></p>
                            <p>If you have any questions, please contact our support team.</p>
                            <p>Best regards,<br>The Pacific Green Partners Team</p>
                        </div>
                    </div>
                </body>
                </html>
                """
                
                send_email(email, welcome_subject, welcome_body)
            except Exception as e:
                print(f"Email sending failed: {e}")
                # Don't fail registration if email fails
            
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))
            
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            flash('Registration failed. Please try again.', 'danger')
            return render_template('register.html', 
                                 username=username, email=email, 
                                 full_name=full_name, company=company, 
                                 phone=phone, ein=ein, 
                                 business_type=business_type, tax_year_end=tax_year_end)
        except Exception as e:
            print(f"Unexpected error: {e}")
            flash('An unexpected error occurred. Please try again.', 'danger')
            return render_template('register.html', 
                                 username=username, email=email, 
                                 full_name=full_name, company=company, 
                                 phone=phone, ein=ein, 
                                 business_type=business_type, tax_year_end=tax_year_end)
    
    # GET request - show empty form
    return render_template('register.html')

@app.route('/portal')
@login_required
def portal():
    dashboard_data = get_user_dashboard_data(current_user.id)
    
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    # Get user documents
    c.execute('SELECT * FROM documents WHERE user_id = ? ORDER BY upload_date DESC LIMIT 10', (current_user.id,))
    documents = c.fetchall()
    
    # Get user profile
    c.execute('SELECT * FROM user_profiles WHERE user_id = ?', (current_user.id,))
    profile = c.fetchone()
    
    # Get recent tax filings
    c.execute('SELECT * FROM tax_filings WHERE user_id = ? ORDER BY due_date DESC LIMIT 5', (current_user.id,))
    tax_filings = c.fetchall()
    
    # Get upcoming audits
    c.execute('SELECT * FROM audits WHERE user_id = ? AND status IN ("scheduled", "in_progress") ORDER BY scheduled_date LIMIT 5', (current_user.id,))
    audits = c.fetchall()
    
    # Get recent messages
    c.execute('''SELECT m.*, u.full_name as sender_name 
                FROM messages m 
                JOIN users u ON m.sender_id = u.id 
                WHERE m.receiver_id = ? 
                ORDER BY m.sent_date DESC LIMIT 5''', (current_user.id,))
    messages = c.fetchall()
    
    conn.close()
    
    # Format data for template
    doc_list = []
    for doc in documents:
        doc_list.append({
            'id': doc[0],
            'filename': doc[2],
            'category': doc[3],
            'upload_date': doc[4],
            'size': doc[5],
            'status': doc[6]
        })
    
    tax_list = []
    for tax in tax_filings:
        tax_list.append({
            'id': tax[0],
            'tax_year': tax[2],
            'form_type': tax[3],
            'status': tax[4],
            'due_date': tax[6],
            'amount_due': tax[7]
        })
    
    audit_list = []
    for audit in audits:
        audit_list.append({
            'id': audit[0],
            'audit_type': audit[2],
            'audit_year': audit[3],
            'status': audit[4],
            'scheduled_date': audit[5]
        })
    
    message_list = []
    for msg in messages:
        message_list.append({
            'id': msg[0],
            'subject': msg[3],
            'message': msg[4],
            'read': msg[5],
            'sent_date': msg[6],
            'sender_name': msg[9]
        })
    
    return render_template('portal.html', 
                         user=current_user,
                         dashboard_data=dashboard_data,
                         documents=doc_list,
                         tax_filings=tax_list,
                         audits=audit_list,
                         messages=message_list,
                         profile=profile)

# Automated Tax Filing Routes
@app.route('/tax/auto-file', methods=['POST'])
@login_required
def auto_file_tax():
    """Automated tax filing endpoint"""
    data = request.json
    tax_year = data.get('tax_year', datetime.now().year - 1)
    form_type = data.get('form_type', '1040')
    
    # In production, this would integrate with actual tax filing APIs
    # For now, we'll simulate the process
    
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    # Calculate tax (simplified)
    c.execute('SELECT tax_data FROM user_profiles WHERE user_id = ?', (current_user.id,))
    tax_data = json.loads(c.fetchone()[0])
    
    # Simplified tax calculation
    income = tax_data.get('income', 0)
    deductions = tax_data.get('deductions', 0)
    credits = tax_data.get('credits', 0)
    
    taxable_income = max(0, income - deductions)
    
    # Simple tax brackets (example)
    if taxable_income <= 10000:
        tax = taxable_income * 0.10
    elif taxable_income <= 40000:
        tax = 1000 + (taxable_income - 10000) * 0.12
    elif taxable_income <= 85000:
        tax = 4600 + (taxable_income - 40000) * 0.22
    else:
        tax = 14500 + (taxable_income - 85000) * 0.24
    
    tax = max(0, tax - credits)
    
    # Create tax filing record
    due_date = datetime.now() + timedelta(days=90)
    c.execute('''INSERT INTO tax_filings 
                (user_id, tax_year, filing_type, form_type, status, due_date, amount_due) 
                VALUES (?, ?, ?, ?, ?, ?, ?)''',
             (current_user.id, tax_year, 'electronic', form_type, 'prepared', due_date, tax))
    
    filing_id = c.lastrowid
    
    conn.commit()
    conn.close()
    
    # Send notification email
    subject = f"Tax Filing Prepared - {form_type} for {tax_year}"
    body = f"""
    <html>
    <body>
        <h2>Tax Filing Prepared</h2>
        <p>Dear {current_user.full_name},</p>
        <p>Your {form_type} tax filing for {tax_year} has been prepared.</p>
        <p><strong>Estimated Tax Due:</strong> ${tax:,.2f}</p>
        <p><strong>Due Date:</strong> {due_date.strftime('%Y-%m-%d')}</p>
        <p>Please review and approve the filing in your client portal.</p>
    </body>
    </html>
    """
    
    send_email(current_user.email, subject, body)
    
    return jsonify({
        'success': True,
        'message': 'Tax filing prepared successfully',
        'filing_id': filing_id,
        'estimated_tax': tax,
        'due_date': due_date.strftime('%Y-%m-%d')
    })

@app.route('/tax/submit/<int:filing_id>', methods=['POST'])
@login_required
def submit_tax_filing(filing_id):
    """Submit tax filing to IRS (simulated)"""
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    c.execute('UPDATE tax_filings SET status = "submitted", submitted_date = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?',
             (filing_id, current_user.id))
    
    conn.commit()
    conn.close()
    
    # In production, this would actually submit to IRS API
    # For demo, we'll simulate submission
    
    flash('Tax filing submitted successfully!', 'success')
    return redirect(url_for('portal'))

# Audit Services Routes
@app.route('/audit/schedule', methods=['POST'])
@login_required
def schedule_audit():
    """Schedule an audit"""
    data = request.form
    audit_type = data.get('audit_type')
    audit_year = data.get('audit_year')
    scheduled_date = data.get('scheduled_date')
    
    if not all([audit_type, audit_year, scheduled_date]):
        flash('Please fill all required fields', 'danger')
        return redirect(url_for('portal'))
    
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    c.execute('''INSERT INTO audits 
                (user_id, audit_type, audit_year, status, scheduled_date, auditor_assigned) 
                VALUES (?, ?, ?, ?, ?, ?)''',
             (current_user.id, audit_type, audit_year, 'scheduled', scheduled_date, 'To be assigned'))
    
    conn.commit()
    conn.close()
    
    # Send confirmation email
    subject = f"Audit Scheduled - {audit_type} for {audit_year}"
    body = f"""
    <html>
    <body>
        <h2>Audit Scheduled</h2>
        <p>Dear {current_user.full_name},</p>
        <p>Your {audit_type} audit for {audit_year} has been scheduled.</p>
        <p><strong>Scheduled Date:</strong> {scheduled_date}</p>
        <p>Our audit team will contact you soon with further details.</p>
    </body>
    </html>
    """
    
    send_email(current_user.email, subject, body)
    
    flash('Audit scheduled successfully!', 'success')
    return redirect(url_for('portal'))

# Document Upload with OCR Processing
@app.route('/api/upload_document', methods=['POST'])
@login_required
def upload_document():
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file selected'})
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No file selected'})
    
    if not allowed_file(file.filename):
        return jsonify({'success': False, 'message': 'File type not allowed'})
    
    category = request.form.get('category', 'other')
    
    # Save file
    filename = secure_filename(f"{current_user.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{file.filename}")
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    file.save(file_path)
    
    # Process document based on type
    file_ext = filename.rsplit('.', 1)[1].lower()
    
    if file_ext in ['pdf', 'jpg', 'png']:
        # In production, add OCR processing here
        # For now, we'll just record the upload
        pass
    
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('INSERT INTO documents (user_id, filename, category, file_size, file_path) VALUES (?, ?, ?, ?, ?)',
             (current_user.id, file.filename, category, os.path.getsize(file_path), file_path))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'File uploaded successfully', 'filename': file.filename})

# Admin Dashboard
@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('portal'))
    
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    # Get stats
    c.execute('SELECT COUNT(*) FROM users WHERE role = "client"')
    total_clients = c.fetchone()[0]
    
    c.execute('SELECT COUNT(*) FROM tax_filings WHERE status = "pending"')
    pending_tax = c.fetchone()[0]
    
    c.execute('SELECT COUNT(*) FROM audits WHERE status IN ("scheduled", "in_progress")')
    active_audits = c.fetchone()[0]
    
    c.execute('SELECT COUNT(*) FROM messages WHERE read = 0')
    unread_messages = c.fetchone()[0]
    
    # Get recent activities
    c.execute('''SELECT u.full_name, tf.tax_year, tf.form_type, tf.status 
                FROM tax_filings tf 
                JOIN users u ON tf.user_id = u.id 
                ORDER BY tf.submitted_date DESC LIMIT 10''')
    recent_filings = c.fetchall()
    
    conn.close()
    
    return render_template('admin_dashboard.html',
                         total_clients=total_clients,
                         pending_tax=pending_tax,
                         active_audits=active_audits,
                         unread_messages=unread_messages,
                         recent_filings=recent_filings)

# API Endpoints
@app.route('/api/user_data')
@login_required
def get_user_data():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    c.execute('''SELECT u.*, up.tax_status, up.audit_status 
                FROM users u 
                LEFT JOIN user_profiles up ON u.id = up.user_id 
                WHERE u.id = ?''', (current_user.id,))
    user_data = c.fetchone()
    
    conn.close()
    
    if user_data:
        data = {
            'full_name': user_data[4],
            'company': user_data[5],
            'email': user_data[2],
            'phone': user_data[6],
            'ein': user_data[7],
            'business_type': user_data[8],
            'tax_status': user_data[13],
            'audit_status': user_data[14]
        }
        return jsonify(data)
    
    return jsonify({'error': 'User not found'}), 404

@app.route('/api/tax_calculator', methods=['POST'])
@login_required
def tax_calculator():
    data = request.json
    income = float(data.get('income', 0))
    deductions = float(data.get('deductions', 0))
    credits = float(data.get('credits', 0))
    
    # Simple tax calculation
    taxable_income = max(0, income - deductions)
    
    # 2024 tax brackets (single filer)
    if taxable_income <= 11600:
        tax = taxable_income * 0.10
    elif taxable_income <= 47150:
        tax = 1160 + (taxable_income - 11600) * 0.12
    elif taxable_income <= 100525:
        tax = 5426 + (taxable_income - 47150) * 0.22
    elif taxable_income <= 191950:
        tax = 17169 + (taxable_income - 100525) * 0.24
    elif taxable_income <= 243725:
        tax = 39110 + (taxable_income - 191950) * 0.32
    elif taxable_income <= 609350:
        tax = 55678 + (taxable_income - 243725) * 0.35
    else:
        tax = 183647 + (taxable_income - 609350) * 0.37
    
    effective_rate = (tax / income * 100) if income > 0 else 0
    tax_after_credits = max(0, tax - credits)
    
    return jsonify({
        'taxable_income': taxable_income,
        'tax_before_credits': tax,
        'tax_after_credits': tax_after_credits,
        'effective_rate': round(effective_rate, 2),
        'savings_from_credits': credits
    })

# Services Management
@app.route('/services', methods=['GET', 'POST'])
@login_required
def manage_services():
    if request.method == 'POST':
        service_type = request.form.get('service_type')
        service_name = request.form.get('service_name')
        monthly_fee = request.form.get('monthly_fee')
        
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        
        c.execute('''INSERT INTO services 
                    (user_id, service_type, service_name, monthly_fee) 
                    VALUES (?, ?, ?, ?)''',
                 (current_user.id, service_type, service_name, monthly_fee))
        
        conn.commit()
        conn.close()
        
        flash('Service added successfully!', 'success')
        return redirect(url_for('portal'))
    
    # GET request - show services
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    c.execute('SELECT * FROM services WHERE user_id = ?', (current_user.id,))
    services = c.fetchall()
    
    conn.close()
    
    service_list = []
    for service in services:
        service_list.append({
            'id': service[0],
            'service_type': service[2],
            'service_name': service[3],
            'status': service[4],
            'monthly_fee': service[8]
        })
    
    return render_template('services.html', services=service_list)

# ESG Reporting
@app.route('/esg/report', methods=['GET'])
@login_required
def generate_esg_report():
    """Generate ESG report"""
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    c.execute('SELECT esg_data FROM user_profiles WHERE user_id = ?', (current_user.id,))
    esg_data = json.loads(c.fetchone()[0])
    
    # Calculate ESG score
    environmental_score = esg_data.get('environmental_score', 75)
    social_score = esg_data.get('social_score', 80)
    governance_score = esg_data.get('governance_score', 85)
    
    overall_score = (environmental_score + social_score + governance_score) / 3
    
    report = {
        'company': current_user.company,
        'report_date': datetime.now().strftime('%Y-%m-%d'),
        'environmental_score': environmental_score,
        'social_score': social_score,
        'governance_score': governance_score,
        'overall_score': round(overall_score, 1),
        'carbon_footprint': esg_data.get('carbon_footprint', '245 tCO2e'),
        'energy_consumption': esg_data.get('energy_consumption', '150,000 kWh'),
        'waste_reduction': esg_data.get('waste_reduction', '35%'),
        'employee_satisfaction': esg_data.get('employee_satisfaction', '4.2/5'),
        'community_investment': esg_data.get('community_investment', '$25,000')
    }
    
    conn.close()
    
    return jsonify(report)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)