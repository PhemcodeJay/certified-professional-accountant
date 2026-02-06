# app.py - Enhanced for real-life CPA tax services and audits in USA
import logging
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, DateField, FloatField, TextAreaField
from wtforms.validators import DataRequired, Email, Length, Optional, Regexp
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
from dotenv import load_dotenv
from datetime import datetime, timedelta
import sqlite3  # For dev; use psycopg2 for PostgreSQL in prod
import json
import secrets
from werkzeug.utils import secure_filename
import pandas as pd

# Logging setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

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

# Database initialization (SQLite for dev; switch to PostgreSQL for prod)
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS users (
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
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS user_profiles (
        user_id INTEGER PRIMARY KEY,
        tax_data TEXT DEFAULT '{}',
        esg_data TEXT DEFAULT '{}',
        preferences TEXT DEFAULT '{"theme": "light", "notifications": true}',
        tax_status TEXT DEFAULT 'pending',
        audit_status TEXT DEFAULT 'not_scheduled',
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS documents (
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
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS tax_filings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        tax_year INTEGER,
        filing_type TEXT,  -- 'personal' or 'business'
        form_type TEXT,  -- e.g., '1040', '1120'
        status TEXT DEFAULT 'draft',
        submitted_date TIMESTAMP,
        due_date TIMESTAMP,
        amount_due DECIMAL(10,2),
        amount_paid DECIMAL(10,2),
        documents TEXT DEFAULT '[]',
        notes TEXT,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS audits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        audit_type TEXT,  -- e.g., 'IRS', 'financial'
        audit_year INTEGER,
        audit_scope TEXT,  -- 'personal' or 'business'
        status TEXT DEFAULT 'scheduled',
        scheduled_date TIMESTAMP,
        completion_date TIMESTAMP,
        auditor_assigned TEXT,
        findings TEXT DEFAULT '[]',
        recommendations TEXT DEFAULT '[]',
        documents TEXT DEFAULT '[]',
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS services (
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
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS messages (
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
    )''')
    
    # Create admin user
    admin_password = bcrypt.generate_password_hash('Admin@123').decode('utf-8')
    c.execute('''INSERT OR IGNORE INTO users 
        (username, email, password, full_name, company, role, is_active) 
        VALUES (?, ?, ?, ?, ?, ?, ?)''', ('admin', 'admin@greencpapartners.com', admin_password, 'System Administrator', 'Pacific Green Partners', 'admin', 1))
    c.execute('UPDATE users SET is_active = 1 WHERE username = "admin"')
    
    # Create sample user
    sample_password = bcrypt.generate_password_hash('Test@123').decode('utf-8')
    c.execute('''INSERT OR IGNORE INTO users 
        (username, email, password, full_name, company, phone, ein, business_type, tax_year_end, role, is_active) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', ('sampleuser', 'sample@greencpapartners.com', sample_password, 'John Doe', 'Sample Corporation', '555-123-4567', '12-3456789', 'LLC', '2023-12-31', 'client', 1))
    
    c.execute('SELECT id FROM users WHERE username = "sampleuser"')
    sample_user_id = c.fetchone()[0]
    
    sample_tax_data = json.dumps({
        'income': 85000,
        'deductions': 15000,
        'credits': 2500,
        'filing_status': 'single'
    })
    sample_esg_data = json.dumps({
        'environmental_score': 88,
        'social_score': 92,
        'governance_score': 85,
        'carbon_footprint': '245 tCO2e',
        'energy_consumption': '150,000 kWh',
        'waste_reduction': '35%',
        'employee_satisfaction': '4.2/5',
        'community_investment': '$25,000',
        'diversity_index': 78,
        'sustainability_goals': ['Net Zero by 2030']
    })
    c.execute('''INSERT OR IGNORE INTO user_profiles 
        (user_id, tax_data, esg_data) 
        VALUES (?, ?, ?)''', (sample_user_id, sample_tax_data, sample_esg_data))
    
    conn.commit()
    conn.close()

# User class
class User(UserMixin):
    def __init__(self, id, username, email, role):
        self.id = id
        self.username = username
        self.email = email
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT id, username, email, role FROM users WHERE id = ?', (user_id,))
    user_data = c.fetchone()
    conn.close()
    if user_data:
        return User(*user_data)
    return None

# Forms
class LoginForm(FlaskForm):
    username = StringField('Username or Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=50)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    full_name = StringField('Full Name', validators=[DataRequired()])
    company = StringField('Company Name', validators=[Optional()])
    phone = StringField('Phone', validators=[Optional()])
    ein = StringField('EIN / Tax ID', validators=[Optional(), Regexp(r'^\d{2}-\d{7}$', message='Invalid EIN format (XX-XXXXXXX)')])
    business_type = SelectField('Business Type', choices=[('', 'Select'), ('sole_proprietor', 'Sole Proprietor'), ('llc', 'LLC'), ('corporation', 'Corporation'), ('partnership', 'Partnership'), ('nonprofit', 'Nonprofit'), ('other', 'Other')])
    tax_year_end = DateField('Tax Year End', validators=[Optional()])
    submit = SubmitField('Register')

class TaxFilingForm(FlaskForm):
    tax_year = StringField('Tax Year', validators=[DataRequired(), Regexp(r'^\d{4}$', message='Invalid year')])
    filing_type = SelectField('Filing Type', choices=[('personal', 'Personal'), ('business', 'Business')], validators=[DataRequired()])
    form_type = StringField('Form Type (e.g., 1040, 1120)', validators=[DataRequired()])
    amount_due = FloatField('Amount Due', validators=[Optional()])
    notes = TextAreaField('Notes')
    submit = SubmitField('Save Draft')

class AuditForm(FlaskForm):
    audit_year = StringField('Audit Year', validators=[DataRequired(), Regexp(r'^\d{4}$', message='Invalid year')])
    audit_type = StringField('Audit Type (e.g., IRS, Financial)', validators=[DataRequired()])
    audit_scope = SelectField('Scope', choices=[('personal', 'Personal'), ('business', 'Business')], validators=[DataRequired()])
    scheduled_date = DateField('Scheduled Date', validators=[DataRequired()])
    notes = TextAreaField('Notes')
    submit = SubmitField('Schedule Audit')

# Helper functions
def send_email(to, subject, body):
    msg = MIMEMultipart()
    msg['From'] = EMAIL_USER
    msg['To'] = to
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))
    
    try:
        server = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT)
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASS)
        server.send_message(msg)
        server.quit()
        logging.info(f'Email sent to {to}')
        return True
    except Exception as e:
        logging.error(f"Email error: {e}")
        return False

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE (username = ? OR email = ?) AND is_active = 1', (form.username.data, form.username.data))
        user = c.fetchone()
        if user and bcrypt.check_password_hash(user[3], form.password.data):
            user_obj = User(user[0], user[1], user[2], user[10])
            login_user(user_obj)
            c.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', (user[0],))
            conn.commit()
            flash('Login successful!', 'success')
            if user_obj.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('portal'))
        flash('Invalid credentials or inactive account', 'danger')
        conn.close()
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username = ? OR email = ?', (form.username.data, form.email.data))
        if c.fetchone():
            flash('Username or email already exists', 'danger')
            conn.close()
            return render_template('register.html', form=form)
        
        hashed_pw = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        tax_year_end_str = form.tax_year_end.data.strftime('%Y-%m-%d') if form.tax_year_end.data else None
        try:
            c.execute('''INSERT INTO users 
                (username, email, password, full_name, company, phone, ein, business_type, tax_year_end) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''', (form.username.data, form.email.data, hashed_pw, form.full_name.data, 
                form.company.data, form.phone.data, form.ein.data, form.business_type.data, tax_year_end_str))
            user_id = c.lastrowid
            c.execute('INSERT INTO user_profiles (user_id) VALUES (?)', (user_id,))
            conn.commit()
            welcome_body = f"Welcome {form.full_name.data}! Your account is ready. Disclaimer: All tax/audit tools are estimates; consult a professional for official filings."
            send_email(form.email.data, 'Welcome to Pacific Green Partners', welcome_body)
            flash('Registration successful! Check your email.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            conn.rollback()
            flash(f'Registration error: {str(e)}', 'danger')
        conn.close()
    return render_template('register.html', form=form)

@app.route('/portal')
@login_required
def portal():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT * FROM user_profiles WHERE user_id = ?', (current_user.id,))
    profile = c.fetchone()
    tax_status = profile[4] if profile else 'pending'
    audit_status = profile[5] if profile else 'not_scheduled'
    conn.close()
    return render_template('portal.html', tax_status=tax_status, audit_status=audit_status, disclaimer="Note: Tax and audit tools are for estimation only. Not official IRS filings.")

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file part'})
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No selected file'})
    if file and '.' in file.filename and file.filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']:
        category = request.form.get('category', 'other')
        filename = secure_filename(f"{current_user.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{file.filename}")
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        file.save(file_path)
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('INSERT INTO documents (user_id, filename, category, file_size, file_path) VALUES (?, ?, ?, ?, ?)',
                  (current_user.id, file.filename, category, os.path.getsize(file_path), file_path))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': 'File uploaded successfully', 'filename': file.filename})
    return jsonify({'success': False, 'message': 'File type not allowed'})

@app.route('/file_tax', methods=['GET', 'POST'])
@login_required
def file_tax():
    form = TaxFilingForm()
    if form.validate_on_submit():
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        try:
            c.execute('''INSERT INTO tax_filings 
                (user_id, tax_year, filing_type, form_type, amount_due, notes, status) 
                VALUES (?, ?, ?, ?, ?, ?, 'draft')''', (current_user.id, form.tax_year.data, form.filing_type.data, 
                form.form_type.data, form.amount_due.data, form.notes.data))
            conn.commit()
            flash('Tax filing draft saved. Disclaimer: This is not an official IRS submission. Contact your CPA for e-filing.', 'success')
            body = f"New tax draft filed by {current_user.username}. Year: {form.tax_year.data}, Type: {form.filing_type.data}"
            send_email(ADMIN_EMAIL, 'New Tax Draft', body)
        except Exception as e:
            flash(f'Error: {str(e)}', 'danger')
        conn.close()
        return redirect(url_for('portal'))
    return render_template('file_tax.html', form=form)

@app.route('/schedule_audit', methods=['GET', 'POST'])
@login_required
def schedule_audit():
    form = AuditForm()
    if form.validate_on_submit():
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        scheduled_date_str = form.scheduled_date.data.strftime('%Y-%m-%d')
        try:
            c.execute('''INSERT INTO audits 
                (user_id, audit_year, audit_type, audit_scope, scheduled_date, status) 
                VALUES (?, ?, ?, ?, ?, 'scheduled')''', (current_user.id, form.audit_year.data, form.audit_type.data, 
                form.audit_scope.data, scheduled_date_str, ))
            conn.commit()
            flash('Audit scheduled. Your auditor will contact you.', 'success')
            body = f"Audit scheduled by {current_user.username}. Year: {form.audit_year.data}, Type: {form.audit_type.data}"
            send_email(ADMIN_EMAIL, 'New Audit Scheduled', body)
        except Exception as e:
            flash(f'Error: {str(e)}', 'danger')
        conn.close()
        return redirect(url_for('portal'))
    return render_template('schedule_audit.html', form=form)

@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('portal'))
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT COUNT(*) FROM users WHERE role = "client"')
    total_clients = c.fetchone()[0]
    c.execute('SELECT COUNT(*) FROM tax_filings WHERE status = "draft" OR status = "pending"')
    pending_tax = c.fetchone()[0]
    c.execute('SELECT COUNT(*) FROM audits WHERE status IN ("scheduled", "in_progress")')
    active_audits = c.fetchone()[0]
    c.execute('SELECT COUNT(*) FROM messages WHERE read = 0')
    unread_messages = c.fetchone()[0]
    c.execute('''SELECT u.full_name, tf.tax_year, tf.form_type, tf.status 
                FROM tax_filings tf JOIN users u ON tf.user_id = u.id 
                ORDER BY tf.submitted_date DESC LIMIT 10''')
    recent_filings = c.fetchall()
    conn.close()
    return render_template('admin_dashboard.html', total_clients=total_clients, pending_tax=pending_tax, 
                           active_audits=active_audits, unread_messages=unread_messages, recent_filings=recent_filings)

@app.route('/api/user_data')
@login_required
def get_user_data():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''SELECT u.*, up.tax_status, up.audit_status 
                FROM users u LEFT JOIN user_profiles up ON u.id = up.user_id WHERE u.id = ?''', (current_user.id,))
    user_data = c.fetchone()
    conn.close()
    if user_data:
        return jsonify({
            'full_name': user_data[4],
            'company': user_data[5],
            'email': user_data[2],
            'phone': user_data[6],
            'ein': user_data[7],
            'business_type': user_data[8],
            'tax_status': user_data[13],
            'audit_status': user_data[14]
        })
    return jsonify({'error': 'User not found'}), 404

@app.route('/api/tax_calculator', methods=['POST'])
@login_required
def tax_calculator():
    data = request.json
    income = float(data.get('income', 0))
    deductions = float(data.get('deductions', 0))
    credits = float(data.get('credits', 0))
    filing_status = data.get('filing_status', 'single')  # Enhanced with status
    taxable_income = max(0, income - deductions)
    
    # 2024 IRS brackets (simplified; add more for accuracy)
    brackets = {
        'single': [(11600, 0.10), (47150, 0.12), (100525, 0.22), (191950, 0.24), (243725, 0.32), (609350, 0.35), (float('inf'), 0.37)],
        'married_joint': [(23200, 0.10), (94300, 0.12), (201050, 0.22), (383900, 0.24), (487450, 0.32), (731200, 0.35), (float('inf'), 0.37)],
        # Add 'head_of_household', 'married_separate'
    }
    tax = 0
    prev_bracket = 0
    rates = brackets.get(filing_status, brackets['single'])
    for bracket, rate in rates:
        if taxable_income > bracket:
            tax += (bracket - prev_bracket) * rate
            prev_bracket = bracket
        else:
            tax += (taxable_income - prev_bracket) * rate
            break
    effective_rate = (tax / income * 100) if income > 0 else 0
    tax_after_credits = max(0, tax - credits)
    
    return jsonify({
        'disclaimer': 'This is an estimate only. Consult a CPA for official calculations.',
        'taxable_income': taxable_income,
        'tax_before_credits': tax,
        'tax_after_credits': tax_after_credits,
        'effective_rate': round(effective_rate, 2),
        'savings_from_credits': credits
    })

@app.route('/services', methods=['GET', 'POST'])
@login_required
def manage_services():
    if request.method == 'POST':
        service_type = request.form.get('service_type')
        service_name = request.form.get('service_name')
        monthly_fee = request.form.get('monthly_fee')
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('''INSERT INTO services (user_id, service_type, service_name, monthly_fee) VALUES (?, ?, ?, ?)''',
                  (current_user.id, service_type, service_name, monthly_fee))
        conn.commit()
        conn.close()
        flash('Service added. Payment integration pending (use Stripe in prod).', 'success')
        return redirect(url_for('portal'))
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT * FROM services WHERE user_id = ?', (current_user.id,))
    services = c.fetchall()
    conn.close()
    service_list = [{'id': s[0], 'service_type': s[2], 'service_name': s[3], 'status': s[4], 'monthly_fee': s[8]} for s in services]
    return render_template('services.html', services=service_list)

@app.route('/esg/report', methods=['GET'])
@login_required
def generate_esg_report():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT esg_data FROM user_profiles WHERE user_id = ?', (current_user.id,))
    esg_data = json.loads(c.fetchone()[0])
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
        'community_investment': esg_data.get('community_investment', '$25,000'),
        'diversity_index': esg_data.get('diversity_index', 78),
        'sustainability_goals': esg_data.get('sustainability_goals', ['Net Zero by 2030'])
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