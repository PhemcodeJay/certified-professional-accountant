# app.py - Updated version with user authentication
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
from dotenv import load_dotenv
from datetime import datetime
import sqlite3
import json

load_dotenv()  # Load environment variables from .env file

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your-secret-key-here')

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
            role TEXT DEFAULT 'client',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    ''')
    
    # User profiles table
    c.execute('''
        CREATE TABLE IF NOT EXISTS user_profiles (
            user_id INTEGER PRIMARY KEY,
            tax_data TEXT,
            esg_data TEXT,
            preferences TEXT,
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
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    conn.commit()
    conn.close()

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, email, full_name, company, phone, role):
        self.id = id
        self.username = username
        self.email = email
        self.full_name = full_name
        self.company = company
        self.phone = phone
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
            full_name=user_data[3],
            company=user_data[4],
            phone=user_data[5],
            role=user_data[6]
        )
    return None

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
        username = request.form.get('username')
        password = request.form.get('password')
        
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username = ? OR email = ?', (username, username))
        user = c.fetchone()
        conn.close()
        
        if user and bcrypt.check_password_hash(user[3], password):
            user_obj = User(
                id=user[0],
                username=user[1],
                email=user[2],
                full_name=user[4],
                company=user[5],
                phone=user[6],
                role=user[7]
            )
            login_user(user_obj)
            update_last_login(user[0])
            flash('Login successful!', 'success')
            return redirect(url_for('portal'))
        else:
            flash('Invalid username or password', 'danger')
    
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
        
        errors = []
        
        if len(username) < 3:
            errors.append("Username must be at least 3 characters long.")
        if len(password) < 6:
            errors.append("Password must be at least 6 characters long.")
        if password != confirm_password:
            errors.append("Passwords do not match.")
        if '@' not in email or '.' not in email:
            errors.append("Valid email is required.")
        
        if errors:
            for error in errors:
                flash(error, 'danger')
            return render_template('register.html', 
                                 username=username, email=email, 
                                 full_name=full_name, company=company, phone=phone)
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        try:
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            c.execute('INSERT INTO users (username, email, password, full_name, company, phone) VALUES (?, ?, ?, ?, ?, ?)',
                     (username, email, hashed_password, full_name, company, phone))
            
            # Create user profile
            user_id = c.lastrowid
            c.execute('INSERT INTO user_profiles (user_id, preferences) VALUES (?, ?)',
                     (user_id, json.dumps({"theme": "light", "notifications": True})))
            
            conn.commit()
            conn.close()
            
            # Send welcome email
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
                        <p>Login to get started: <a href="{request.host_url}portal">Client Portal</a></p>
                        <p>If you have any questions, please contact our support team.</p>
                        <p>Best regards,<br>The Pacific Green Partners Team</p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            send_email(email, welcome_subject, welcome_body)
            flash('Registration successful! Please check your email for welcome message.', 'success')
            return redirect(url_for('login'))
            
        except sqlite3.IntegrityError:
            flash('Username or email already exists.', 'danger')
            return render_template('register.html', 
                                 username=username, email=email, 
                                 full_name=full_name, company=company, phone=phone)
    
    return render_template('register.html')

@app.route('/portal')
@login_required
def portal():
    # Get user data for the portal
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    # Get user documents
    c.execute('SELECT * FROM documents WHERE user_id = ? ORDER BY upload_date DESC LIMIT 10', (current_user.id,))
    documents = c.fetchall()
    
    # Get user profile
    c.execute('SELECT * FROM user_profiles WHERE user_id = ?', (current_user.id,))
    profile = c.fetchone()
    
    conn.close()
    
    # Format documents for template
    doc_list = []
    for doc in documents:
        doc_list.append({
            'id': doc[0],
            'filename': doc[2],
            'category': doc[3],
            'upload_date': doc[4],
            'size': doc[5]
        })
    
    return render_template('portal.html', 
                         user=current_user,
                         documents=doc_list,
                         profile=profile)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# API endpoints for portal
@app.route('/api/upload_document', methods=['POST'])
@login_required
def upload_document():
    if 'file' not in request.files:
        return json.dumps({'success': False, 'message': 'No file selected'})
    
    file = request.files['file']
    if file.filename == '':
        return json.dumps({'success': False, 'message': 'No file selected'})
    
    category = request.form.get('category', 'other')
    
    # Save file (in production, use secure storage like AWS S3)
    filename = f"{current_user.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{file.filename}"
    file_path = os.path.join('uploads', filename)
    os.makedirs('uploads', exist_ok=True)
    file.save(file_path)
    
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('INSERT INTO documents (user_id, filename, category, file_size, file_path) VALUES (?, ?, ?, ?, ?)',
             (current_user.id, file.filename, category, os.path.getsize(file_path), file_path))
    conn.commit()
    conn.close()
    
    return json.dumps({'success': True, 'message': 'File uploaded successfully'})

@app.route('/api/user_data')
@login_required
def get_user_data():
    # Return user-specific data for dashboard
    user_data = {
        'full_name': current_user.full_name,
        'company': current_user.company,
        'email': current_user.email,
        'phone': current_user.phone
    }
    return json.dumps(user_data)

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)