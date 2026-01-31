# app.py - Updated version
from flask import Flask, render_template, request, redirect, url_for, flash
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
from dotenv import load_dotenv

load_dotenv()  # Load environment variables from .env file

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your-secret-key-here')

# Email configuration
EMAIL_HOST = os.getenv('EMAIL_HOST', 'smtp.gmail.com')
EMAIL_PORT = int(os.getenv('EMAIL_PORT', 587))
EMAIL_USER = os.getenv('EMAIL_USER', 'your-email@gmail.com')
EMAIL_PASS = os.getenv('EMAIL_PASS', 'your-app-password')
ADMIN_EMAIL = os.getenv('ADMIN_EMAIL', 'admin@greencpapartners.com')

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

@app.route('/portal')
def portal():
    return render_template('portal.html')

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # Get form data
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        phone = request.form.get('phone', '').strip()
        service = request.form.get('service', '').strip()
        message = request.form.get('message', '').strip()
        honeypot = request.form.get('honeypot', '')
        
        # Spam protection
        if honeypot:
            return "Spam detected", 400
        
        # Validation
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
                    <p><strong>Date:</strong> {request.form.get('date', '')}</p>
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
        
        # Send emails
        admin_sent = send_email(ADMIN_EMAIL, admin_subject, admin_body)
        client_sent = send_email(email, client_subject, client_body)
        
        if admin_sent:
            flash('Thank you! Your message has been sent. We will contact you soon.', 'success')
            return redirect(url_for('index'))
        else:
            flash('Sorry, there was an error sending your message. Please try again later.', 'danger')
            return redirect(url_for('index'))
    
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True, port=5000)