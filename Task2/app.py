from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth
import os, secrets
from datetime import datetime
from functools import wraps
from dotenv import load_dotenv
import pyotp
import qrcode
import io
import base64
from datetime import datetime, timedelta

# Load environment variables
load_dotenv()

# Initialize Flask
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 minutes in seconds

# MySQL Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = (
    f"mysql+pymysql://{os.environ['DB_USER']}:{os.environ['DB_PASSWORD']}"
    f"@{os.environ['DB_HOST']}/{os.environ['DB_NAME']}"
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# OAuth Configuration
oauth = OAuth(app)
github = oauth.register(
    name='github',
    client_id=os.environ.get('GITHUB_CLIENT_ID'),
    client_secret=os.environ.get('GITHUB_CLIENT_SECRET'),
    access_token_url='https://github.com/login/oauth/access_token',
    authorize_url='https://github.com/login/oauth/authorize',
    api_base_url='https://api.github.com/',
    client_kwargs={'scope': 'user:email'},
)

# Models
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    auth_method = db.Column(db.String(10), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    twofa_secret = db.Column(db.String(32), nullable=False)  # Now required for all users

class ManualAuth(db.Model):
    __tablename__ = 'manual_auth'
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

class GitHubAuth(db.Model):
    __tablename__ = 'github_auth'
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    github_id = db.Column(db.String(50), unique=True, nullable=False)
    github_username = db.Column(db.String(50))
    github_email = db.Column(db.String(255))

class LoginLog(db.Model):
    __tablename__ = 'login_logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    login_timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.Text)
    auth_method = db.Column(db.String(10), nullable=False)
class FailedLoginAttempt(db.Model):
    __tablename__ = 'failed_login_attempts'
    id = db.Column(db.Integer, primary_key=True)
    identifier = db.Column(db.String(255), nullable=False)  # username or email
    ip_address = db.Column(db.String(45), nullable=False)
    attempt_time = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)    

# Password policy validation
def validate_password(password):
    if (len(password) < 8 or 
        not any(c.isupper() for c in password) or
        not any(c.islower() for c in password) or
        not any(c.isdigit() for c in password) or
        not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?~' for c in password)):
        return False
    return True

# Decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or 'twofa_verified' not in session:
            flash('Please complete authentication', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def no_cache(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        response = make_response(f(*args, **kwargs))
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '-1'
        return response
    return decorated_function

def is_account_locked(identifier):
    # Check if there are 3+ failed attempts in the last minute
    one_minute_ago = datetime.utcnow() - timedelta(minutes=5)
    recent_attempts = FailedLoginAttempt.query.filter(
        FailedLoginAttempt.identifier == identifier,
        FailedLoginAttempt.attempt_time >= one_minute_ago
    ).count()
    
    if recent_attempts >= 3:
        # Check if 15 minutes have passed since the first of these attempts
        first_failed_attempt = FailedLoginAttempt.query.filter(
            FailedLoginAttempt.identifier == identifier
        ).order_by(FailedLoginAttempt.attempt_time.desc()).first()
        
        if first_failed_attempt and (datetime.utcnow() - first_failed_attempt.attempt_time) < timedelta(minutes=15):
            return True
    return False

def record_failed_attempt(identifier, ip_address):
    attempt = FailedLoginAttempt(
        identifier=identifier,
        ip_address=ip_address
    )
    db.session.add(attempt)
    db.session.commit()

# Routes
@app.route('/')
@login_required
@no_cache
def home():
    user = db.session.get(User, session['user_id'])
    if not user:
        session.clear()
        flash('User not found', 'error')
        return redirect(url_for('login'))

    # Get username based on auth method
    username = None
    if user.auth_method == 'manual':
        manual_auth = db.session.get(ManualAuth, user.id)
        if manual_auth:
            username = manual_auth.username
    elif user.auth_method == 'github':
        github_auth = db.session.get(GitHubAuth, user.id)
        if github_auth:
            username = github_auth.github_username

    if not username:
        session.clear()
        flash('User data incomplete', 'error')
        return redirect(url_for('login'))

    recent_logs = db.session.query(LoginLog)\
                  .filter_by(user_id=user.id)\
                  .order_by(LoginLog.login_timestamp.desc())\
                  .limit(5)\
                  .all()
    
    return render_template('home.html',
                         username=username,
                         auth_method=user.auth_method,
                         created_at=user.created_at,
                         recent_logs=recent_logs)

@app.route('/signup', methods=['GET', 'POST'])
@no_cache
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        remember = 'remember' in request.form
        
        if not all([username, email, password]):
            flash('All fields are required!', 'error')
            return redirect(url_for('signup'))
        
        if not validate_password(password):
            flash('Password must be 8+ chars with uppercase, lowercase, number, and special char', 'error')
            return redirect(url_for('signup'))
        
        if ManualAuth.query.filter((ManualAuth.username == username) | (ManualAuth.email == email)).first():
            flash('Username or email already exists', 'error')
            return redirect(url_for('signup'))
        
        # Generate 2FA secret and store in session
        twofa_secret = pyotp.random_base32()
        session['signup_data'] = {
            'username': username,
            'email': email,
            'password': password,
            'remember': remember,
            'twofa_secret': twofa_secret
        }
        return redirect(url_for('setup_2fa'))
    
    return render_template('signup.html')

@app.route('/setup-2fa', methods=['GET', 'POST'])
def setup_2fa():
    if 'signup_data' not in session:
        return redirect(url_for('signup'))
    
    if request.method == 'POST':
        otp = request.form.get('otp')
        if not otp or len(otp) != 6 or not otp.isdigit():
            flash('Invalid OTP format - must be 6 digits', 'error')
            return render_template('setup_2fa.html')
        
        totp = pyotp.TOTP(session['signup_data']['twofa_secret'])
        if not totp.verify(otp, valid_window=1):
            flash('Invalid OTP code', 'error')
            return render_template('setup_2fa.html')
        
        try:
            user = User(
                auth_method='manual',
                twofa_secret=session['signup_data']['twofa_secret']
            )
            db.session.add(user)
            db.session.flush()
            
            manual_auth = ManualAuth(
                user_id=user.id,
                username=session['signup_data']['username'],
                email=session['signup_data']['email'],
                password_hash=generate_password_hash(session['signup_data']['password'])
            )
            db.session.add(manual_auth)
            
            login_log = LoginLog(
                user_id=user.id,
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent'),
                auth_method='manual'
            )
            db.session.add(login_log)
            
            db.session.commit()
            
            session['user_id'] = user.id
            session['auth_method'] = 'manual'
            session['twofa_verified'] = True
            
            if session['signup_data']['remember']:
                session.permanent = True
            
            session.pop('signup_data', None)
            flash('Account created successfully!', 'success')
            return redirect(url_for('home'))
            
        except Exception as e:
            db.session.rollback()
            flash('Error creating account', 'error')
            return redirect(url_for('signup'))
    
    # Generate QR code for GET request
    otp_uri = pyotp.totp.TOTP(session['signup_data']['twofa_secret']).provisioning_uri(
        name=session['signup_data']['username'],
        issuer_name="Flask Auth App"
    )
    img = qrcode.make(otp_uri)
    img_io = io.BytesIO()
    img.save(img_io, 'PNG')
    img_io.seek(0)
    qr_code = base64.b64encode(img_io.getvalue()).decode('ascii')
    
    return render_template('setup_2fa.html', 
                         qr_code=qr_code, 
                         secret=session['signup_data']['twofa_secret'])

@app.route('/login', methods=['GET', 'POST'])
@no_cache
def login():
    if request.method == 'POST':
        identifier = request.form.get('identifier')
        password = request.form.get('password')
        remember = 'remember' in request.form
        
        if is_account_locked(identifier):
            flash('Account temporarily locked due to too many failed attempts. Please try again in 15 minutes.', 'error')
            return redirect(url_for('login'))
        
        manual_auth = ManualAuth.query.filter(
            (ManualAuth.username == identifier) | 
            (ManualAuth.email == identifier)
        ).first()
        
        if not manual_auth:
            flash('Account not found. Please sign up first.', 'error')
            return redirect(url_for('signup'))
        
        if check_password_hash(manual_auth.password_hash, password):
            user = User.query.get(manual_auth.user_id)
            session['login_data'] = {
                'user_id': user.id,
                'auth_method': 'manual',
                'remember': remember
            }
            return redirect(url_for('verify_2fa'))
        else:
            record_failed_attempt(identifier, request.remote_addr)
            flash('Incorrect password.', 'error')
    
    return render_template('login.html')

@app.route('/verify-2fa', methods=['GET', 'POST'])
@no_cache
def verify_2fa():
    # Check for pending authentication
    if 'login_data' not in session and 'github_login' not in session:
        flash('No pending authentication', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        otp = request.form.get('otp')
        if not otp or len(otp) != 6 or not otp.isdigit():
            flash('Invalid OTP format - must be 6 digits', 'error')
            return redirect(request.url)
        
        # Handle regular login
        if 'login_data' in session:
            user = User.query.get(session['login_data']['user_id'])
            if not user:
                flash('User not found', 'error')
                return redirect(url_for('login'))
                
            totp = pyotp.TOTP(user.twofa_secret)
            if not totp.verify(otp, valid_window=1):
                flash('Invalid OTP code', 'error')
                return redirect(request.url)
            
            # Successful verification
            session['user_id'] = user.id
            session['auth_method'] = session['login_data']['auth_method']
            session['twofa_verified'] = True
            
            if session['login_data'].get('remember'):
                session.permanent = True
            
            login_log = LoginLog(
                user_id=user.id,
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent'),
                auth_method=session['login_data']['auth_method']
            )
            db.session.add(login_log)
            db.session.commit()
            
            session.pop('login_data', None)
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        
        # Handle GitHub login
        elif 'github_login' in session:
            user = User.query.get(session['github_login']['user_id'])
            if not user:
                flash('User not found', 'error')
                return redirect(url_for('login'))
                
            totp = pyotp.TOTP(user.twofa_secret)
            if not totp.verify(otp, valid_window=1):
                flash('Invalid OTP code', 'error')
                return redirect(request.url)
            
            session['user_id'] = user.id
            session['auth_method'] = 'github'
            session['twofa_verified'] = True
            
            login_log = LoginLog(
                user_id=user.id,
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent'),
                auth_method='github'
            )
            db.session.add(login_log)
            db.session.commit()
            
            session.pop('github_login', None)
            flash('GitHub login successful!', 'success')
            return redirect(url_for('home'))
    
    return render_template('verify_2fa.html')

@app.route('/login/github')
@no_cache
def login_github():
    redirect_uri = url_for('authorize_github', _external=True)
    return github.authorize_redirect(redirect_uri)

@app.route('/login/github/callback')
@no_cache
def authorize_github():
    try:
        token = github.authorize_access_token()
        resp = github.get('user', token=token)
        profile = resp.json()
        
        github_auth = GitHubAuth.query.filter_by(github_id=str(profile['id'])).first()
        
        if github_auth:
            # Existing user - require 2FA verification
            session['github_login'] = {
                'user_id': github_auth.user_id,
                'auth_method': 'github'
            }
            return redirect(url_for('verify_2fa'))
        else:
            # New user - require 2FA setup
            twofa_secret = pyotp.random_base32()
            session['github_signup'] = {
                'github_id': str(profile['id']),
                'github_username': profile['login'],
                'github_email': profile.get('email'),
                'twofa_secret': twofa_secret
            }
            return redirect(url_for('setup_github_2fa'))
    
    except Exception as e:
        flash('GitHub login failed', 'error')
        return redirect(url_for('login'))

@app.route('/setup-github-2fa', methods=['GET', 'POST'])
def setup_github_2fa():
    if 'github_signup' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        otp = request.form.get('otp')
        if not otp or len(otp) != 6 or not otp.isdigit():
            flash('Invalid OTP format - must be 6 digits', 'error')
            return render_template('setup_2fa.html')
        
        totp = pyotp.TOTP(session['github_signup']['twofa_secret'])
        if not totp.verify(otp, valid_window=1):
            flash('Invalid OTP code', 'error')
            return render_template('setup_2fa.html')
        
        try:
            user = User(
                auth_method='github',
                twofa_secret=session['github_signup']['twofa_secret']
            )
            db.session.add(user)
            db.session.flush()
            
            github_auth = GitHubAuth(
                user_id=user.id,
                github_id=session['github_signup']['github_id'],
                github_username=session['github_signup']['github_username'],
                github_email=session['github_signup']['github_email']
            )
            db.session.add(github_auth)
            
            login_log = LoginLog(
                user_id=user.id,
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent'),
                auth_method='github'
            )
            db.session.add(login_log)
            
            db.session.commit()
            
            session['user_id'] = user.id
            session['auth_method'] = 'github'
            session['twofa_verified'] = True
            session.pop('github_signup', None)
            
            flash('GitHub account linked successfully!', 'success')
            return redirect(url_for('home'))
            
        except Exception as e:
            db.session.rollback()
            flash('Error creating GitHub account', 'error')
            return redirect(url_for('login'))
    
    # Generate QR code for GET request
    otp_uri = pyotp.totp.TOTP(session['github_signup']['twofa_secret']).provisioning_uri(
        name=session['github_signup']['github_username'],
        issuer_name="Flask Auth App"
    )
    img = qrcode.make(otp_uri)
    img_io = io.BytesIO()
    img.save(img_io, 'PNG')
    img_io.seek(0)
    qr_code = base64.b64encode(img_io.getvalue()).decode('ascii')
    
    return render_template('setup_2fa.html', 
                         qr_code=qr_code, 
                         secret=session['github_signup']['twofa_secret'])

@app.route('/logout')
@no_cache
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/api/check_username/<username>')
def check_username(username):
    exists = ManualAuth.query.filter_by(username=username).first() is not None
    return jsonify({'available': not exists})

# Initialize the database
def create_app():
    with app.app_context():
        db.create_all()
    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)