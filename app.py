from flask import Flask, send_from_directory, jsonify, request, url_for, session
from flask_cors import CORS
from datetime import datetime, timedelta
import sys
import os
import socket
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from functools import wraps
from dotenv import load_dotenv
import sqlalchemy.orm

# Load environment variables from .env file if it exists
if os.path.exists(os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')):
    load_dotenv()

# Get environment variables or use defaults
DEBUG = os.getenv('DEBUG', 'True').lower() in ('true', '1', 't')
PORT = int(os.getenv('PORT', 5002))

# Calculate current script directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# 💡 Compatible with PyInstaller packaged environment
if getattr(sys, 'frozen', False):  # PyInstaller runtime
    BASE_DIR = sys._MEIPASS  # Get PyInstaller temporary directory

# 💡 Ensure `models.py` can be imported
sys.path.append(BASE_DIR)  # Current directory
sys.path.append(os.path.join(BASE_DIR, "backend"))  # Adapt for backend directory
sys.path.append(os.path.dirname(BASE_DIR))  # Adapt for PyInstaller runtime environment

# 💡 Ensure `models.py` exists and can be imported
try:
    import models
except ModuleNotFoundError as e:
    print("❌ Error: models module not found!")
    print(f"🔍 Current sys.path: {sys.path}")
    raise e  # Raise exception to see complete error message

# Bind database models
Session = models.Session
Record = models.Record
Category = models.Category
User = models.User
Role = models.Role
AuditLog = models.AuditLog
insert_default_categories = models.insert_default_categories
record_user_activity = models.record_user_activity

# Ensure database `accounting.db` exists
DB_PATH = os.path.join(BASE_DIR, "accounting.db")
if not os.path.exists(DB_PATH):
    print(f"⚠️ Warning: Database file {DB_PATH} not found, will attempt to create...")
    models.init_db()  # Reinitialize database

# Calculate Vue frontend path
DIST_DIR = os.path.join(BASE_DIR, "web_frontend/dist")
if not os.path.exists(DIST_DIR):  # Compatible with PyInstaller packaged path
    DIST_DIR = os.path.join(BASE_DIR, "../web_frontend/dist")

app = Flask(__name__, static_folder=DIST_DIR, static_url_path="/")
app.secret_key = os.getenv('SECRET_KEY', os.urandom(24).hex())  # Set session key
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Session timeout: 30 minutes

# Configure session security
app.config['SESSION_COOKIE_SECURE'] = not DEBUG  # Use HTTPS in production environment
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JS access to cookies
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Prevent CSRF

# Configure CORS based on environment
if DEBUG:
    print("🔒 CORS: Development mode - Allow local frontend source (e.g., http://localhost:5173)")
    CORS(app, origins=["http://localhost:5173", "https://fanum-frontend.vercel.app"], supports_credentials=True)
else:
    # In production, restrict origins for security
    allowed_origins = os.getenv('ALLOWED_ORIGINS', '*').split(',')
    print(f"🔒 CORS: Production mode - Allow sources: {allowed_origins}")
    CORS(app, origins=allowed_origins, supports_credentials=True)


# --- Add this below your CORS(app, ...) ---
@app.after_request
def apply_cors_headers(response):
    origin = request.headers.get('Origin')
    if origin and ('vercel.app' in origin or 'localhost' in origin):
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        response.headers['Vary'] = 'Origin'
    return response

# Add preflight request handling to ensure CORS works
@app.route('/api/auth/register', methods=['OPTIONS'])
@app.route('/api/auth/login', methods=['OPTIONS'])
@app.route('/api/auth/verify', methods=['OPTIONS'])
@app.route('/api/auth/verify-email/<token>', methods=['OPTIONS'])  # Added preflight request handling
def handle_auth_preflight():
    """Handle preflight requests for authentication-related requests"""
    print("⭐ Received preflight request for authentication-related requests")
    response = jsonify({'status': 'ok'})
    response.headers.add('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization')

    return response

# Send email function
def send_verification_email(email, token):
    """Send verification email"""
    # Get email configuration from environment variables
    smtp_server = os.getenv('SMTP_SERVER', 'smtp.example.com')
    smtp_port = int(os.getenv('SMTP_PORT', 587))
    smtp_user = os.getenv('SMTP_USER', 'user@example.com')
    smtp_password = os.getenv('SMTP_PASSWORD', 'password')
    sender_email = os.getenv('SENDER_EMAIL', 'noreply@example.com')
    
    # Build verification URL
    base_url = os.getenv('BASE_URL', 'http://localhost:5002')
    verify_url = f"{base_url}/api/auth/verify-email/{token}"
    
    # Build email content
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = email
    msg['Subject'] = "Verify Your Account - Accounting Tool"
    
    # Email body
    body = f"""
    <html>
    <body>
        <h2>Thank you for registering with the Accounting Tool!</h2>
        <p>Please click the link below to verify your email address:</p>
        <p><a href="{verify_url}">{verify_url}</a></p>
        <p>If you did not register for this account, please ignore this email.</p>
    </body>
    </html>
    """
    msg.attach(MIMEText(body, 'html'))
    
    try:
        # Connect to SMTP server and send email
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()  # Enable TLS encryption
        server.login(smtp_user, smtp_password)
        server.send_message(msg)
        server.quit()
        print(f"✅ Verification email sent to {email}")
        return True
    except Exception as e:
        print(f"❌ Failed to send verification email: {e}")
        import traceback
        traceback.print_exc()
        return False

# Permission check decorator
def requires_permission(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Prioritize Authorization header
            auth_header = request.headers.get('Authorization')
            user = None
            user_id = None
            user_role = None
            
            s = Session()
            try:
                if auth_header and auth_header.startswith('Bearer '):
                    token = auth_header[7:]  # Remove 'Bearer ' prefix
                    # Use token to find user
                    user = s.query(User).filter_by(username=token).first()
                
                # If no authorization header or invalid header, try to get user ID from session
                if not user and 'user_id' in session:
                    user_id = session.get('user_id')
                    # Important: Get user and role in session process
                    user = s.query(User).options(
                        # Preload role relationship
                        sqlalchemy.orm.joinedload(User.role)
                    ).filter_by(id=user_id).first()
                
                # If no valid user found, return unauthorized
                if not user or not user.is_active:
                    return jsonify({'success': False, 'message': 'Unauthorized access'}), 401
                
                # Check role and permissions
                if user.role:
                    user_role = user.role.name
                
                # Check permissions
                if permission == 'admin' and user_role != 'admin':
                    return jsonify({'success': False, 'message': 'Admin permission required'}), 403
                elif not user.has_permission(permission):
                    return jsonify({'success': False, 'message': 'No permission to perform this operation'}), 403
                    
                # Update session activity time
                if 'user_id' in session:
                    session.modified = True
                    
                # Call original view function, using the same session
                return f(user, *args, **kwargs)
            finally:
                s.close()
        return decorated_function
    return decorator

# Check session timeout middleware
@app.before_request
def check_session_timeout():
    # Skip OPTIONS requests and static files
    if request.method == 'OPTIONS' or request.path.startswith('/static/'):
        return
        
    # If user is logged in, check session activity time
    if 'user_id' in session and 'last_activity' in session:
        last_activity = session.get('last_activity')
        if isinstance(last_activity, str):
            # If last_activity is a string, convert to datetime
            try:
                last_activity = datetime.fromisoformat(last_activity)
            except ValueError:
                # If conversion fails, reset session
                session.clear()
                return
        
        # Ensure no timezone information
        if hasattr(last_activity, 'tzinfo') and last_activity.tzinfo is not None:
            # Remove timezone information
            last_activity = last_activity.replace(tzinfo=None)
            
        now = datetime.utcnow()  # UTC time without timezone information
        
        # If last activity time exceeds session timeout time, clear session
        timeout = timedelta(minutes=30)
        if now - last_activity > timeout:
            session.clear()
            if request.content_type == 'application/json':
                return jsonify({'success': False, 'message': 'Session expired, please log in again', 'session_expired': True}), 401
                
    # Update last activity time
    if 'user_id' in session:
        session['last_activity'] = datetime.utcnow().isoformat()  # Store as ISO format string

# ===== User authentication API =====
@app.route('/api/auth/register', methods=['POST'])
def register():
    """Register new user"""
    print("⭐ Received registration request")
    try:
        data = request.json
        if not data:
            print("❌ Request data is empty or incorrect")
            return jsonify({'success': False, 'message': 'Request data is empty or incorrect'}), 400
            
        # Get data from request
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        given_name = data.get('givenName')
        family_name = data.get('familyName')
        phone = data.get('phone')
        role_name = data.get('role', 'individual')  # Default to individual user
        
        # If no username is provided, use email as username
        if not username and email:
            username = email
            
        print(f"📝 Registration request data: email={email}, role={role_name}, password={'*' * len(password) if password else 'None'}")
        
        # Validate required fields
        if not password or not email:
            print("❌ Email and password cannot be empty")
            return jsonify({'success': False, 'message': 'Email and password cannot be empty'}), 400
        
        # Simple email format validation
        if '@' not in email or '.' not in email:
            print(f"❌ Incorrect email format: {email}")
            return jsonify({'success': False, 'message': 'Incorrect email format'}), 400
            
        # Validate role is valid
        if role_name not in ['individual', 'business']:
            print(f"❌ Invalid role type: {role_name}")
            return jsonify({'success': False, 'message': 'Invalid role type'}), 400
            
        s = Session()
        try:
            # Check if username already exists
            existing_user = s.query(User).filter_by(username=username).first()
            if existing_user:
                print(f"❌ Username {username} already exists")
                return jsonify({'success': False, 'message': 'Username already exists'}), 400
                
            # Check if email already exists
            existing_email = s.query(User).filter_by(email=email).first()
            if existing_email:
                print(f"❌ Email {email} already registered")
                return jsonify({'success': False, 'message': 'This email is already registered'}), 400
                
            # Get corresponding role ID
            role = s.query(Role).filter_by(name=role_name).first()
            if not role:
                print(f"❌ Role {role_name} does not exist, default role will be used")
                # If role does not exist, try to create
                try:
                    if role_name == 'individual':
                        role = Role(name='individual', description='Individual taxpayer')
                    elif role_name == 'business':
                        role = Role(name='business', description='Business user')
                    else:
                        role = Role(name='individual', description='Individual taxpayer')
                    s.add(role)
                    s.flush()  # Get new role ID
                except Exception as e:
                    print(f"❌ Failed to create role: {e}")
                    # Fallback to using default role
                    role = s.query(Role).filter_by(name='individual').first()
                    if not role:
                        print("❌ Default role does not exist, please initialize role first")
                        return jsonify({'success': False, 'message': 'System error: Role not initialized'}), 500
                
            # Create new user
            new_user = User(username=username, email=email, role_id=role.id)
            
            # Set other user fields
            if given_name:
                new_user.given_name = given_name
            if family_name:
                new_user.family_name = family_name
            if phone:
                new_user.phone = phone
                
            new_user.set_password(password)
            
            # Directly set as verified, skip email verification
            new_user.email_verified = True
            
            # Add to database
            s.add(new_user)
            s.commit()
            
            print(f"✅ User {username} registered successfully")
            return jsonify({
                'success': True, 
                'message': 'Registration successful, please log in directly',
            }), 201
                
        except Exception as e:
            s.rollback()
            print(f"❌ Registration failed {username}: {e}")
            import traceback
            traceback.print_exc()  # Print detailed error stack
            return jsonify({'success': False, 'message': f'Registration failed: {str(e)}'}), 500
        finally:
            s.close()
    except Exception as e:
        print(f"❌ Error processing registration request: {e}")
        import traceback
        traceback.print_exc()  # Print detailed error stack
        return jsonify({'success': False, 'message': f'Server error: {str(e)}'}), 500

# Email verification interface
@app.route('/api/auth/verify-email/<token>', methods=['GET'])
def verify_email(token):
    """Verify user email"""
    print(f"⭐ Received email verification request, token: {token}")
    s = Session()
    try:
        user = s.query(User).filter_by(verification_token=token).first()
        if not user:
            print("❌ Invalid verification token")
            return jsonify({'success': False, 'message': 'Invalid verification link'}), 400
            
        # Update verification status
        user.email_verified = True
        user.verification_token = None  # Clear token to prevent reuse
        s.commit()
        
        print(f"✅ User {user.username}'s email has been verified")
        
        # Return HTML page instead of JSON for better user experience
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Email Verification Successful</title>
            <style>
                body { font-family: Arial, sans-serif; text-align: center; margin-top: 50px; }
                .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                .success { color: #28a745; }
                .btn { display: inline-block; padding: 10px 20px; background-color: #007bff; 
                       color: white; text-decoration: none; border-radius: 5px; margin-top: 20px; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1 class="success">Email Verification Successful!</h1>
                <p>Your account has been activated. You can now log in and use all features.</p>
                <a href="/" class="btn">Return to Login</a>
            </div>
        </body>
        </html>
        """
        return html
    except Exception as e:
        s.rollback()
        print(f"❌ Email verification failed: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': f'Email verification failed: {str(e)}'}), 500
    finally:
        s.close()
        
@app.route('/api/auth/login', methods=['POST'])
def login():
    """User login"""
    print("⭐ Received login request")
    
    try:
        data = request.json
        if not data:
            return jsonify({'success': False, 'message': 'Invalid request data'}), 400
            
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            print("❌ Email or password is empty")
            return jsonify({'success': False, 'message': 'Please provide email and password'}), 400
            
        s = Session()
        try:
            # Find user
            user = s.query(User).filter_by(email=email).first()
            
            if not user:
                print(f"❌ Email {email} does not exist")
                return jsonify({'success': False, 'message': 'Email or password error'}), 401
                
            if not user.verify_password(password):
                print(f"❌ User {email} password error")
                return jsonify({'success': False, 'message': 'Email or password error'}), 401
                
            # Mark user as verified
            user.email_verified = True
            s.commit()
            
            # Set session
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role.name if user.role else None
            session['last_activity'] = datetime.utcnow().isoformat()  # Store as ISO format string
            session.permanent = True
            
            # Record login activity
            record_user_activity(s, user.id, 'login', f'User login - Email: {email}', request.remote_addr)
            
            # Login successful, return user information
            print(f"✅ User {email} login successful")
            return jsonify({
                'success': True,
                'message': 'Login successful',
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'role': user.role.name if user.role else None
                }
            }), 200
        except Exception as e:
            s.rollback()
            print(f"❌ Login processing failed: {str(e)}")
            import traceback
            traceback.print_exc()
            return jsonify({'success': False, 'message': f'Login failed: {str(e)}'}), 500
        finally:
            s.close()
    except Exception as e:
        print(f"❌ Error processing login request: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': f'Server error: {str(e)}'}), 500

# Logout interface
@app.route('/api/auth/logout', methods=['POST'])
def logout():
    """User logout"""
    print("⭐ Received logout request")
    
    # Record logout activity
    if 'user_id' in session:
        user_id = session.get('user_id')
        email = session.get('username')
        s = Session()
        try:
            record_user_activity(s, user_id, 'logout', f'User logout - Email: {email}', request.remote_addr)
            s.commit()
        except Exception as e:
            print(f"❌ Record logout activity failed: {e}")
        finally:
            s.close()
        
    # Clear session
    session.clear()
    
    return jsonify({'success': True, 'message': 'Logout successful'}), 200

# Re-send verification email interface
@app.route('/api/auth/resend-verification', methods=['POST'])
def resend_verification():
    """Re-send verification email"""
    print("⭐ Received re-send verification email request")
    try:
        data = request.json
        if not data or 'email' not in data:
            return jsonify({'success': False, 'message': 'Please provide email address'}), 400
            
        email = data.get('email')
        
        s = Session()
        try:
            user = s.query(User).filter_by(email=email).first()
            
            if not user:
                # For security, do not reveal email existence
                return jsonify({'success': True, 'message': 'If this email is registered, verification email will be sent to this address'}), 200
                
            if user.email_verified:
                return jsonify({'success': False, 'message': 'This email is verified, no need to re-verify'}), 400
                
            # Generate new verification token
            token = user.generate_verification_token()
            s.commit()
            
            # Send verification email
            email_sent = send_verification_email(email, token)
            
            if email_sent:
                return jsonify({'success': True, 'message': 'Verification email has been re-sent, please check'}), 200
            else:
                return jsonify({'success': False, 'message': 'Failed to send verification email, please try again later'}), 500
                
        except Exception as e:
            s.rollback()
            print(f"❌ Failed to re-send verification email: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({'success': False, 'message': f'Failed to re-send verification email: {str(e)}'}), 500
        finally:
            s.close()
    except Exception as e:
        print(f"❌ Error processing re-send verification email request: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': f'Server error: {str(e)}'}), 500
        
@app.route('/api/auth/verify', methods=['GET'])
def verify_user():
    """Verify user is logged in (for frontend authorization)"""
    # If using session, first check user information in session
    if 'user_id' in session:
        s = Session()
        try:
            user = s.query(User).get(session['user_id'])
            if user and user.is_active:
                return jsonify({
                    'success': True,
                    'user': {
                        'id': user.id,
                        'username': user.username,
                        'email': user.email,
                        'role': user.role.name if user.role else None
                    }
                }), 200
        except Exception as e:
            print(f"❌ Session verification failed: {e}")
        finally:
            s.close()
    
    # Fallback to token verification (compatible with old API)
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'success': False, 'message': 'Unauthorized access'}), 401
        
    token = auth_header[7:]  # Remove 'Bearer ' prefix
    
    s = Session()
    try:
        user = s.query(User).filter_by(username=token).first()  # Simplified example, actual should use JWT
        if not user or not user.is_active:
            return jsonify({'success': False, 'message': 'Unauthorized access'}), 401
            
        # Update session (even if verified through token, also establish session for user)
        session['user_id'] = user.id
        session['username'] = user.username
        session['role'] = user.role.name if user.role else None
        session['last_activity'] = datetime.utcnow().isoformat()  # Store as ISO format string
        session.permanent = True
            
        return jsonify({
            'success': True,
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'role': user.role.name if user.role else None
            }
        }), 200
    except Exception as e:
        print(f"❌ Verification failed: {e}")
        return jsonify({'success': False, 'message': f'Verification failed: {str(e)}'}), 500
    finally:
        s.close()

# Audit log query (only for admin)
@app.route('/api/admin/audit-logs', methods=['GET'])
@requires_permission('admin')
def get_audit_logs(current_user):
    """Get audit log records (requires admin permission)"""
    print("⭐ Received audit log query request")
    
    # Pagination parameters
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    # Filter parameters
    user_id = request.args.get('user_id', type=int)
    action = request.args.get('action')
    from_date = request.args.get('from_date')
    to_date = request.args.get('to_date')
    user_role = request.args.get('user_role')
    
    s = Session()
    try:
        # Preload User and Role relationships to avoid lazy loading errors
        query = s.query(AuditLog).options(
            sqlalchemy.orm.joinedload(AuditLog.user).joinedload(User.role)
        )
        
        # Apply filter conditions
        if user_id:
            query = query.filter(AuditLog.user_id == user_id)
        if action:
            query = query.filter(AuditLog.action == action)
        if from_date:
            try:
                from_datetime = datetime.strptime(from_date, '%Y-%m-%d')
                query = query.filter(AuditLog.timestamp >= from_datetime)
            except ValueError:
                pass
        if to_date:
            try:
                to_datetime = datetime.strptime(to_date, '%Y-%m-%d')
                to_datetime = to_datetime + timedelta(days=1)  # Include current day
                query = query.filter(AuditLog.timestamp < to_datetime)
            except ValueError:
                pass
        # Filter by user role
        if user_role:
            query = query.join(AuditLog.user).join(User.role).filter(Role.name == user_role)
                
        # Avoid using user_role column for counting query
        total = s.query(sqlalchemy.func.count(AuditLog.id)).scalar()
        
        # Sort and paginate
        logs = query.order_by(AuditLog.timestamp.desc()).offset((page-1)*per_page).limit(per_page).all()
        
        result = []
        for log in logs:
            # Safe handling of user role, avoid null reference errors
            username = 'Unknown'
            user_role = 'Unknown'
            
            if log.user:
                username = log.user.username
                if hasattr(log.user, 'role') and log.user.role:
                    user_role = log.user.role.name
            
            result.append({
                'id': log.id,
                'user_id': log.user_id,
                'username': username,
                'user_role': user_role,
                'timestamp': log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'action': log.action,
                'ip_address': log.ip_address,
                'details': log.details
            })
        
        # Record audit log
        record_user_activity(s, current_user.id, 'view_audit_logs', f'Viewed audit logs', request.remote_addr)
        
        return jsonify({
            'success': True,
            'logs': result,
            'total': total,
            'page': page,
            'per_page': per_page,
            'total_pages': (total + per_page - 1) // per_page
        }), 200
    except Exception as e:
        print(f"❌ Failed to get audit logs: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': f'Failed to get audit logs: {str(e)}'}), 500
    finally:
        s.close()

# Export audit logs as PDF
@app.route('/api/admin/export-audit-logs/pdf', methods=['GET'])
@requires_permission('admin')
def export_audit_logs_pdf(current_user):
    """Export audit logs as PDF (requires admin permission)"""
    print("⭐ Received export audit logs as PDF request")
    
    # Filter parameters
    user_id = request.args.get('user_id', type=int)
    action = request.args.get('action')
    from_date = request.args.get('from_date')
    to_date = request.args.get('to_date')
    user_role = request.args.get('user_role')
    
    s = Session()
    try:
        # Use the same query logic as get_audit_logs
        query = s.query(AuditLog).options(
            sqlalchemy.orm.joinedload(AuditLog.user).joinedload(User.role)
        )
        
        # Apply filter conditions
        if user_id:
            query = query.filter(AuditLog.user_id == user_id)
        if action:
            query = query.filter(AuditLog.action == action)
        if from_date:
            try:
                from_datetime = datetime.strptime(from_date, '%Y-%m-%d')
                query = query.filter(AuditLog.timestamp >= from_datetime)
            except ValueError:
                pass
        if to_date:
            try:
                to_datetime = datetime.strptime(to_date, '%Y-%m-%d')
                to_datetime = to_datetime + timedelta(days=1)  # Include current day
                query = query.filter(AuditLog.timestamp < to_datetime)
            except ValueError:
                pass
        # Filter by user role
        if user_role:
            query = query.join(AuditLog.user).join(User.role).filter(Role.name == user_role)
                
        # Get all logs that match the conditions, but no more than 1000
        logs = query.order_by(AuditLog.timestamp.desc()).limit(1000).all()
        
        # Record audit log
        record_user_activity(s, current_user.id, 'export_audit_logs', f'Exported audit logs to PDF', request.remote_addr)
        
        result = []
        for log in logs:
            # Safe handling of user role
            username = 'Unknown'
            user_role_value = 'Unknown'
            
            if log.user:
                username = log.user.username
                if hasattr(log.user, 'role') and log.user.role:
                    user_role_value = log.user.role.name
            
            result.append({
                'id': log.id,
                'user_id': log.user_id,
                'username': username,
                'user_role': user_role_value,
                'timestamp': log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'action': log.action,
                'ip_address': log.ip_address,
                'details': log.details
            })
        
        # Here we directly return JSON, front end is responsible for generating PDF
        # In actual production environment, PDF can be generated on backend and returned as file stream
        return jsonify({
            'success': True,
            'logs': result
        }), 200
    except Exception as e:
        print(f"❌ Failed to export audit logs as PDF: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': f'Failed to export audit logs as PDF: {str(e)}'}), 500
    finally:
        s.close()

# Export audit logs as CSV
@app.route('/api/admin/export-audit-logs/csv', methods=['GET'])
@requires_permission('admin')
def export_audit_logs_csv(current_user):
    """Export audit logs as CSV (requires admin permission)"""
    print("⭐ Received export audit logs as CSV request")
    
    # Filter parameters
    user_id = request.args.get('user_id', type=int)
    action = request.args.get('action')
    from_date = request.args.get('from_date')
    to_date = request.args.get('to_date')
    user_role = request.args.get('user_role')
    
    s = Session()
    try:
        # Use the same query logic as get_audit_logs
        query = s.query(AuditLog).options(
            sqlalchemy.orm.joinedload(AuditLog.user).joinedload(User.role)
        )
        
        # Apply filter conditions
        if user_id:
            query = query.filter(AuditLog.user_id == user_id)
        if action:
            query = query.filter(AuditLog.action == action)
        if from_date:
            try:
                from_datetime = datetime.strptime(from_date, '%Y-%m-%d')
                query = query.filter(AuditLog.timestamp >= from_datetime)
            except ValueError:
                pass
        if to_date:
            try:
                to_datetime = datetime.strptime(to_date, '%Y-%m-%d')
                to_datetime = to_datetime + timedelta(days=1)  # Include current day
                query = query.filter(AuditLog.timestamp < to_datetime)
            except ValueError:
                pass
        # Filter by user role
        if user_role:
            query = query.join(AuditLog.user).join(User.role).filter(Role.name == user_role)
                
        # Get all logs that match the conditions, but no more than 5000
        logs = query.order_by(AuditLog.timestamp.desc()).limit(5000).all()
        
        # Record audit log
        record_user_activity(s, current_user.id, 'export_audit_logs', f'Exported audit logs to CSV', request.remote_addr)
        
        result = []
        for log in logs:
            # Safe handling of user role
            username = 'Unknown'
            user_role_value = 'Unknown'
            
            if log.user:
                username = log.user.username
                if hasattr(log.user, 'role') and log.user.role:
                    user_role_value = log.user.role.name
            
            result.append({
                'id': log.id,
                'user_id': log.user_id,
                'username': username,
                'user_role': user_role_value,
                'timestamp': log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'action': log.action,
                'ip_address': log.ip_address or '',
                'details': log.details or ''
            })
        
        # Here we directly return JSON, front end is responsible for generating CSV
        # In actual production environment, CSV can be generated on backend and returned as file stream
        return jsonify({
            'success': True,
            'logs': result
        }), 200
    except Exception as e:
        print(f"❌ Failed to export audit logs as CSV: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': f'Failed to export audit logs as CSV: {str(e)}'}), 500
    finally:
        s.close()

# ===== Accounting API =====
@app.route('/api/add_record', methods=['POST'])
@requires_permission('add_record')
def add_record(current_user):
    """Add accounting record"""
    data = request.json
    s = Session()
    try:
        record = Record(
            date=datetime.strptime(data.get('date'), '%Y-%m-%d'),
            amount=data.get('amount'),
            category_id=data.get('category_id'),
            remarks=data.get('remarks')
        )
        s.add(record)
        s.commit()
        
        # Record operation to audit log
        record_user_activity(s, current_user.id, 'add_record', f"Added record ID: {record.id}", request.remote_addr)
        
        return jsonify({'message': 'Record added successfully', 'record_id': record.id}), 200
    except Exception as e:
        s.rollback()
        return jsonify({'error': str(e)}), 400
    finally:
        s.close()

@app.route('/api/get_records', methods=['GET'])
@requires_permission('view_records')
def get_records(current_user):
    """Get all accounting records"""
    s = Session()
    try:
        from sqlalchemy.orm import joinedload
        records = s.query(Record).options(joinedload(Record.category)).all()
        result = [{
            'id': r.id,
            'date': r.date.strftime('%Y-%m-%d'),
            'amount': r.amount,
            'category_id': r.category_id,
            'category': r.category.name if r.category else '',
            'remarks': r.remarks
        } for r in records]
        
        # Record audit log
        record_user_activity(s, current_user.id, 'view_records', "Viewed all accounting records", request.remote_addr)
        
        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400
    finally:
        s.close()

@app.route('/api/delete_record/<int:record_id>', methods=['DELETE'])
@requires_permission('delete_record')
def delete_record(current_user, record_id):
    """Delete an accounting record"""
    s = Session()
    try:
        print(f"🔍 Trying to delete record ID: {record_id}")  # ✅ Added debug information

        record = s.query(Record).filter_by(id=record_id).first()
        if not record:
            print(f"❌ Record {record_id} does not exist!")  # ✅ Added debug information
            return jsonify({'error': 'Record does not exist'}), 404
        
        s.delete(record)
        s.commit()
        
        # Record audit log
        record_user_activity(s, current_user.id, 'delete_record', f"Deleted record ID: {record_id}", request.remote_addr)
        
        print(f"✅ Record {record_id} deleted successfully!")  # ✅ Added debug information
        return jsonify({'message': 'Record deleted successfully'}), 200
    except Exception as e:
        s.rollback()
        print(f"❌ Delete failed: {e}")  # ✅ Added debug information
        return jsonify({'error': str(e)}), 400
    finally:
        s.close()

@app.route('/api/update_record/<int:record_id>', methods=['PUT'])
@requires_permission('update_record')
def update_record(current_user, record_id):
    data = request.json
    s = Session()
    try:
        print(f"🔍 Received update request, recordID: {record_id}, data: {data}")
        
        record = s.query(Record).filter_by(id=record_id).first()
        if not record:
            print(f"❌ Record {record_id} does not exist!")
            return jsonify({'error': 'Record does not exist'}), 404
            
        # Handle date
        if 'date' in data:
            try:
                record.date = datetime.strptime(data.get('date'), '%Y-%m-%d')
                print(f"✅ Date updated to: {record.date}")
            except ValueError as e:
                print(f"❌ Date format error: {e}")
                return jsonify({'error': f'Date format error: {e}'}), 400
            
        # Handle amount
        if 'amount' in data:
            try:
                record.amount = float(data.get('amount'))
                print(f"✅ Amount updated to: {record.amount}")
            except ValueError as e:
                print(f"❌ Amount format error: {e}")
                return jsonify({'error': f'Amount format error: {e}'}), 400
            
        # Handle category ID
        if 'category_id' in data and data['category_id'] is not None:
            record.category_id = data.get('category_id')
            print(f"✅ Category ID updated to: {record.category_id}")
        # If frontend passes category name, find corresponding ID by name
        elif 'category' in data and data['category']:
            try:
                category = s.query(Category).filter_by(name=data['category']).first()
                if category:
                    record.category_id = category.id
                    print(f"✅ Found category ID by name '{data['category']}': {category.id}")
                else:
                    # If category does not exist, create new category
                    new_category = Category(name=data['category'])
                    s.add(new_category)
                    s.flush()  # Get new category ID
                    record.category_id = new_category.id
                    print(f"✅ Created new category '{data['category']}', ID: {new_category.id}")
            except Exception as e:
                print(f"❌ Error processing category: {e}")
                return jsonify({'error': f'Error processing category: {e}'}), 400
                
        # Handle remarks
        if 'remarks' in data:
            record.remarks = data.get('remarks')
            print(f"✅ Remarks updated to: {record.remarks}")
            
        s.commit()
        
        # Record audit log
        record_user_activity(s, current_user.id, 'update_record', f"Updated record ID: {record_id}", request.remote_addr)
        
        print(f"✅ Record {record_id} updated successfully!")
        return jsonify({'message': 'Record updated successfully', 'record_id': record_id}), 200
    except Exception as e:
        s.rollback()
        print(f"❌ Update failed: {e}")
        import traceback
        traceback.print_exc()  # Print detailed error stack
        return jsonify({'error': str(e)}), 400
    finally:
        s.close()

@app.route('/api/get_categories', methods=['GET'])
def get_categories():
    """Get all categories"""
    s = Session()
    try:
        categories = s.query(Category).all()
        result = [{'id': cat.id, 'name': cat.name} for cat in categories]
        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400
    finally:
        s.close()

# User management API (only for admin)
@app.route('/api/admin/users', methods=['GET'])
@requires_permission('admin')
def get_users(current_user):
    """Get all users (requires admin permission)"""
    s = Session()
    try:
        users = s.query(User).all()
        result = [{
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'is_active': user.is_active,
            'email_verified': user.email_verified,
            'role': user.role.name if user.role else None
        } for user in users]
        
        # Record audit log
        record_user_activity(s, current_user.id, 'view_users', "Viewed all users list", request.remote_addr)
        
        return jsonify({'success': True, 'users': result}), 200
    except Exception as e:
        print(f"❌ Failed to get users list: {e}")
        return jsonify({'success': False, 'message': f'Failed to get users: {str(e)}'}), 500
    finally:
        s.close()

@app.route('/api/admin/user/<int:user_id>', methods=['PUT'])
@requires_permission('admin')
def update_user(current_user, user_id):
    """Update user information (requires admin permission)"""
    data = request.json
    s = Session()
    try:
        user = s.query(User).get(user_id)
        if not user:
            return jsonify({'success': False, 'message': 'User does not exist'}), 404
            
        # Record state before modification
        old_status = {
            'is_active': user.is_active,
            'role': user.role.name if user.role else None,
            'email_verified': user.email_verified
        }
        
        # Update user status
        if 'is_active' in data:
            user.is_active = data['is_active']
            
        if 'email_verified' in data:
            user.email_verified = data['email_verified']
            
        if 'role' in data and data['role']:
            role = s.query(Role).filter_by(name=data['role']).first()
            if role:
                user.role_id = role.id
        
        s.commit()
        
        # Record audit log
        changes = {k: v for k, v in {
            'is_active': user.is_active,
            'role': user.role.name if user.role else None,
            'email_verified': user.email_verified
        }.items() if old_status.get(k) != v}
        
        record_user_activity(
            s,
            current_user.id, 
            'update_user',
            f"Updated user ID: {user_id}, changes: {changes}",
            request.remote_addr
        )
        
        return jsonify({
            'success': True,
            'message': 'User information updated',
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'is_active': user.is_active,
                'email_verified': user.email_verified,
                'role': user.role.name if user.role else None
            }
        }), 200
    except Exception as e:
        s.rollback()
        print(f"❌ Failed to update user: {e}")
        return jsonify({'success': False, 'message': f'Failed to update user: {str(e)}'}), 500
    finally:
        s.close()

# ===== Vue frontend hosting =====
@app.route("/")
def serve_vue():
    """Return Vue frontend's index.html"""
    return send_from_directory(app.static_folder, "index.html")

@app.route("/<path:path>")
def serve_static(path):
    """Return Vue other static files (JS, CSS, images, etc.)"""
    return send_from_directory(app.static_folder, path)

# ===== Port occupation check =====
def is_port_in_use(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('127.0.0.1', port)) == 0

# Add API endpoint to save draft
@app.route('/api/save_draft', methods=['POST'])
def save_draft():
    """Save form draft to database"""
    print("⭐ Received save draft request")
    
    # Check if user is logged in
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please log in first'}), 401
    
    try:
        # Get request data
        data = request.json
        if not data:
            return jsonify({'success': False, 'message': 'Invalid request data'}), 400
            
        # Get current user
        s = Session()
        user_id = session.get('user_id')
        user = s.query(User).filter_by(id=user_id).first()
        
        if not user:
            return jsonify({'success': False, 'message': 'User does not exist'}), 404
            
        # Check if it's a new draft or updating an existing draft
        form_id = data.get('form_id')
        
        # Create or update draft form
        from models import TaxForm
        
        if form_id and str(form_id).startswith("temp-") or not form_id:
            # New draft, save temporary ID for tracking
            temp_id = form_id if form_id else None
            
            new_form = TaxForm(
                user_id=user_id,
                temp_id=temp_id,  # Save frontend temporary ID
                date=data.get('date'),
                declaration_type=data.get('declaration_type'),
                address=data.get('address'),
                declaration_name=data.get('declaration_name'),
                price=data.get('price', 0),
                other_info=data.get('other_info', ''),
                status='draft'
            )
            s.add(new_form)
            s.commit()
            
            # Record user activity
            record_user_activity(s, user_id, 'DRAFT_SAVE', f'Saved draft form - ID: {new_form.id}, Type: {data.get("declaration_type")}, Amount: {data.get("price")}', request.remote_addr)
            
            # Return generated ID and temporary ID
            return jsonify({
                'success': True,
                'message': 'Draft saved successfully',
                'id': new_form.id,
                'temp_id': temp_id
            })
        else:
            # Update existing draft
            existing_form = s.query(TaxForm).filter_by(id=form_id, user_id=user_id).first()
            if not existing_form:
                return jsonify({'success': False, 'message': 'Form does not exist or no permission'}), 404
                
            # Update fields
            existing_form.date = data.get('date')
            existing_form.declaration_type = data.get('declaration_type')
            existing_form.address = data.get('address')
            existing_form.declaration_name = data.get('declaration_name')
            existing_form.price = data.get('price', 0)
            existing_form.other_info = data.get('other_info', '')
            existing_form.updated_at = datetime.utcnow()
            
            s.commit()
            
            # Record user activity
            record_user_activity(s, user_id, 'DRAFT_UPDATE', f'Updated draft form - ID: {existing_form.id}, Type: {data.get("declaration_type")}, Amount: {data.get("price")}', request.remote_addr)
            
            return jsonify({
                'success': True,
                'message': 'Draft updated successfully',
                'id': existing_form.id,
                'temp_id': existing_form.temp_id
            })
            
    except Exception as e:
        print(f"❌ Failed to save draft: {e}")
        import traceback
        traceback.print_exc()
        s.rollback()
        return jsonify({'success': False, 'message': f'Failed to save draft: {str(e)}'}), 500
    finally:
        s.close()

# Add API endpoint to submit tax form
@app.route('/api/submit_tax_form', methods=['POST'])
def submit_tax_form():
    """Submit tax form to database"""
    print("⭐ Received submit tax form request")
    
    # Check if user is logged in
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please log in first'}), 401
    
    try:
        # Get request data
        data = request.json
        if not data:
            return jsonify({'success': False, 'message': 'Invalid request data'}), 400
            
        # Get current user
        s = Session()
        user_id = session.get('user_id')
        user = s.query(User).filter_by(id=user_id).first()
        
        if not user:
            return jsonify({'success': False, 'message': 'User does not exist'}), 404
            
        # Check if submitting from existing draft
        form_id = data.get('form_id')
        
        from models import TaxForm
        
        if form_id and not str(form_id).startswith("temp-"):
            # Update existing form
            existing_form = s.query(TaxForm).filter_by(id=form_id, user_id=user_id).first()
            if not existing_form:
                return jsonify({'success': False, 'message': 'Form does not exist or no permission'}), 404
                
            # Update fields
            existing_form.date = data.get('date')
            existing_form.declaration_type = data.get('declaration_type')
            existing_form.address = data.get('address')
            existing_form.declaration_name = data.get('declaration_name')
            existing_form.price = data.get('price', 0)
            existing_form.other_info = data.get('other_info', '')
            existing_form.status = 'submitted'
            existing_form.submitted_at = datetime.utcnow()
            existing_form.updated_at = datetime.utcnow()
            
            s.commit()
            
            # Record user activity
            record_user_activity(s, user_id, 'FORM_SUBMIT', f'Submitted form - ID: {existing_form.id}, Type: {data.get("declaration_type")}, Amount: {data.get("price")}, Date: {data.get("date")}', request.remote_addr)
            
            return jsonify({
                'success': True,
                'message': 'Form submitted successfully',
                'id': existing_form.id,
                'temp_id': existing_form.temp_id
            })
        else:
            # Create new form, save temporary ID
            temp_id = form_id if form_id else None
            
            new_form = TaxForm(
                user_id=user_id,
                temp_id=temp_id,  # Save frontend temporary ID
                date=data.get('date'),
                declaration_type=data.get('declaration_type'),
                address=data.get('address'),
                declaration_name=data.get('declaration_name'),
                price=data.get('price', 0),
                other_info=data.get('other_info', ''),
                status='submitted',
                submitted_at=datetime.utcnow()
            )
            s.add(new_form)
            s.commit()
            
            # Record user activity
            record_user_activity(s, user_id, 'FORM_SUBMIT', f'Submitted new form - ID: {new_form.id}, Type: {data.get("declaration_type")}, Amount: {data.get("price")}, Date: {data.get("date")}', request.remote_addr)
            
            # Return generated ID and temporary ID
            return jsonify({
                'success': True,
                'message': 'Form submitted successfully',
                'id': new_form.id,
                'temp_id': temp_id
            })
            
    except Exception as e:
        print(f"❌ Failed to submit form: {e}")
        import traceback
        traceback.print_exc()
        s.rollback()
        return jsonify({'success': False, 'message': f'Failed to submit form: {str(e)}'}), 500
    finally:
        s.close()
        
# Query all tax forms
@app.route('/api/get_tax_forms', methods=['GET'])
def get_tax_forms():
    """Get all tax forms for current user"""
    print("⭐ Received get tax forms request")
    
    # Check if user is logged in
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please log in first'}), 401
    
    try:
        # Get current user
        s = Session()
        user_id = session.get('user_id')
        
        # Query user's all forms
        from models import TaxForm
        forms = s.query(TaxForm).filter_by(user_id=user_id).order_by(TaxForm.updated_at.desc()).all()
        
        # Convert to JSON format
        forms_data = []
        for form in forms:
            forms_data.append({
                'id': form.id,
                'temp_id': form.temp_id,  # Include temporary ID
                'date': form.date,
                'declaration_type': form.declaration_type,
                'address': form.address,
                'declaration_name': form.declaration_name,
                'price': form.price,
                'other_info': form.other_info,
                'status': form.status,
                'created_at': form.created_at.isoformat() if form.created_at else None,
                'updated_at': form.updated_at.isoformat() if form.updated_at else None,
                'submitted_at': form.submitted_at.isoformat() if form.submitted_at else None,
            })
        
        # Record user viewed form history activity
        record_user_activity(s, user_id, 'VIEW_FORMS', f'Viewed form history - {len(forms_data)} records', request.remote_addr)
        
        return jsonify({
            'success': True,
            'forms': forms_data
        })
            
    except Exception as e:
        print(f"❌ Failed to get forms: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': f'Failed to get forms: {str(e)}'}), 500
    finally:
        s.close()

if __name__ == '__main__':
    if is_port_in_use(PORT):
        print(f"⚠️ Port {PORT} is occupied, please release port or use other port!")
        sys.exit(1)

    print(f"✅ Running Flask on port {PORT}, Debug mode: {DEBUG}")
    app.run(host='0.0.0.0', port=PORT, debug=DEBUG, use_reloader=False)