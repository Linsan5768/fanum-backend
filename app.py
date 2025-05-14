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

# 计算当前脚本所在目录
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# 💡 兼容 PyInstaller 打包后的环境
if getattr(sys, 'frozen', False):  # PyInstaller 运行时
    BASE_DIR = sys._MEIPASS  # 获取 PyInstaller 临时目录

# 💡 确保 `models.py` 可被导入
sys.path.append(BASE_DIR)  # 当前目录
sys.path.append(os.path.join(BASE_DIR, "backend"))  # 适配 backend 目录
sys.path.append(os.path.dirname(BASE_DIR))  # 适配 PyInstaller 运行环境

# 💡 确保 `models.py` 存在并可导入
try:
    import models
except ModuleNotFoundError as e:
    print("❌ 错误: models 模块未找到！")
    print(f"🔍 当前 sys.path: {sys.path}")
    raise e  # 抛出异常，确保我们看到完整错误信息

# 绑定数据库模型
Session = models.Session
Record = models.Record
Category = models.Category
User = models.User
Role = models.Role
AuditLog = models.AuditLog
insert_default_categories = models.insert_default_categories
record_user_activity = models.record_user_activity

# 确保数据库 `accounting.db` 存在
DB_PATH = os.path.join(BASE_DIR, "accounting.db")
if not os.path.exists(DB_PATH):
    print(f"⚠️ 警告: 未找到数据库文件 {DB_PATH}，将尝试创建...")
    models.init_db()  # 重新初始化数据库

# 计算 Vue 前端路径
DIST_DIR = os.path.join(BASE_DIR, "web_frontend/dist")
if not os.path.exists(DIST_DIR):  # 兼容 PyInstaller 打包后路径
    DIST_DIR = os.path.join(BASE_DIR, "../web_frontend/dist")

app = Flask(__name__, static_folder=DIST_DIR, static_url_path="/")
app.secret_key = os.getenv('SECRET_KEY', os.urandom(24).hex())  # 设置会话密钥
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # 会话超时时间：30分钟

# 配置会话安全
app.config['SESSION_COOKIE_SECURE'] = not DEBUG  # 生产环境使用HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # 防止JS访问cookie
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # 防止CSRF

# Configure CORS based on environment
if DEBUG:
    # In development, allow all origins for easier testing
    print("🔒 CORS: 开发模式 - 允许所有源")
    CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)
else:
    # In production, restrict origins for security
    allowed_origins = os.getenv('ALLOWED_ORIGINS', '*').split(',')
    print(f"🔒 CORS: 生产模式 - 允许来源: {allowed_origins}")
    CORS(app, resources={r"/*": {"origins": allowed_origins}}, supports_credentials=True)

# 添加预检请求处理以确保CORS正常工作
@app.route('/api/auth/register', methods=['OPTIONS'])
@app.route('/api/auth/login', methods=['OPTIONS'])
@app.route('/api/auth/verify', methods=['OPTIONS'])
@app.route('/api/auth/verify-email/<token>', methods=['OPTIONS'])  # 新增预检请求处理
def handle_auth_preflight():
    """处理认证相关的预检请求"""
    print("⭐ 收到认证相关的预检请求")
    response = jsonify({'status': 'ok'})
    response.headers.add('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    return response

# 发送邮件函数
def send_verification_email(email, token):
    """发送验证邮件"""
    # 从环境变量获取邮件配置
    smtp_server = os.getenv('SMTP_SERVER', 'smtp.example.com')
    smtp_port = int(os.getenv('SMTP_PORT', 587))
    smtp_user = os.getenv('SMTP_USER', 'user@example.com')
    smtp_password = os.getenv('SMTP_PASSWORD', 'password')
    sender_email = os.getenv('SENDER_EMAIL', 'noreply@example.com')
    
    # 构建验证URL
    base_url = os.getenv('BASE_URL', 'http://localhost:5002')
    verify_url = f"{base_url}/api/auth/verify-email/{token}"
    
    # 创建邮件内容
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = email
    msg['Subject'] = "验证您的账户 - 记账工具"
    
    # 邮件正文
    body = f"""
    <html>
    <body>
        <h2>感谢您注册记账工具！</h2>
        <p>请点击下面的链接验证您的邮箱地址：</p>
        <p><a href="{verify_url}">{verify_url}</a></p>
        <p>如果您没有注册该账户，请忽略此邮件。</p>
    </body>
    </html>
    """
    msg.attach(MIMEText(body, 'html'))
    
    try:
        # 连接SMTP服务器并发送邮件
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()  # 启用TLS加密
        server.login(smtp_user, smtp_password)
        server.send_message(msg)
        server.quit()
        print(f"✅ 验证邮件已发送至 {email}")
        return True
    except Exception as e:
        print(f"❌ 发送验证邮件失败: {e}")
        import traceback
        traceback.print_exc()
        return False

# 权限检查装饰器
def requires_permission(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # 优先检查Authorization头
            auth_header = request.headers.get('Authorization')
            user = None
            user_id = None
            user_role = None
            
            s = Session()
            try:
                if auth_header and auth_header.startswith('Bearer '):
                    token = auth_header[7:]  # 去掉'Bearer '前缀
                    # 使用token查找用户
                    user = s.query(User).filter_by(username=token).first()
                
                # 如果没有认证头或认证头无效，尝试从session中获取用户ID
                if not user and 'user_id' in session:
                    user_id = session.get('user_id')
                    # 重要：在会话过程中获取用户与角色
                    user = s.query(User).options(
                        # 预加载role关系
                        sqlalchemy.orm.joinedload(User.role)
                    ).filter_by(id=user_id).first()
                
                # 如果没有找到有效用户，返回未授权
                if not user or not user.is_active:
                    return jsonify({'success': False, 'message': '未授权访问'}), 401
                
                # 检查角色和权限
                if user.role:
                    user_role = user.role.name
                
                # 检查权限
                if permission == 'admin' and user_role != 'admin':
                    return jsonify({'success': False, 'message': '需要管理员权限'}), 403
                elif not user.has_permission(permission):
                    return jsonify({'success': False, 'message': '无权执行此操作'}), 403
                    
                # 更新会话活动时间
                if 'user_id' in session:
                    session.modified = True
                    
                # 调用原始视图函数，使用同一个会话
                return f(user, *args, **kwargs)
            finally:
                s.close()
        return decorated_function
    return decorator

# 检查会话超时的中间件
@app.before_request
def check_session_timeout():
    # 跳过OPTIONS请求和静态文件
    if request.method == 'OPTIONS' or request.path.startswith('/static/'):
        return
        
    # 如果用户已登录，检查会话活动时间
    if 'user_id' in session and 'last_activity' in session:
        last_activity = session.get('last_activity')
        if isinstance(last_activity, str):
            # 如果last_activity是字符串，则转换为datetime
            try:
                last_activity = datetime.fromisoformat(last_activity)
            except ValueError:
                # 如果转换失败，则重置会话
                session.clear()
                return
        
        # 确保没有时区信息
        if hasattr(last_activity, 'tzinfo') and last_activity.tzinfo is not None:
            # 去除时区信息
            last_activity = last_activity.replace(tzinfo=None)
            
        now = datetime.utcnow()  # 无时区信息的UTC时间
        
        # 如果最后活动时间超过会话超时时间，则清除会话
        timeout = timedelta(minutes=30)
        if now - last_activity > timeout:
            session.clear()
            if request.content_type == 'application/json':
                return jsonify({'success': False, 'message': '会话已过期，请重新登录', 'session_expired': True}), 401
                
    # 更新最后活动时间
    if 'user_id' in session:
        session['last_activity'] = datetime.utcnow().isoformat()  # 存储为ISO格式字符串

# ===== 用户认证 API =====
@app.route('/api/auth/register', methods=['POST'])
def register():
    """注册新用户"""
    print("⭐ 收到注册请求")
    try:
        data = request.json
        if not data:
            print("❌ 请求数据为空或格式不正确")
            return jsonify({'success': False, 'message': '请求数据为空或格式不正确'}), 400
            
        # 从请求中获取数据
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        given_name = data.get('givenName')
        family_name = data.get('familyName')
        phone = data.get('phone')
        role_name = data.get('role', 'individual')  # 默认为个人用户
        
        # If no username is provided, use email as username
        if not username and email:
            username = email
            
        print(f"📝 注册请求数据: email={email}, role={role_name}, password={'*' * len(password) if password else 'None'}")
        
        # 验证必填字段
        if not password or not email:
            print("❌ 邮箱和密码不能为空")
            return jsonify({'success': False, 'message': '邮箱和密码不能为空'}), 400
        
        # 简单验证邮箱格式
        if '@' not in email or '.' not in email:
            print(f"❌ 邮箱格式不正确: {email}")
            return jsonify({'success': False, 'message': '邮箱格式不正确'}), 400
            
        # 验证角色是否有效
        if role_name not in ['individual', 'business']:
            print(f"❌ 无效的角色类型: {role_name}")
            return jsonify({'success': False, 'message': '无效的角色类型'}), 400
            
        s = Session()
        try:
            # 检查用户名是否已存在
            existing_user = s.query(User).filter_by(username=username).first()
            if existing_user:
                print(f"❌ 用户名 {username} 已存在")
                return jsonify({'success': False, 'message': '用户名已存在'}), 400
                
            # 检查邮箱是否已存在
            existing_email = s.query(User).filter_by(email=email).first()
            if existing_email:
                print(f"❌ 邮箱 {email} 已被注册")
                return jsonify({'success': False, 'message': '该邮箱已被注册'}), 400
                
            # 获取对应的角色ID
            role = s.query(Role).filter_by(name=role_name).first()
            if not role:
                print(f"❌ 角色 {role_name} 不存在，将使用默认角色")
                # 如果角色不存在，尝试创建
                try:
                    if role_name == 'individual':
                        role = Role(name='individual', description='个人纳税人')
                    elif role_name == 'business':
                        role = Role(name='business', description='企业用户')
                    else:
                        role = Role(name='individual', description='个人纳税人')
                    s.add(role)
                    s.flush()  # 获取新角色的ID
                except Exception as e:
                    print(f"❌ 创建角色失败: {e}")
                    # 回退到使用默认角色
                    role = s.query(Role).filter_by(name='individual').first()
                    if not role:
                        print("❌ 默认角色不存在，请先初始化角色")
                        return jsonify({'success': False, 'message': '系统错误：角色未初始化'}), 500
                
            # 创建新用户
            new_user = User(username=username, email=email, role_id=role.id)
            
            # 设置其他用户字段
            if given_name:
                new_user.given_name = given_name
            if family_name:
                new_user.family_name = family_name
            if phone:
                new_user.phone = phone
                
            new_user.set_password(password)
            
            # 直接设置为已验证，跳过邮箱验证
            new_user.email_verified = True
            
            # 添加到数据库
            s.add(new_user)
            s.commit()
            
            print(f"✅ 用户 {username} 注册成功")
            return jsonify({
                'success': True, 
                'message': '注册成功，请直接登录',
            }), 201
                
        except Exception as e:
            s.rollback()
            print(f"❌ 注册失败 {username}: {e}")
            import traceback
            traceback.print_exc()  # 打印详细错误堆栈
            return jsonify({'success': False, 'message': f'注册失败: {str(e)}'}), 500
        finally:
            s.close()
    except Exception as e:
        print(f"❌ 处理注册请求时出错: {e}")
        import traceback
        traceback.print_exc()  # 打印详细错误堆栈
        return jsonify({'success': False, 'message': f'服务器错误: {str(e)}'}), 500

# 邮箱验证接口
@app.route('/api/auth/verify-email/<token>', methods=['GET'])
def verify_email(token):
    """验证用户邮箱"""
    print(f"⭐ 收到邮箱验证请求，令牌: {token}")
    s = Session()
    try:
        user = s.query(User).filter_by(verification_token=token).first()
        if not user:
            print("❌ 无效的验证令牌")
            return jsonify({'success': False, 'message': '无效的验证链接'}), 400
            
        # 更新验证状态
        user.email_verified = True
        user.verification_token = None  # 清除令牌，防止重复使用
        s.commit()
        
        print(f"✅ 用户 {user.username} 的邮箱已验证")
        
        # 返回HTML页面而不是JSON，用户体验更好
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>邮箱验证成功</title>
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
                <h1 class="success">邮箱验证成功！</h1>
                <p>您的账户已激活，现在可以登录并使用所有功能。</p>
                <a href="/" class="btn">返回登录</a>
            </div>
        </body>
        </html>
        """
        return html
    except Exception as e:
        s.rollback()
        print(f"❌ 验证邮箱失败: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': f'验证邮箱失败: {str(e)}'}), 500
    finally:
        s.close()
        
@app.route('/api/auth/login', methods=['POST'])
def login():
    """用户登录"""
    print("⭐ 收到登录请求")
    
    try:
        data = request.json
        if not data:
            return jsonify({'success': False, 'message': '无效的请求数据'}), 400
            
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            print("❌ 邮箱或密码为空")
            return jsonify({'success': False, 'message': '请提供邮箱和密码'}), 400
            
        s = Session()
        try:
            # 查找用户
            user = s.query(User).filter_by(email=email).first()
            
            if not user:
                print(f"❌ 邮箱 {email} 不存在")
                return jsonify({'success': False, 'message': '邮箱或密码错误'}), 401
                
            if not user.verify_password(password):
                print(f"❌ 用户 {email} 密码错误")
                return jsonify({'success': False, 'message': '邮箱或密码错误'}), 401
                
            # 将用户标记为已验证
            user.email_verified = True
            s.commit()
            
            # 设置会话
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role.name if user.role else None
            session['last_activity'] = datetime.utcnow().isoformat()  # 存储为ISO格式字符串
            session.permanent = True
            
            # 记录登录活动
            record_user_activity(s, user.id, 'login', f'User login - Email: {email}', request.remote_addr)
            
            # 登录成功，返回用户信息
            print(f"✅ 用户 {email} 登录成功")
            return jsonify({
                'success': True,
                'message': '登录成功',
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'role': user.role.name if user.role else None
                }
            }), 200
        except Exception as e:
            s.rollback()
            print(f"❌ 登录处理失败: {str(e)}")
            import traceback
            traceback.print_exc()
            return jsonify({'success': False, 'message': f'登录失败: {str(e)}'}), 500
        finally:
            s.close()
    except Exception as e:
        print(f"❌ 处理登录请求时出错: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': f'服务器错误: {str(e)}'}), 500

# 登出接口
@app.route('/api/auth/logout', methods=['POST'])
def logout():
    """用户登出"""
    print("⭐ 收到登出请求")
    
    # 记录登出活动
    if 'user_id' in session:
        user_id = session.get('user_id')
        email = session.get('username')
        s = Session()
        try:
            record_user_activity(s, user_id, 'logout', f'User logout - Email: {email}', request.remote_addr)
            s.commit()
        except Exception as e:
            print(f"❌ 记录登出活动失败: {e}")
        finally:
            s.close()
        
    # 清除会话
    session.clear()
    
    return jsonify({'success': True, 'message': '已成功登出'}), 200

# 重新发送验证邮件的接口
@app.route('/api/auth/resend-verification', methods=['POST'])
def resend_verification():
    """重新发送验证邮件"""
    print("⭐ 收到重新发送验证邮件请求")
    try:
        data = request.json
        if not data or 'email' not in data:
            return jsonify({'success': False, 'message': '请提供邮箱地址'}), 400
            
        email = data.get('email')
        
        s = Session()
        try:
            user = s.query(User).filter_by(email=email).first()
            
            if not user:
                # 为了安全，不透露邮箱是否存在
                return jsonify({'success': True, 'message': '如果该邮箱已注册，验证邮件将发送到该地址'}), 200
                
            if user.email_verified:
                return jsonify({'success': False, 'message': '该邮箱已验证，无需重新验证'}), 400
                
            # 生成新的验证令牌
            token = user.generate_verification_token()
            s.commit()
            
            # 发送验证邮件
            email_sent = send_verification_email(email, token)
            
            if email_sent:
                return jsonify({'success': True, 'message': '验证邮件已重新发送，请查收'}), 200
            else:
                return jsonify({'success': False, 'message': '发送验证邮件失败，请稍后再试'}), 500
                
        except Exception as e:
            s.rollback()
            print(f"❌ 重发验证邮件失败: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({'success': False, 'message': f'重发验证邮件失败: {str(e)}'}), 500
        finally:
            s.close()
    except Exception as e:
        print(f"❌ 处理重发验证邮件请求时出错: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': f'服务器错误: {str(e)}'}), 500

@app.route('/api/auth/verify', methods=['GET'])
def verify_user():
    """验证用户是否已登录（用于前端鉴权）"""
    # 如果使用会话，先检查会话中的用户信息
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
            print(f"❌ 会话验证失败: {e}")
        finally:
            s.close()
    
    # 回退到令牌验证（兼容旧版API）
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'success': False, 'message': '未授权访问'}), 401
        
    token = auth_header[7:]  # 去掉'Bearer '前缀
    
    s = Session()
    try:
        user = s.query(User).filter_by(username=token).first()  # 简化示例，实际应使用JWT
        if not user or not user.is_active:
            return jsonify({'success': False, 'message': '未授权访问'}), 401
            
        # 更新会话（即使通过令牌验证，也为用户建立会话）
        session['user_id'] = user.id
        session['username'] = user.username
        session['role'] = user.role.name if user.role else None
        session['last_activity'] = datetime.utcnow().isoformat()  # 存储为ISO格式字符串
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
        print(f"❌ 验证失败: {e}")
        return jsonify({'success': False, 'message': f'验证失败: {str(e)}'}), 500
    finally:
        s.close()

# 审计日志查询（仅限管理员）
@app.route('/api/admin/audit-logs', methods=['GET'])
@requires_permission('admin')
def get_audit_logs(current_user):
    """获取审计日志记录（需要管理员权限）"""
    print("⭐ 收到审计日志查询请求")
    
    # 分页参数
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    # 过滤参数
    user_id = request.args.get('user_id', type=int)
    action = request.args.get('action')
    from_date = request.args.get('from_date')
    to_date = request.args.get('to_date')
    user_role = request.args.get('user_role')
    
    s = Session()
    try:
        # 预加载User和Role关系以避免懒加载错误
        query = s.query(AuditLog).options(
            sqlalchemy.orm.joinedload(AuditLog.user).joinedload(User.role)
        )
        
        # 应用过滤条件
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
                to_datetime = to_datetime + timedelta(days=1)  # 包含当天
                query = query.filter(AuditLog.timestamp < to_datetime)
            except ValueError:
                pass
        # 按用户角色筛选
        if user_role:
            query = query.join(AuditLog.user).join(User.role).filter(Role.name == user_role)
                
        # 避免使用user_role列进行计数查询
        total = s.query(sqlalchemy.func.count(AuditLog.id)).scalar()
        
        # 排序和分页
        logs = query.order_by(AuditLog.timestamp.desc()).offset((page-1)*per_page).limit(per_page).all()
        
        result = []
        for log in logs:
            # 安全处理用户角色,避免空引用错误
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
        
        # 记录审计日志
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
        print(f"❌ 获取审计日志失败: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': f'获取审计日志失败: {str(e)}'}), 500
    finally:
        s.close()

# 导出审计日志为PDF
@app.route('/api/admin/export-audit-logs/pdf', methods=['GET'])
@requires_permission('admin')
def export_audit_logs_pdf(current_user):
    """导出审计日志为PDF（需要管理员权限）"""
    print("⭐ 收到导出审计日志为PDF请求")
    
    # 过滤参数
    user_id = request.args.get('user_id', type=int)
    action = request.args.get('action')
    from_date = request.args.get('from_date')
    to_date = request.args.get('to_date')
    user_role = request.args.get('user_role')
    
    s = Session()
    try:
        # 使用与get_audit_logs相同的查询逻辑
        query = s.query(AuditLog).options(
            sqlalchemy.orm.joinedload(AuditLog.user).joinedload(User.role)
        )
        
        # 应用过滤条件
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
                to_datetime = to_datetime + timedelta(days=1)  # 包含当天
                query = query.filter(AuditLog.timestamp < to_datetime)
            except ValueError:
                pass
        # 按用户角色筛选
        if user_role:
            query = query.join(AuditLog.user).join(User.role).filter(Role.name == user_role)
                
        # 获取所有符合条件的日志，但最多不超过1000条
        logs = query.order_by(AuditLog.timestamp.desc()).limit(1000).all()
        
        # 记录审计日志
        record_user_activity(s, current_user.id, 'export_audit_logs', f'Exported audit logs to PDF', request.remote_addr)
        
        result = []
        for log in logs:
            # 安全处理用户角色
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
        
        # 这里我们直接返回JSON，前端负责生成PDF
        # 在实际生产环境中，可以在后端生成PDF并返回文件流
        return jsonify({
            'success': True,
            'logs': result
        }), 200
    except Exception as e:
        print(f"❌ 导出审计日志为PDF失败: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': f'导出审计日志为PDF失败: {str(e)}'}), 500
    finally:
        s.close()

# 导出审计日志为CSV
@app.route('/api/admin/export-audit-logs/csv', methods=['GET'])
@requires_permission('admin')
def export_audit_logs_csv(current_user):
    """导出审计日志为CSV（需要管理员权限）"""
    print("⭐ 收到导出审计日志为CSV请求")
    
    # 过滤参数
    user_id = request.args.get('user_id', type=int)
    action = request.args.get('action')
    from_date = request.args.get('from_date')
    to_date = request.args.get('to_date')
    user_role = request.args.get('user_role')
    
    s = Session()
    try:
        # 使用与get_audit_logs相同的查询逻辑
        query = s.query(AuditLog).options(
            sqlalchemy.orm.joinedload(AuditLog.user).joinedload(User.role)
        )
        
        # 应用过滤条件
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
                to_datetime = to_datetime + timedelta(days=1)  # 包含当天
                query = query.filter(AuditLog.timestamp < to_datetime)
            except ValueError:
                pass
        # 按用户角色筛选
        if user_role:
            query = query.join(AuditLog.user).join(User.role).filter(Role.name == user_role)
                
        # 获取所有符合条件的日志，但最多不超过5000条
        logs = query.order_by(AuditLog.timestamp.desc()).limit(5000).all()
        
        # 记录审计日志
        record_user_activity(s, current_user.id, 'export_audit_logs', f'Exported audit logs to CSV', request.remote_addr)
        
        result = []
        for log in logs:
            # 安全处理用户角色
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
        
        # 这里我们直接返回JSON，前端负责生成CSV
        # 在实际生产环境中，可以在后端生成CSV并返回文件流
        return jsonify({
            'success': True,
            'logs': result
        }), 200
    except Exception as e:
        print(f"❌ 导出审计日志为CSV失败: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': f'导出审计日志为CSV失败: {str(e)}'}), 500
    finally:
        s.close()

# ===== 记账 API =====
@app.route('/api/add_record', methods=['POST'])
@requires_permission('add_record')
def add_record(current_user):
    """添加记账记录"""
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
        
        # 记录操作到审计日志
        record_user_activity(s, current_user.id, 'add_record', f"Added record ID: {record.id}", request.remote_addr)
        
        return jsonify({'message': '记录添加成功', 'record_id': record.id}), 200
    except Exception as e:
        s.rollback()
        return jsonify({'error': str(e)}), 400
    finally:
        s.close()

@app.route('/api/get_records', methods=['GET'])
@requires_permission('view_records')
def get_records(current_user):
    """获取所有记账记录"""
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
        
        # 记录审计日志
        record_user_activity(s, current_user.id, 'view_records', "Viewed all accounting records", request.remote_addr)
        
        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400
    finally:
        s.close()

@app.route('/api/delete_record/<int:record_id>', methods=['DELETE'])
@requires_permission('delete_record')
def delete_record(current_user, record_id):
    """删除一条记账记录"""
    s = Session()
    try:
        print(f"🔍 尝试删除记录 ID: {record_id}")  # ✅ 添加调试信息

        record = s.query(Record).filter_by(id=record_id).first()
        if not record:
            print(f"❌ 记录 {record_id} 不存在！")  # ✅ 添加调试信息
            return jsonify({'error': '记录不存在'}), 404
        
        s.delete(record)
        s.commit()
        
        # 记录审计日志
        record_user_activity(s, current_user.id, 'delete_record', f"Deleted record ID: {record_id}", request.remote_addr)
        
        print(f"✅ 记录 {record_id} 删除成功！")  # ✅ 添加调试信息
        return jsonify({'message': '记录删除成功'}), 200
    except Exception as e:
        s.rollback()
        print(f"❌ 删除失败: {e}")  # ✅ 添加调试信息
        return jsonify({'error': str(e)}), 400
    finally:
        s.close()

@app.route('/api/update_record/<int:record_id>', methods=['PUT'])
@requires_permission('update_record')
def update_record(current_user, record_id):
    data = request.json
    s = Session()
    try:
        print(f"🔍 接收到更新请求，记录ID: {record_id}, 数据: {data}")
        
        record = s.query(Record).filter_by(id=record_id).first()
        if not record:
            print(f"❌ 记录 {record_id} 不存在！")
            return jsonify({'error': '记录不存在'}), 404
            
        # 处理日期
        if 'date' in data:
            try:
                record.date = datetime.strptime(data.get('date'), '%Y-%m-%d')
                print(f"✅ 日期更新为: {record.date}")
            except ValueError as e:
                print(f"❌ 日期格式错误: {e}")
                return jsonify({'error': f'日期格式错误: {e}'}), 400
            
        # 处理金额
        if 'amount' in data:
            try:
                record.amount = float(data.get('amount'))
                print(f"✅ 金额更新为: {record.amount}")
            except ValueError as e:
                print(f"❌ 金额格式错误: {e}")
                return jsonify({'error': f'金额格式错误: {e}'}), 400
            
        # 处理类别ID
        if 'category_id' in data and data['category_id'] is not None:
            record.category_id = data.get('category_id')
            print(f"✅ 类别ID更新为: {record.category_id}")
        # 如果前端传递了类别名称，通过名称查找对应的ID
        elif 'category' in data and data['category']:
            try:
                category = s.query(Category).filter_by(name=data['category']).first()
                if category:
                    record.category_id = category.id
                    print(f"✅ 通过名称 '{data['category']}' 找到类别ID: {category.id}")
                else:
                    # 如果类别不存在，则创建新类别
                    new_category = Category(name=data['category'])
                    s.add(new_category)
                    s.flush()  # 获取新类别的ID
                    record.category_id = new_category.id
                    print(f"✅ 创建新类别 '{data['category']}', ID: {new_category.id}")
            except Exception as e:
                print(f"❌ 处理类别时出错: {e}")
                return jsonify({'error': f'处理类别时出错: {e}'}), 400
                
        # 处理备注
        if 'remarks' in data:
            record.remarks = data.get('remarks')
            print(f"✅ 备注更新为: {record.remarks}")
            
        s.commit()
        
        # 记录审计日志
        record_user_activity(s, current_user.id, 'update_record', f"Updated record ID: {record_id}", request.remote_addr)
        
        print(f"✅ 记录 {record_id} 更新成功!")
        return jsonify({'message': '记录更新成功', 'record_id': record_id}), 200
    except Exception as e:
        s.rollback()
        print(f"❌ 更新失败: {e}")
        import traceback
        traceback.print_exc()  # 打印详细错误堆栈
        return jsonify({'error': str(e)}), 400
    finally:
        s.close()

@app.route('/api/get_categories', methods=['GET'])
def get_categories():
    """获取所有类别"""
    s = Session()
    try:
        categories = s.query(Category).all()
        result = [{'id': cat.id, 'name': cat.name} for cat in categories]
        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400
    finally:
        s.close()

# 用户管理API（仅限管理员）
@app.route('/api/admin/users', methods=['GET'])
@requires_permission('admin')
def get_users(current_user):
    """获取所有用户（需要管理员权限）"""
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
        
        # 记录审计日志
        record_user_activity(s, current_user.id, 'view_users', "Viewed all users list", request.remote_addr)
        
        return jsonify({'success': True, 'users': result}), 200
    except Exception as e:
        print(f"❌ 获取用户列表失败: {e}")
        return jsonify({'success': False, 'message': f'获取用户失败: {str(e)}'}), 500
    finally:
        s.close()

@app.route('/api/admin/user/<int:user_id>', methods=['PUT'])
@requires_permission('admin')
def update_user(current_user, user_id):
    """更新用户信息（需要管理员权限）"""
    data = request.json
    s = Session()
    try:
        user = s.query(User).get(user_id)
        if not user:
            return jsonify({'success': False, 'message': '用户不存在'}), 404
            
        # 记录修改前的状态
        old_status = {
            'is_active': user.is_active,
            'role': user.role.name if user.role else None,
            'email_verified': user.email_verified
        }
        
        # 更新用户状态
        if 'is_active' in data:
            user.is_active = data['is_active']
            
        if 'email_verified' in data:
            user.email_verified = data['email_verified']
            
        if 'role' in data and data['role']:
            role = s.query(Role).filter_by(name=data['role']).first()
            if role:
                user.role_id = role.id
        
        s.commit()
        
        # 记录审计日志
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
            'message': '用户信息已更新',
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
        print(f"❌ 更新用户失败: {e}")
        return jsonify({'success': False, 'message': f'更新用户失败: {str(e)}'}), 500
    finally:
        s.close()

# ===== Vue 前端托管 =====
@app.route("/")
def serve_vue():
    """返回 Vue 前端的 index.html"""
    return send_from_directory(app.static_folder, "index.html")

@app.route("/<path:path>")
def serve_static(path):
    """返回 Vue 其他静态文件（JS、CSS、图片等）"""
    return send_from_directory(app.static_folder, path)

# ===== 端口占用检查 =====
def is_port_in_use(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('127.0.0.1', port)) == 0

# 添加保存草稿的API端点
@app.route('/api/save_draft', methods=['POST'])
def save_draft():
    """保存表单草稿到数据库"""
    print("⭐ 收到保存草稿请求")
    
    # 检查用户是否已登录
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': '请先登录'}), 401
    
    try:
        # 获取请求数据
        data = request.json
        if not data:
            return jsonify({'success': False, 'message': '无效的请求数据'}), 400
            
        # 获取当前用户
        s = Session()
        user_id = session.get('user_id')
        user = s.query(User).filter_by(id=user_id).first()
        
        if not user:
            return jsonify({'success': False, 'message': '用户不存在'}), 404
            
        # 检查是新建草稿还是更新现有草稿
        form_id = data.get('form_id')
        
        # 创建或更新草稿表单
        from models import TaxForm
        
        if form_id and str(form_id).startswith("temp-") or not form_id:
            # 新建草稿，保存临时ID用于跟踪
            temp_id = form_id if form_id else None
            
            new_form = TaxForm(
                user_id=user_id,
                temp_id=temp_id,  # 保存前端临时ID
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
            
            # 记录用户活动
            record_user_activity(s, user_id, 'DRAFT_SAVE', f'Saved draft form - ID: {new_form.id}, Type: {data.get("declaration_type")}, Amount: {data.get("price")}', request.remote_addr)
            
            # 返回生成的ID和临时ID
            return jsonify({
                'success': True,
                'message': '草稿保存成功',
                'id': new_form.id,
                'temp_id': temp_id
            })
        else:
            # 更新现有草稿
            existing_form = s.query(TaxForm).filter_by(id=form_id, user_id=user_id).first()
            if not existing_form:
                return jsonify({'success': False, 'message': '表单不存在或无权限'}), 404
                
            # 更新字段
            existing_form.date = data.get('date')
            existing_form.declaration_type = data.get('declaration_type')
            existing_form.address = data.get('address')
            existing_form.declaration_name = data.get('declaration_name')
            existing_form.price = data.get('price', 0)
            existing_form.other_info = data.get('other_info', '')
            existing_form.updated_at = datetime.utcnow()
            
            s.commit()
            
            # 记录用户活动
            record_user_activity(s, user_id, 'DRAFT_UPDATE', f'Updated draft form - ID: {existing_form.id}, Type: {data.get("declaration_type")}, Amount: {data.get("price")}', request.remote_addr)
            
            return jsonify({
                'success': True,
                'message': '草稿更新成功',
                'id': existing_form.id,
                'temp_id': existing_form.temp_id
            })
            
    except Exception as e:
        print(f"❌ 保存草稿失败: {e}")
        import traceback
        traceback.print_exc()
        s.rollback()
        return jsonify({'success': False, 'message': f'保存草稿失败: {str(e)}'}), 500
    finally:
        s.close()

# 添加提交税务表单的API端点
@app.route('/api/submit_tax_form', methods=['POST'])
def submit_tax_form():
    """提交税务表单到数据库"""
    print("⭐ 收到提交税务表单请求")
    
    # 检查用户是否已登录
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': '请先登录'}), 401
    
    try:
        # 获取请求数据
        data = request.json
        if not data:
            return jsonify({'success': False, 'message': '无效的请求数据'}), 400
            
        # 获取当前用户
        s = Session()
        user_id = session.get('user_id')
        user = s.query(User).filter_by(id=user_id).first()
        
        if not user:
            return jsonify({'success': False, 'message': '用户不存在'}), 404
            
        # 检查是否从现有草稿提交
        form_id = data.get('form_id')
        
        from models import TaxForm
        
        if form_id and not str(form_id).startswith("temp-"):
            # 更新现有表单
            existing_form = s.query(TaxForm).filter_by(id=form_id, user_id=user_id).first()
            if not existing_form:
                return jsonify({'success': False, 'message': '表单不存在或无权限'}), 404
                
            # 更新字段
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
            
            # 记录用户活动
            record_user_activity(s, user_id, 'FORM_SUBMIT', f'Submitted form - ID: {existing_form.id}, Type: {data.get("declaration_type")}, Amount: {data.get("price")}, Date: {data.get("date")}', request.remote_addr)
            
            return jsonify({
                'success': True,
                'message': '表单提交成功',
                'id': existing_form.id,
                'temp_id': existing_form.temp_id
            })
        else:
            # 创建新表单，保存临时ID
            temp_id = form_id if form_id else None
            
            new_form = TaxForm(
                user_id=user_id,
                temp_id=temp_id,  # 保存前端临时ID
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
            
            # 记录用户活动
            record_user_activity(s, user_id, 'FORM_SUBMIT', f'Submitted new form - ID: {new_form.id}, Type: {data.get("declaration_type")}, Amount: {data.get("price")}, Date: {data.get("date")}', request.remote_addr)
            
            # 返回生成的ID和临时ID
            return jsonify({
                'success': True,
                'message': '表单提交成功',
                'id': new_form.id,
                'temp_id': temp_id
            })
            
    except Exception as e:
        print(f"❌ 提交表单失败: {e}")
        import traceback
        traceback.print_exc()
        s.rollback()
        return jsonify({'success': False, 'message': f'提交表单失败: {str(e)}'}), 500
    finally:
        s.close()
        
# 查询所有税务表单
@app.route('/api/get_tax_forms', methods=['GET'])
def get_tax_forms():
    """获取当前用户的所有税务表单"""
    print("⭐ 收到获取税务表单请求")
    
    # 检查用户是否已登录
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': '请先登录'}), 401
    
    try:
        # 获取当前用户
        s = Session()
        user_id = session.get('user_id')
        
        # 查询用户的所有表单
        from models import TaxForm
        forms = s.query(TaxForm).filter_by(user_id=user_id).order_by(TaxForm.updated_at.desc()).all()
        
        # 转换为JSON格式
        forms_data = []
        for form in forms:
            forms_data.append({
                'id': form.id,
                'temp_id': form.temp_id,  # 包含临时ID
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
        
        # 记录用户查看表单历史的活动
        record_user_activity(s, user_id, 'VIEW_FORMS', f'Viewed form history - {len(forms_data)} records', request.remote_addr)
        
        return jsonify({
            'success': True,
            'forms': forms_data
        })
            
    except Exception as e:
        print(f"❌ 获取表单失败: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': f'获取表单失败: {str(e)}'}), 500
    finally:
        s.close()

if __name__ == '__main__':
    if is_port_in_use(PORT):
        print(f"⚠️  端口 {PORT} 已被占用，请先释放端口或使用其他端口！")
        sys.exit(1)

    print(f"✅ Running Flask on port {PORT}, Debug mode: {DEBUG}")
    app.run(host='0.0.0.0', port=PORT, debug=DEBUG, use_reloader=False)