from sqlalchemy import create_engine, Column, Integer, String, Float, Date, ForeignKey, Boolean, DateTime
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
import hashlib
import os
import secrets  # For generating secure tokens
import datetime

# 连接 SQLite 数据库（使用 accounting.db）
DATABASE_URL = "sqlite:///accounting.db"  
# Increase the timeout to 30 seconds (default is often 5)
engine = create_engine(DATABASE_URL, echo=True, connect_args={"timeout": 30})

# ORM 基类
Base = declarative_base()

# SQLAlchemy Session
Session = sessionmaker(bind=engine)

# 分类表
class Category(Base):
    __tablename__ = 'categories'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, unique=True, nullable=False)
    
    # 反向关系：一个分类对应多个记账记录
    records = relationship("Record", back_populates="category")

# 记账记录表
class Record(Base):
    __tablename__ = 'records'

    id = Column(Integer, primary_key=True, autoincrement=True)
    date = Column(Date, nullable=False)
    amount = Column(Float, nullable=False)
    category_id = Column(Integer, ForeignKey('categories.id'))
    remarks = Column(String)

    # 关联分类表
    category = relationship("Category", back_populates="records")

# 角色表
class Role(Base):
    __tablename__ = 'roles'
    
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, nullable=False)
    description = Column(String)
    
    # 一个角色对应多个用户
    users = relationship("User", back_populates="role")

# 审计日志表
class AuditLog(Base):
    __tablename__ = 'audit_logs'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    action = Column(String, nullable=False)  # login, logout, record_create, etc.
    ip_address = Column(String)
    details = Column(String)  # 其他详细信息
    user_role = Column(String)  # 用户角色
    
    user = relationship("User")

# 税务表单模型
class TaxForm(Base):
    __tablename__ = 'tax_forms'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    temp_id = Column(String, nullable=True)  # 存储前端临时ID，用于跟踪
    date = Column(String, nullable=False)  # 表单日期
    declaration_type = Column(String, nullable=False)  # 申报类型
    address = Column(String, nullable=False)  # 地址
    declaration_name = Column(String, nullable=False)  # 申报名称
    price = Column(Float, nullable=False, default=0)  # 金额
    other_info = Column(String, nullable=True)  # 其他信息
    status = Column(String, nullable=False, default='draft')  # 状态：draft, submitted, failed
    created_at = Column(DateTime, default=datetime.datetime.utcnow)  # 创建时间
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)  # 更新时间
    submitted_at = Column(DateTime, nullable=True)  # 提交时间
    
    # 关联用户
    user = relationship("User", backref="tax_forms")
    
    def to_dict(self):
        """转换为字典格式便于JSON序列化"""
        return {
            'id': self.id,
            'temp_id': self.temp_id,
            'user_id': self.user_id,
            'date': self.date,
            'declaration_type': self.declaration_type,
            'address': self.address,
            'declaration_name': self.declaration_name,
            'price': self.price,
            'other_info': self.other_info,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'submitted_at': self.submitted_at.isoformat() if self.submitted_at else None
        }

# 用户表
class User(Base):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, nullable=False)  # 新增邮箱字段
    password_hash = Column(String, nullable=False)
    salt = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    email_verified = Column(Boolean, default=False)  # 邮箱验证状态
    verification_token = Column(String, nullable=True)  # 验证令牌
    role_id = Column(Integer, ForeignKey('roles.id'))  # 用户角色
    # 添加个人信息字段
    given_name = Column(String, nullable=True)
    family_name = Column(String, nullable=True)
    phone = Column(String, nullable=True)
    
    # 关系
    role = relationship("Role", back_populates="users")
    audit_logs = relationship("AuditLog", backref="logged_user")
    
    def set_password(self, password):
        """设置密码，使用随机盐值和SHA-256哈希"""
        self.salt = os.urandom(16).hex()
        self.password_hash = self._hash_password(password, self.salt)
    
    def verify_password(self, password):
        """验证密码是否正确"""
        return self.password_hash == self._hash_password(password, self.salt)
    
    def generate_verification_token(self):
        """生成邮箱验证令牌"""
        self.verification_token = secrets.token_urlsafe(32)
        return self.verification_token
    
    def has_permission(self, permission):
        """检查用户是否有指定权限"""
        if not self.role:
            return False
            
        # 管理员拥有所有权限
        if self.role.name == 'admin':
            return True
            
        # 确保用户邮箱已验证
        if not self.email_verified:
            return False
            
        # 根据角色和权限类型判断
        if self.role.name in ['individual', 'business']:
            # 所有已验证用户都可以执行的操作
            if permission in ['view_records', 'add_record', 'update_record', 'delete_record']:
                return True
                
        # 企业用户特有权限
        if self.role.name == 'business' and permission in ['manage_employees', 'view_reports']:
            return True
            
        return False
    
    @staticmethod
    def _hash_password(password, salt):
        """使用盐值哈希密码"""
        return hashlib.sha256((password + salt).encode()).hexdigest()

# 插入默认分类
def insert_default_categories(session):
    """初始化默认分类"""
    default_categories = ['餐饮', '话费', '理发', '交通', '洗衣', '超市购物', '零钱', '房租']
    
    existing_categories = {c.name for c in session.query(Category).all()}
    print("数据库已有类别:", existing_categories)  # 调试输出

    for name in default_categories:
        if name not in existing_categories:
            print(f"插入类别: {name}")  # 调试输出
            session.add(Category(name=name))
    
    session.commit()

def init_roles(session):
    """初始化角色"""
    roles = [
        {'name': 'individual', 'description': '个人纳税人'},
        {'name': 'business', 'description': '企业用户'},
        {'name': 'admin', 'description': '系统管理员'}
    ]
    
    for role_data in roles:
        if not session.query(Role).filter_by(name=role_data['name']).first():
            print(f"创建角色: {role_data['name']}")
            session.add(Role(**role_data))
    
    session.commit()

def record_user_activity(session, user_id, action, details=None, ip_address=None):
    """记录用户活动到审计日志"""
    try:
        # 获取用户角色
        user_role = None
        try:
            user = session.query(User).filter_by(id=user_id).first()
            if user and user.role:
                user_role = user.role.name
        except Exception as e:
            print(f"获取用户角色失败: {e}")
        
        log = AuditLog(
            user_id=user_id,
            action=action,
            ip_address=ip_address,
            details=details,
            user_role=user_role,
            timestamp=datetime.datetime.utcnow()
        )
        session.add(log)
        session.commit()
        return True
    except Exception as e:
        session.rollback()
        print(f"记录活动失败: {e}")
        return False

# 创建表
def init_db():
    """初始化数据库"""
    # 如果表已存在，先删除所有表
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with Session() as session:
        # 初始化角色
        init_roles(session)
        # 初始化分类
        insert_default_categories(session)
        # 创建默认管理员账户（如果不存在）
        admin_role = session.query(Role).filter_by(name='admin').first()
        if not admin_role:
            print("创建管理员角色")
            admin_role = Role(name='admin', description='系统管理员')
            session.add(admin_role)
            session.flush()
            
        if not session.query(User).filter_by(username='sysadmin').first():
            admin = User(
                username='sysadmin', 
                email='admin@accounting.com', 
                role_id=admin_role.id,
                given_name='System',
                family_name='Administrator',
                phone='+61400000000'
            )
            admin.set_password('Admin123$')
            admin.email_verified = True  # 默认管理员账户邮箱已验证
            session.add(admin)
            session.commit()

# 运行数据库初始化
if __name__ == "__main__":
    init_db()