from sqlalchemy import create_engine, Column, Integer, String, Float, Date, ForeignKey, Boolean, DateTime
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
import hashlib
import os
import secrets  # For generating secure tokens
import datetime

# Connect to SQLite database (using accounting.db)
DATABASE_URL = "sqlite:///accounting.db"  
# Increase the timeout to 30 seconds (default is often 5)
engine = create_engine(DATABASE_URL, echo=True, connect_args={"timeout": 30})

# ORM base class
Base = declarative_base()

# SQLAlchemy Session
Session = sessionmaker(bind=engine)

# Category table
class Category(Base):
    __tablename__ = 'categories'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, unique=True, nullable=False)
    
    # Reverse relationship: one category corresponds to multiple records
    records = relationship("Record", back_populates="category")

# Accounting records table
class Record(Base):
    __tablename__ = 'records'

    id = Column(Integer, primary_key=True, autoincrement=True)
    date = Column(Date, nullable=False)
    amount = Column(Float, nullable=False)
    category_id = Column(Integer, ForeignKey('categories.id'))
    remarks = Column(String)

    # Associated with category table
    category = relationship("Category", back_populates="records")

# Role table
class Role(Base):
    __tablename__ = 'roles'
    
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, nullable=False)
    description = Column(String)
    
    # One role corresponds to multiple users
    users = relationship("User", back_populates="role")

# Audit log table
class AuditLog(Base):
    __tablename__ = 'audit_logs'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    action = Column(String, nullable=False)  # login, logout, record_create, etc.
    ip_address = Column(String)
    details = Column(String)  # Other detailed information
    user_role = Column(String)  # User role
    
    user = relationship("User")

# Tax form model
class TaxForm(Base):
    __tablename__ = 'tax_forms'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    temp_id = Column(String, nullable=True)  # Store frontend temporary ID for tracking
    date = Column(String, nullable=False)  # Form date
    declaration_type = Column(String, nullable=False)  # Declaration type
    address = Column(String, nullable=False)  # Address
    declaration_name = Column(String, nullable=False)  # Declaration name
    price = Column(Float, nullable=False, default=0)  # Amount
    other_info = Column(String, nullable=True)  # Other information
    status = Column(String, nullable=False, default='draft')  # Status: draft, submitted, failed
    created_at = Column(DateTime, default=datetime.datetime.utcnow)  # Creation time
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)  # Update time
    submitted_at = Column(DateTime, nullable=True)  # Submission time
    
    # User association
    user = relationship("User", backref="tax_forms")
    
    def to_dict(self):
        """Convert to dictionary format for JSON serialization"""
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

# User table
class User(Base):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, nullable=False)  # Email field
    password_hash = Column(String, nullable=False)
    salt = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    email_verified = Column(Boolean, default=False)  # Email verification status
    verification_token = Column(String, nullable=True)  # Verification token
    role_id = Column(Integer, ForeignKey('roles.id'))  # User role
    # Additional personal information fields
    given_name = Column(String, nullable=True)
    family_name = Column(String, nullable=True)
    phone = Column(String, nullable=True)
    
    # Relationships
    role = relationship("Role", back_populates="users")
    audit_logs = relationship("AuditLog", backref="logged_user")
    
    def set_password(self, password):
        """Set password using random salt and SHA-256 hash"""
        self.salt = os.urandom(16).hex()
        self.password_hash = self._hash_password(password, self.salt)
    
    def verify_password(self, password):
        """Verify if password is correct"""
        return self.password_hash == self._hash_password(password, self.salt)
    
    def generate_verification_token(self):
        """Generate email verification token"""
        self.verification_token = secrets.token_urlsafe(32)
        return self.verification_token
    
    def has_permission(self, permission):
        """Check if user has specified permission"""
        if not self.role:
            return False
            
        # Administrators have all permissions
        if self.role.name == 'admin':
            return True
            
        # Ensure user email is verified
        if not self.email_verified:
            return False
            
        # Judge based on role and permission type
        if self.role.name in ['individual', 'business']:
            # Operations that all verified users can perform
            if permission in ['view_records', 'add_record', 'update_record', 'delete_record']:
                return True
                
        # Business user specific permissions
        if self.role.name == 'business' and permission in ['manage_employees', 'view_reports']:
            return True
            
        return False
    
    @staticmethod
    def _hash_password(password, salt):
        """Hash password with salt"""
        return hashlib.sha256((password + salt).encode()).hexdigest()

# Insert default categories
def insert_default_categories(session):
    """Initialize default categories"""
    default_categories = ['Dining', 'Phone Bill', 'Haircut', 'Transportation', 'Laundry', 'Supermarket Shopping', 'Petty Cash', 'Rent']
    
    existing_categories = {c.name for c in session.query(Category).all()}
    print("Existing categories in database:", existing_categories)  # Debug output

    for name in default_categories:
        if name not in existing_categories:
            print(f"Inserting category: {name}")  # Debug output
            session.add(Category(name=name))
    
    session.commit()

def init_roles(session):
    """Initialize roles"""
    roles = [
        {'name': 'individual', 'description': 'Individual Taxpayer'},
        {'name': 'business', 'description': 'Business User'},
        {'name': 'admin', 'description': 'System Administrator'}
    ]
    
    for role_data in roles:
        if not session.query(Role).filter_by(name=role_data['name']).first():
            print(f"Creating role: {role_data['name']}")
            session.add(Role(**role_data))
    
    session.commit()

def record_user_activity(session, user_id, action, details=None, ip_address=None):
    """Record user activity to audit log"""
    try:
        # Get user role
        user_role = None
        try:
            user = session.query(User).filter_by(id=user_id).first()
            if user and user.role:
                user_role = user.role.name
        except Exception as e:
            print(f"Failed to get user role: {e}")
        
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
        print(f"Failed to record activity: {e}")
        return False

# Create tables
def init_db():
    """Initialize database"""
    # If tables already exist, delete all tables first
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with Session() as session:
        # Initialize roles
        init_roles(session)
        # Initialize categories
        insert_default_categories(session)
        # Create default admin account (if not exists)
        admin_role = session.query(Role).filter_by(name='admin').first()
        if not admin_role:
            print("Creating admin role")
            admin_role = Role(name='admin', description='System Administrator')
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
            admin.email_verified = True  # Default admin account email is verified
            session.add(admin)
            session.commit()

# Run database initialization
if __name__ == "__main__":
    init_db()