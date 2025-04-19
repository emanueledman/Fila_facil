from sqlalchemy import Column, Integer, String, Float, Time, Boolean, DateTime, ForeignKey, Enum, Index, Text
from sqlalchemy.orm import relationship
import enum
from app import db
from datetime import datetime
import bcrypt

# Enums existentes
class UserRole(enum.Enum):
    USER = "user"
    DEPARTMENT_ADMIN = "dept_admin"
    INSTITUTION_ADMIN = "inst_admin"
    SYSTEM_ADMIN = "sys_admin"

class Weekday(enum.Enum):
    MONDAY = "Monday"
    TUESDAY = "Tuesday"
    WEDNESDAY = "Wednesday"
    THURSDAY = "Thursday"
    FRIDAY = "Friday"
    SATURDAY = "Saturday"
    SUNDAY = "Sunday"

# Nova tabela para categorias de serviços
class ServiceCategory(db.Model):
    __tablename__ = 'service_category'
    id = Column(String(36), primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    parent_id = Column(String(36), ForeignKey('service_category.id'), nullable=True, index=True)
    description = Column(Text, nullable=True)
    
    parent = relationship('ServiceCategory', remote_side=[id], backref='subcategories')
    
    def __repr__(self):
        return f'<ServiceCategory {self.name}>'

# Nova tabela para tags de serviços
class ServiceTag(db.Model):
    __tablename__ = 'service_tag'
    id = Column(String(36), primary_key=True, index=True)
    tag = Column(String(50), nullable=False, index=True)
    queue_id = Column(String(36), ForeignKey('queue.id'), nullable=False, index=True)
    
    queue = relationship('Queue', backref=db.backref('tags', lazy='dynamic'))
    
    def __repr__(self):
        return f'<ServiceTag {self.tag} for Queue {self.queue_id}>'

# Nova tabela para filiais
class Branch(db.Model):
    __tablename__ = 'branch'
    id = Column(String(36), primary_key=True, index=True)
    institution_id = Column(String(36), ForeignKey('institution.id'), nullable=False, index=True)
    name = Column(String(100), nullable=False)
    location = Column(String(200))
    neighborhood = Column(String(100), nullable=True)  # Ex.: Talatona, Kilamba
    latitude = Column(Float)
    longitude = Column(Float)
    
    institution = relationship('Institution', backref=db.backref('branches', lazy='dynamic'))
    
    def __repr__(self):
        return f'<Branch {self.name} of {self.institution.name}>'

# Ajustes nas tabelas existentes
class Institution(db.Model):
    __tablename__ = 'institution'
    id = Column(String(36), primary_key=True, index=True)
    name = Column(String(100), nullable=False)  # Ex.: Banco BIC
    description = Column(Text, nullable=True)
    
    def __repr__(self):
        return f'<Institution {self.name}>'

class Department(db.Model):
    __tablename__ = 'department'
    id = Column(String(36), primary_key=True, index=True)
    branch_id = Column(String(36), ForeignKey('branch.id'), nullable=False, index=True)  # Alterado para branch_id
    name = Column(String(50), nullable=False, index=True)
    sector = Column(String(50))
    
    branch = relationship('Branch', backref=db.backref('departments', lazy='dynamic'))
    
    def __repr__(self):
        return f'<Department {self.name} at {self.branch.name}>'

class Queue(db.Model):
    __tablename__ = 'queue'
    id = Column(String(36), primary_key=True, index=True)
    department_id = Column(String(36), ForeignKey('department.id'), nullable=False, index=True)
    service = Column(String(50), nullable=False, index=True)
    category_id = Column(String(36), ForeignKey('service_category.id'), nullable=True, index=True)  # Novo campo
    prefix = Column(String(10), nullable=False)
    end_time = Column(Time, nullable=True)
    open_time = Column(Time, nullable=False)
    daily_limit = Column(Integer, nullable=False)
    active_tickets = Column(Integer, default=0)
    current_ticket = Column(Integer, default=0)
    avg_wait_time = Column(Float)
    last_service_time = Column(Float)
    num_counters = Column(Integer, default=1)
    last_counter = Column(Integer, default=0)
    
    department = relationship('Department', backref=db.backref('queues', lazy='dynamic'))
    category = relationship('ServiceCategory', backref=db.backref('queues', lazy='dynamic'))
    schedules = relationship('QueueSchedule', back_populates='queue', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<Queue {self.service} at {self.department.name}>'

class Ticket(db.Model):
    __tablename__ = 'ticket'
    id = Column(String(36), primary_key=True, index=True)
    queue_id = Column(String(36), ForeignKey('queue.id'), nullable=False, index=True)
    user_id = Column(String(36), ForeignKey('user.id'), nullable=True, index=True)
    ticket_number = Column(Integer, nullable=False)
    qr_code = Column(String(50), nullable=False, unique=True)
    priority = Column(Integer, default=0)
    is_physical = Column(Boolean, default=False)
    status = Column(String(20), default='Pendente')
    issued_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime)
    attended_at = Column(DateTime)
    cancelled_at = Column(DateTime)
    counter = Column(Integer)
    service_time = Column(Float)
    receipt_data = Column(Text)
    trade_available = Column(Boolean, default=False)
    
    queue = relationship('Queue', backref=db.backref('tickets', lazy='dynamic'))
    user = relationship('User', backref=db.backref('tickets', lazy='dynamic'))
    
    def __repr__(self):
        return f'<Ticket {self.ticket_number} for Queue {self.queue_id}>'

class User(db.Model):
    __tablename__ = 'user'
    id = Column(String(36), primary_key=True, index=True)
    email = Column(String(120), unique=True, nullable=False, index=True)
    name = Column(String(100), nullable=False)
    password_hash = Column(String(128), nullable=True)
    fcm_token = Column(String(255), nullable=True)
    user_role = Column(Enum(UserRole), default=UserRole.USER, index=True)
    department_id = Column(String(36), ForeignKey('department.id'), nullable=True, index=True)
    institution_id = Column(String(36), ForeignKey('institution.id'), nullable=True, index=True)
    last_known_lat = Column(Float, nullable=True)
    last_known_lon = Column(Float, nullable=True)
    last_location_update = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    active = Column(Boolean, default=True)
    
    department = relationship('Department', backref=db.backref('users', lazy='dynamic'))
    institution = relationship('Institution', backref=db.backref('admins', lazy='dynamic'))
    
    def set_password(self, password):
        if password:
            self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            
    def check_password(self, password):
        if not self.password_hash or not password:
            return False
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))
    
    def __repr__(self):
        return f'<User {self.email} ({self.user_role.value})>'

class QueueSchedule(db.Model):
    __tablename__ = 'queue_schedules'
    id = Column(String(36), primary_key=True)
    queue_id = Column(String(36), ForeignKey('queue.id'), nullable=False)
    weekday = Column(Enum(Weekday), nullable=False)
    open_time = Column(Time, nullable=True)
    end_time = Column(Time, nullable=True)
    is_closed = Column(Boolean, default=False)
    queue = relationship('Queue', back_populates='schedules')

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id = Column(String(36), primary_key=True)
    user_id = Column(String(36), nullable=True)
    action = Column(String, nullable=False)
    resource_type = Column(String, nullable=False)
    resource_id = Column(String(36), nullable=False)
    details = Column(Text, nullable=True)
    timestamp = Column(DateTime, nullable=False)

# Nova tabela para preferências do usuário
class UserPreference(db.Model):
    __tablename__ = 'user_preference'
    id = Column(String(36), primary_key=True, index=True)
    user_id = Column(String(36), ForeignKey('user.id'), nullable=False, index=True)
    institution_id = Column(String(36), ForeignKey('institution.id'), nullable=True, index=True)
    service_category_id = Column(String(36), ForeignKey('service_category.id'), nullable=True, index=True)
    neighborhood = Column(String(100), nullable=True)
    
    user = relationship('User', backref=db.backref('preferences', lazy='dynamic'))
    institution = relationship('Institution', backref=db.backref('preferred_by', lazy='dynamic'))
    service_category = relationship('ServiceCategory', backref=db.backref('preferred_by', lazy='dynamic'))
    
    def __repr__(self):
        return f'<UserPreference for User {self.user_id}>'

# Índices
Index('idx_queue_institution_id_service', Queue.department_id, Queue.service)
Index('idx_queue_schedule_queue_id', QueueSchedule.queue_id)
Index('idx_audit_log_timestamp', AuditLog.timestamp)
Index('idx_service_tag_queue_id', ServiceTag.queue_id)
Index('idx_branch_institution_id', Branch.institution_id)
Index('idx_user_preference_user_id', UserPreference.user_id)