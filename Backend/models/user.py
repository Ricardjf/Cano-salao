# Backend/models/user.py - MODELO DE USUARIO CORREGIDO
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token
from . import db

class User(db.Model):
    """Modelo de Usuario para el sistema Caño Salao"""
    __tablename__ = 'users'
    
    # ========== CAMPOS BÁSICOS ==========
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    telefono = db.Column(db.String(20))
    password_hash = db.Column(db.String(256), nullable=False)
    
    # ========== ROLES Y PERMISOS ==========
    rol = db.Column(db.String(20), default='user', nullable=False)  # 'admin', 'user', 'editor'
    activo = db.Column(db.Boolean, default=True, nullable=False)
    
    # ========== DATOS DE CONTACTO ==========
    direccion = db.Column(db.String(200))
    ciudad = db.Column(db.String(50), default='Barcelona')
    estado = db.Column(db.String(50), default='Anzoátegui')
    pais = db.Column(db.String(50), default='Venezuela')
    
    # ========== DATOS DE REGISTRO ==========
    fecha_registro = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    ultimo_acceso = db.Column(db.DateTime, onupdate=datetime.utcnow)
    email_verificado = db.Column(db.Boolean, default=False)
    
    # ========== PREFERENCIAS ==========
    notificaciones_email = db.Column(db.Boolean, default=True)
    notificaciones_push = db.Column(db.Boolean, default=True)
    idioma = db.Column(db.String(10), default='es')
    
    # ========== RELACIONES ==========
    # Relación con reservas (si tienes modelo de bookings)
    # reservas = db.relationship('Booking', backref='usuario', lazy='dynamic', cascade='all, delete-orphan')
    
    # ========== MÉTODOS DE SEGURIDAD ==========
    def set_password(self, password):
        """Hash y almacena la contraseña"""
        if not password or len(password) < 6:
            raise ValueError("La contraseña debe tener al menos 6 caracteres")
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Verifica si la contraseña es correcta"""
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)
    
    def generate_auth_token(self, expires_in=86400):  # 24 horas por defecto
        """Genera un token JWT para el usuario"""
        from app import jwt  # Importar aquí para evitar circular imports
        identity = {
            'id': self.id,
            'nombre': self.nombre,
            'email': self.email,
            'rol': self.rol
        }
        return create_access_token(identity=identity, expires_delta=expires_in)
    
    # ========== MÉTODOS DE ESTADO ==========
    def is_active(self):
        """Verifica si el usuario está activo"""
        return self.activo
    
    def is_admin(self):
        """Verifica si el usuario es administrador"""
        return self.rol == 'admin'
    
    def is_editor(self):
        """Verifica si el usuario es editor"""
        return self.rol == 'editor'
    
    def has_role(self, role):
        """Verifica si el usuario tiene un rol específico"""
        return self.rol == role
    
    def can(self, permission):
        """Verifica si el usuario tiene un permiso específico"""
        roles_permissions = {
            'admin': ['manage_users', 'manage_tours', 'manage_bookings', 'manage_content', 'view_reports'],
            'editor': ['manage_tours', 'manage_content'],
            'user': ['make_bookings', 'view_profile']
        }
        return permission in roles_permissions.get(self.rol, [])
    
    # ========== MÉTODOS DE SERIALIZACIÓN ==========
    def to_dict(self, include_sensitive=False):
        """Convierte el usuario a diccionario"""
        data = {
            'id': self.id,
            'nombre': self.nombre,
            'email': self.email,
            'rol': self.rol,
            'activo': self.activo,
            'telefono': self.telefono,
            'ciudad': self.ciudad,
            'estado': self.estado,
            'fecha_registro': self.fecha_registro.isoformat() if self.fecha_registro else None,
            'ultimo_acceso': self.ultimo_acceso.isoformat() if self.ultimo_acceso else None,
            'email_verificado': self.email_verificado,
        }
        
        if include_sensitive:
            # Solo para administradores o el propio usuario
            data.update({
                'direccion': self.direccion,
                'pais': self.pais,
                'notificaciones_email': self.notificaciones_email,
                'notificaciones_push': self.notificaciones_push,
                'idioma': self.idioma,
            })
        
        return data
    
    def to_auth_dict(self):
        """Diccionario para respuestas de autenticación"""
        return {
            'id': self.id,
            'nombre': self.nombre,
            'email': self.email,
            'rol': self.rol,
            'activo': self.activo,
            'telefono': self.telefono,
        }
    
    def to_profile_dict(self):
        """Diccionario para perfil público"""
        return {
            'id': self.id,
            'nombre': self.nombre,
            'ciudad': self.ciudad,
            'estado': self.estado,
            'fecha_registro': self.fecha_registro.strftime('%d/%m/%Y') if self.fecha_registro else None,
        }
    
    # ========== MÉTODOS DE VALIDACIÓN ==========
    @staticmethod
    def validate_email(email):
        """Valida formato de email"""
        import re
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(email_regex, email) is not None
    
    @staticmethod
    def validate_phone(phone):
        """Valida formato de teléfono"""
        if not phone:
            return True
        phone_regex = r'^[\+]?[0-9\s\-\(\)]{10,20}$'
        import re
        return re.match(phone_regex, phone) is not None
    
    # ========== MÉTODOS DE CLASE (QUERIES) ==========
    @classmethod
    def find_by_email(cls, email):
        """Busca usuario por email"""
        return cls.query.filter_by(email=email).first()
    
    @classmethod
    def find_by_id(cls, user_id):
        """Busca usuario por ID"""
        return cls.query.get(user_id)
    
    @classmethod
    def find_active_users(cls):
        """Obtiene todos los usuarios activos"""
        return cls.query.filter_by(activo=True).all()
    
    @classmethod
    def find_admins(cls):
        """Obtiene todos los administradores"""
        return cls.query.filter_by(rol='admin', activo=True).all()
    
    @classmethod
    def create_user(cls, nombre, email, password, rol='user', **kwargs):
        """Crea un nuevo usuario"""
        if cls.find_by_email(email):
            raise ValueError(f"El email {email} ya está registrado")
        
        user = cls(nombre=nombre, email=email, rol=rol, **kwargs)
        user.set_password(password)
        return user
    
    # ========== MÉTODOS DE ACTUALIZACIÓN ==========
    def update_profile(self, **kwargs):
        """Actualiza el perfil del usuario"""
        allowed_fields = ['nombre', 'telefono', 'direccion', 'ciudad', 'estado', 'pais', 
                         'notificaciones_email', 'notificaciones_push', 'idioma']
        
        for field, value in kwargs.items():
            if field in allowed_fields and value is not None:
                setattr(self, field, value)
        
        return self
    
    def update_password(self, old_password, new_password):
        """Actualiza la contraseña del usuario"""
        if not self.check_password(old_password):
            raise ValueError("Contraseña actual incorrecta")
        
        self.set_password(new_password)
        return True
    
    def activate(self):
        """Activa el usuario"""
        self.activo = True
        return self
    
    def deactivate(self):
        """Desactiva el usuario"""
        self.activo = False
        return self
    
    def change_role(self, new_role):
        """Cambia el rol del usuario"""
        valid_roles = ['admin', 'user', 'editor']
        if new_role not in valid_roles:
            raise ValueError(f"Rol inválido. Debe ser: {', '.join(valid_roles)}")
        
        self.rol = new_role
        return self
    
    def verify_email(self):
        """Marca el email como verificado"""
        self.email_verificado = True
        return self
    
    # ========== REPRESENTACIÓN ==========
    def __repr__(self):
        return f'<User {self.email}>'
    
    def __str__(self):
        return f'{self.nombre} ({self.email})'


# Modelo para tokens de verificación de email (opcional)
class EmailVerificationToken(db.Model):
    """Tokens para verificación de email"""
    __tablename__ = 'email_verification_tokens'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    token = db.Column(db.String(100), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)
    
    # Relación
    user = db.relationship('User', backref=db.backref('verification_tokens', lazy='dynamic'))
    
    def is_valid(self):
        """Verifica si el token es válido"""
        return not self.used and datetime.utcnow() < self.expires_at
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'token': self.token,
            'created_at': self.created_at.isoformat(),
            'expires_at': self.expires_at.isoformat(),
            'used': self.used
        }


# Modelo para tokens de recuperación de contraseña (opcional)
class PasswordResetToken(db.Model):
    """Tokens para recuperación de contraseña"""
    __tablename__ = 'password_reset_tokens'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    token = db.Column(db.String(100), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)
    
    # Relación
    user = db.relationship('User', backref=db.backref('password_reset_tokens', lazy='dynamic'))
    
    def is_valid(self):
        """Verifica si el token es válido"""
        return not self.used and datetime.utcnow() < self.expires_at
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'token': self.token,
            'created_at': self.created_at.isoformat(),
            'expires_at': self.expires_at.isoformat(),
            'used': self.used
        }


# Función helper para crear usuario administrador por defecto
def create_default_admin():
    """Crea un usuario administrador por defecto si no existe"""
    from app import app
    
    with app.app_context():
        from . import db
        
        admin_email = app.config.get('DEFAULT_ADMIN_EMAIL', 'admin@canosalaotours.com')
        admin_password = app.config.get('DEFAULT_ADMIN_PASSWORD', 'admin123')
        
        existing_admin = User.find_by_email(admin_email)
        
        if not existing_admin:
            try:
                admin = User.create_user(
                    nombre='Administrador',
                    email=admin_email,
                    password=admin_password,
                    rol='admin',
                    telefono='+58 412-205-6558',
                    ciudad='Barcelona',
                    estado='Anzoátegui',
                    pais='Venezuela',
                    email_verificado=True
                )
                
                db.session.add(admin)
                db.session.commit()
                print(f"✅ Usuario administrador creado: {admin_email}")
                
            except Exception as e:
                db.session.rollback()
                print(f"⚠️ Error al crear administrador: {e}")
        else:
            print(f"✅ Usuario administrador ya existe: {admin_email}")