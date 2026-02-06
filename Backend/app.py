# Backend/app.py - VERSIÓN COMPLETA Y UNIFICADA - CORREGIDA
import os
import sys
import logging
import functools
import re
from datetime import timedelta, datetime
from flask import Flask, jsonify, request, make_response
from flask_jwt_extended import (
    JWTManager, 
    create_access_token, 
    create_refresh_token,
    jwt_required, 
    get_jwt_identity,
    get_jwt,
    set_access_cookies,
    set_refresh_cookies,
    unset_jwt_cookies
)
from flask_cors import CORS
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import text  # ¡IMPORTANTE! Importar text para SQLAlchemy 2.x

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('app.log', encoding='utf-8')
    ]
)

logger = logging.getLogger(__name__)

print("\n" + "="*60)
print("🚀 INICIANDO CAÑO SALAO - BACKEND API - VERSIÓN CORREGIDA")
print("="*60)

# ========== CONFIGURACIÓN BÁSICA ==========
class Config:
    # Claves secretas - MÁS LARGAS para evitar warnings
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-cano-salao-2024-extra-long-for-security-1234567890')
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'jwt-secret-key-cano-salao-2024-extra-long-for-security-1234567890')
    
    # Configuración de base de datos
    if os.environ.get('DATABASE_URL'):
        SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL').replace('postgres://', 'postgresql://')
    else:
        basedir = os.path.abspath(os.path.dirname(__file__))
        DATABASE_PATH = os.path.join(basedir, 'instance', 'cano_salao.db')
        SQLALCHEMY_DATABASE_URI = f'sqlite:///{DATABASE_PATH}'
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # ========== CONFIGURACIÓN JWT MEJORADA ==========
    # Tiempos de expiración MUCHO más largos
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(days=30)  # 30 DÍAS para acceso
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=365)  # 1 AÑO para refresh
    
    # Configuración para cookies (opcional pero más seguro)
    JWT_TOKEN_LOCATION = ['headers']
    
    # Para desarrollo local, desactivar CSRF
    JWT_COOKIE_CSRF_PROTECT = False
    
    # Para producción con cookies
    JWT_COOKIE_SECURE = os.environ.get('FLASK_ENV') == 'production'
    JWT_COOKIE_SAMESITE = 'Lax'
    
    # ========== CONFIGURACIÓN SEGURIDAD ==========
    PERMANENT_SESSION_LIFETIME = timedelta(days=365)  # Sesión de 1 año
    
    # Configuración CORS
    CORS_ORIGINS = [
        'https://ricardjf.github.io',
        'http://localhost:5500',
        'http://127.0.0.1:5500',
        'http://localhost:3000',
        'http://127.0.0.1:3000',
        '*',  # Temporal para pruebas
    ]
    
    # Configuración del servidor
    HOST = '0.0.0.0'
    PORT = int(os.environ.get('PORT', 5000))
    DEBUG = os.environ.get('FLASK_ENV', 'development') == 'development'
    ENV = os.environ.get('FLASK_ENV', 'development')

# ========== CREAR APLICACIÓN ==========
def create_app(config_class=Config):
    """Factory para crear la aplicación Flask"""
    
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Configurar CORS primero
    CORS(app, resources={
        r"/api/*": {
            "origins": app.config['CORS_ORIGINS'],
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization", "X-Requested-With"],
            "supports_credentials": True,
            "expose_headers": ["Authorization"],
        }
    })
    print("✅ CORS configurado")
    
    # Inicializar JWT
    jwt = JWTManager(app)
    
    # ========== CALLBACKS JWT SIMPLIFICADOS ==========
    
    @jwt.user_identity_loader
    def user_identity_lookup(user):
        """
        ¡IMPORTANTE! Flask-JWT-Extended espera que esto devuelva un STRING.
        'user' aquí es lo que pasas a create_access_token(identity=user)
        """
        if isinstance(user, dict) and 'id' in user:
            # Si es dict, extraer el ID
            return str(user['id'])
        elif isinstance(user, (int, str)):
            # Si ya es int o string, convertirlo a string
            return str(user)
        else:
            # Si es objeto de modelo
            return str(getattr(user, 'id', ''))
    
    @jwt.user_lookup_loader
    def user_lookup_callback(_jwt_header, jwt_data):
        """
        ¡IMPORTANTE! Esto NO se usa si no llamas a get_current_user()
        Pero lo mantenemos por si acaso
        """
        try:
            identity = jwt_data["sub"]
            if identity:
                # Buscar usuario en base de datos
                user = User.query.get(int(identity))
                if user:
                    return user
        except Exception as e:
            logger.warning(f"Error en user_lookup_callback: {e}")
        return None
    
    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        logger.info(f"Token expirado, intentando refresh automático")
        return jsonify({
            'success': False,
            'error': 'token_expired',
            'message': 'Token expirado',
            'can_refresh': True
        }), 401
    
    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        logger.warning(f"Token inválido: {error}")
        return jsonify({
            'success': False,
            'error': 'invalid_token',
            'message': 'Token inválido'
        }), 401
    
    @jwt.unauthorized_loader
    def unauthorized_callback(error):
        logger.warning(f"Acceso no autorizado: {error}")
        return jsonify({
            'success': False,
            'error': 'unauthorized',
            'message': 'No autorizado - Token faltante'
        }), 401
    
    print("✅ JWT configurado con tiempos extendidos")
    
    # Inicializar base de datos
    db = SQLAlchemy(app)
    
    # Inicializar migraciones
    try:
        migrate = Migrate(app, db)
        print("✅ Migraciones configuradas")
    except:
        print("⚠️  Migraciones no disponibles")
    
    # ========== MODELOS ==========
    class User(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        nombre = db.Column(db.String(100), nullable=False)
        email = db.Column(db.String(120), unique=True, nullable=False)
        password = db.Column(db.String(200), nullable=False)
        rol = db.Column(db.String(20), default='user')
        activo = db.Column(db.Boolean, default=True)
        telefono = db.Column(db.String(20))
        direccion = db.Column(db.String(200))
        ciudad = db.Column(db.String(50), default='Barcelona')
        estado = db.Column(db.String(50), default='Anzoátegui')
        pais = db.Column(db.String(50), default='Venezuela')
        fecha_registro = db.Column(db.DateTime, default=datetime.utcnow)
        ultimo_acceso = db.Column(db.DateTime, onupdate=datetime.utcnow)
        last_activity = db.Column(db.DateTime)
        email_verificado = db.Column(db.Boolean, default=False)
        notificaciones_email = db.Column(db.Boolean, default=True)
        notificaciones_push = db.Column(db.Boolean, default=True)
        idioma = db.Column(db.String(10), default='es')
        created_at = db.Column(db.DateTime, default=datetime.utcnow)
        updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
        
        def set_password(self, password):
            """Hash y almacena la contraseña"""
            if not password or len(password) < 6:
                raise ValueError("La contraseña debe tener al menos 6 caracteres")
            self.password = generate_password_hash(password)
        
        def check_password(self, password):
            """Verifica si la contraseña es correcta"""
            return check_password_hash(self.password, password)
        
        def is_active(self):
            return self.activo
        
        def is_admin(self):
            return self.rol == 'admin'
        
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
                data.update({
                    'direccion': self.direccion,
                    'pais': self.pais,
                    'notificaciones_email': self.notificaciones_email,
                    'notificaciones_push': self.notificaciones_push,
                    'idioma': self.idioma,
                })
            
            return data
        
        def to_auth_dict(self):
            return {
                'id': self.id,
                'nombre': self.nombre,
                'email': self.email,
                'rol': self.rol,
                'activo': self.activo,
                'telefono': self.telefono,
            }
        
        @staticmethod
        def validate_email(email):
            """Valida formato de email"""
            email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            return re.match(email_regex, email) is not None
        
        @staticmethod
        def validate_phone(phone):
            """Valida formato de teléfono"""
            if not phone:
                return True
            phone_regex = r'^[\+]?[0-9\s\-\(\)]{10,20}$'
            return re.match(phone_regex, phone) is not None
        
        @classmethod
        def find_by_email(cls, email):
            """Busca usuario por email"""
            return cls.query.filter_by(email=email).first()
        
        @classmethod
        def find_by_id(cls, user_id):
            """Busca usuario por ID"""
            return cls.query.get(user_id)
        
        def __repr__(self):
            return f'<User {self.email}>'
    
    class Tour(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        nombre = db.Column(db.String(100), nullable=False)
        descripcion = db.Column(db.Text)
        precio = db.Column(db.Float, nullable=False)
        capacidad = db.Column(db.Integer, default=15)
        disponible = db.Column(db.Boolean, default=True)
        duracion = db.Column(db.String(50))
        imagen_url = db.Column(db.String(500))
        created_at = db.Column(db.DateTime, default=datetime.utcnow)
        updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
        
        def to_dict(self):
            return {
                'id': self.id,
                'nombre': self.nombre,
                'descripcion': self.descripcion,
                'precio': self.precio,
                'capacidad': self.capacidad,
                'disponible': self.disponible,
                'duracion': self.duracion,
                'imagen_url': self.imagen_url
            }
    
    class Booking(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        codigo = db.Column(db.String(50), unique=True, nullable=False)
        user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
        tour_id = db.Column(db.Integer, db.ForeignKey('tour.id'), nullable=False)
        fecha = db.Column(db.Date, nullable=False)
        personas = db.Column(db.Integer, nullable=False)
        total = db.Column(db.Float, nullable=False)
        estado = db.Column(db.String(20), default='pending')
        created_at = db.Column(db.DateTime, default=datetime.utcnow)
        updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
        
        user = db.relationship('User', backref='bookings')
        tour = db.relationship('Tour', backref='bookings')
        
        def to_dict(self):
            return {
                'id': self.id,
                'codigo': self.codigo,
                'user_id': self.user_id,
                'tour_id': self.tour_id,
                'fecha': self.fecha.isoformat() if self.fecha else None,
                'personas': self.personas,
                'total': self.total,
                'estado': self.estado,
                'created_at': self.created_at.isoformat() if self.created_at else None
            }
    
    class BlogPost(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        titulo = db.Column(db.String(200), nullable=False)
        contenido = db.Column(db.Text, nullable=False)
        excerpt = db.Column(db.Text)
        categoria = db.Column(db.String(50))
        autor = db.Column(db.String(100))
        imagen_url = db.Column(db.String(500))
        publicado = db.Column(db.Boolean, default=False)
        vistas = db.Column(db.Integer, default=0)
        created_at = db.Column(db.DateTime, default=datetime.utcnow)
        updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
        
        def to_dict(self):
            return {
                'id': self.id,
                'titulo': self.titulo,
                'excerpt': self.excerpt,
                'categoria': self.categoria,
                'autor': self.autor,
                'imagen_url': self.imagen_url,
                'publicado': self.publicado,
                'vistas': self.vistas,
                'created_at': self.created_at.isoformat() if self.created_at else None
            }
    
    # ========== INICIALIZAR BASE DE DATOS ==========
    with app.app_context():
        try:
            if 'sqlite' in app.config['SQLALCHEMY_DATABASE_URI']:
                os.makedirs(os.path.dirname(app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')), exist_ok=True)
            
            db.create_all()
            print("✅ Base de datos inicializada")
            
            # Crear admin por defecto si no existe
            if User.query.count() == 0:
                admin = User(
                    nombre='Administrador',
                    email='admin@canosalao.com',
                    rol='admin',
                    telefono='+58 412-205-6558',
                    ciudad='Barcelona',
                    estado='Anzoátegui',
                    pais='Venezuela',
                    email_verificado=True,
                    activo=True
                )
                admin.set_password('admin123')
                admin.last_activity = datetime.utcnow()
                
                db.session.add(admin)
                
                tours = [
                    Tour(
                        nombre='Tour Básico',
                        descripcion='Recorrido por los manglares',
                        precio=25.00,
                        capacidad=15,
                        duracion='2 horas',
                        imagen_url='https://images.unsplash.com/photo-1559827260-dc66d52bef19?w=600'
                    ),
                    Tour(
                        nombre='Tour Completo',
                        descripcion='Experiencia completa de 4 horas',
                        precio=45.00,
                        capacidad=12,
                        duracion='4 horas',
                        imagen_url='https://images.unsplash.com/photo-1578662996442-48f60103fc96?w=600'
                    )
                ]
                db.session.add_all(tours)
                
                blog_post = BlogPost(
                    titulo='Bienvenidos a Caño Salao',
                    contenido='<h1>¡Bienvenidos!</h1><p>Descubre la belleza de nuestros manglares...</p>',
                    excerpt='Conoce más sobre nuestra comunidad y tours',
                    categoria='noticias',
                    autor='Equipo Caño Salao',
                    publicado=True
                )
                db.session.add(blog_post)
                
                db.session.commit()
                print("✅ Datos de ejemplo creados")
                print("👑 Admin: admin@canosalao.com / admin123")
                print(f"🗄️  Usuarios: {User.query.count()}, Tours: {Tour.query.count()}")
                
        except Exception as e:
            print(f"⚠️  Error inicializando base de datos: {str(e)[:100]}")
    
    # ========== HELPER FUNCTIONS ==========
    
    def update_user_activity(user_id):
        """Actualiza la última actividad del usuario"""
        try:
            user = User.query.get(user_id)
            if user:
                user.last_activity = datetime.utcnow()
                db.session.commit()
        except Exception as e:
            logger.error(f"Error actualizando actividad: {e}")
    
    # ========== FUNCIONES DE VALIDACIÓN ==========
    
    def validate_email_frontend(email):
        """Valida formato de email"""
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(email_regex, email) is not None
    
    def validate_password_frontend(password):
        """Valida fortaleza de contraseña"""
        if len(password) < 6:
            return False, "La contraseña debe tener al menos 6 caracteres"
        if len(password) > 50:
            return False, "La contraseña no puede exceder 50 caracteres"
        return True, "Contraseña válida"
    
    def validate_name_frontend(name):
        """Valida nombre"""
        if not name or len(name.strip()) < 2:
            return False, "El nombre debe tener al menos 2 caracteres"
        if len(name) > 100:
            return False, "El nombre no puede exceder 100 caracteres"
        return True, "Nombre válido"
    
    # ========== RUTAS BÁSICAS ==========
    
    @app.route('/')
    def home():
        return jsonify({
            'success': True,
            'message': '🚤 API Caño Salao - Sistema de Turismo',
            'version': '1.0.0',
            'status': 'online',
            'timestamp': datetime.utcnow().isoformat(),
            'endpoints': {
                'auth': '/api/auth/*',
                'tours': '/api/tours',
                'blog': '/api/blog',
                'status': '/api/status',
                'health': '/health'
            }
        })
    
    @app.route('/api/status')
    def api_status():
        return jsonify({
            'success': True,
            'status': 'online',
            'service': 'cano-salao-api',
            'environment': app.config['ENV'],
            'timestamp': datetime.utcnow().isoformat(),
            'jwt_config': {
                'access_token_expires': str(app.config['JWT_ACCESS_TOKEN_EXPIRES']),
                'refresh_token_expires': str(app.config['JWT_REFRESH_TOKEN_EXPIRES']),
                'access_token_days': app.config['JWT_ACCESS_TOKEN_EXPIRES'].days
            },
            'database': {
                'users': User.query.count(),
                'tours': Tour.query.count(),
                'bookings': Booking.query.count(),
                'blog_posts': BlogPost.query.count()
            }
        })
    
    @app.route('/health')
    def health():
        """
        Health check endpoint - CORREGIDO para SQLAlchemy 2.x
        """
        try:
            # ¡CORRECCIÓN APLICADA AQUÍ! Usar text() para consultas SQL
            db.session.execute(text('SELECT 1'))
            
            # También podemos verificar algunos datos
            user_count = User.query.count()
            tour_count = Tour.query.count()
            
            return jsonify({
                'status': 'healthy',
                'database': 'connected',
                'users': user_count,
                'tours': tour_count,
                'timestamp': datetime.utcnow().isoformat(),
                'sqlalchemy_version': '2.x_compatible'
            })
        except Exception as e:
            logger.error(f"Health check error: {e}")
            return jsonify({
                'status': 'unhealthy',
                'database': 'disconnected',
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }), 500
    
    # ========== RUTAS DE AUTENTICACIÓN UNIFICADAS ==========
    
    @app.route('/api/auth/login', methods=['POST'])
    def login():
        """
        Iniciar sesión - VERSIÓN UNIFICADA Y CORREGIDA
        POST /api/auth/login
        Body: { "email": "usuario@email.com", "password": "contraseña" }
        """
        try:
            data = request.get_json()
            
            if not data:
                logger.warning("Intento de login sin datos JSON")
                return jsonify({
                    'success': False,
                    'error': 'Se requiere datos en formato JSON'
                }), 400
            
            email = data.get('email', '').strip().lower()
            password = data.get('password', '')
            
            # Validaciones básicas
            if not email or not password:
                return jsonify({
                    'success': False,
                    'error': 'Email y contraseña son requeridos'
                }), 400
            
            if not validate_email_frontend(email):
                return jsonify({
                    'success': False,
                    'error': 'Formato de email inválido'
                }), 400
            
            # Buscar usuario en base de datos
            usuario = User.find_by_email(email)
            
            # Verificar usuario
            if not usuario:
                logger.warning(f"Intento de login con email no registrado: {email}")
                return jsonify({
                    'success': False,
                    'error': 'Credenciales inválidas'
                }), 401
            
            # Verificar si el usuario está activo
            if not usuario.is_active():
                logger.warning(f"Intento de login con usuario inactivo: {email}")
                return jsonify({
                    'success': False,
                    'error': 'Tu cuenta está desactivada. Contacta al administrador.'
                }), 403
            
            # Verificar contraseña
            if not usuario.check_password(password):
                logger.warning(f"Contraseña incorrecta para: {email}")
                return jsonify({
                    'success': False,
                    'error': 'Credenciales inválidas'
                }), 401
            
            # Actualizar último acceso
            try:
                usuario.ultimo_acceso = datetime.utcnow()
                usuario.last_activity = datetime.utcnow()
                db.session.commit()
            except Exception as e:
                logger.warning(f"Error al actualizar último acceso: {e}")
                # Continuar aunque falle esta parte
            
            # ¡IMPORTANTE! Para Flask-JWT-Extended, identity debe ser un STRING o algo JSON-serializable
            # Usamos un dict con el ID - user_identity_loader lo convertirá a string
            identity_dict = {
                'id': usuario.id,
                'email': usuario.email
            }
            
            # Obtener duración de la configuración
            jwt_expires = app.config.get('JWT_ACCESS_TOKEN_EXPIRES', timedelta(days=30))
            
            # Crear token de acceso con duración extendida
            # Pasamos el dict, user_identity_loader lo convertirá a string
            access_token = create_access_token(
                identity=identity_dict,
                expires_delta=jwt_expires
            )
            
            # Crear refresh token (1 año)
            refresh_token = create_refresh_token(
                identity=identity_dict,
                expires_delta=app.config.get('JWT_REFRESH_TOKEN_EXPIRES', timedelta(days=365))
            )
            
            logger.info(f"✅ Login exitoso: {email} (ID: {usuario.id}), Token expira en: {jwt_expires}")
            
            # RESPUESTA CORREGIDA - Frontend busca "token"
            return jsonify({
                'success': True,
                'message': 'Inicio de sesión exitoso',
                'token': access_token,  # ← Lo que busca el frontend
                'access_token': access_token,  # ← Para compatibilidad
                'refresh_token': refresh_token,
                'user': usuario.to_auth_dict(),
                'user_full': usuario.to_dict(include_sensitive=False),
                'token_type': 'Bearer',
                'expires_in': int(jwt_expires.total_seconds()),
                'expires_days': jwt_expires.days,
                'persistent_session': True,
                'timestamp': datetime.utcnow().isoformat()
            }), 200
            
        except Exception as e:
            logger.error(f"❌ Error en login: {str(e)}", exc_info=True)
            return jsonify({
                'success': False,
                'error': 'Error interno del servidor',
                'details': str(e) if app.config['DEBUG'] else None
            }), 500
    
    @app.route('/api/auth/register', methods=['POST'])
    def register():
        """
        Registrar nuevo usuario - VERSIÓN UNIFICADA
        POST /api/auth/register
        Body: {
            "nombre": "Nombre Completo",
            "email": "usuario@email.com", 
            "password": "contraseña",
            "telefono": "+58 412-1234567" (opcional)
        }
        """
        try:
            data = request.get_json()
            
            if not data:
                return jsonify({
                    'success': False,
                    'error': 'Se requiere datos en formato JSON'
                }), 400
            
            nombre = data.get('nombre', '').strip()
            email = data.get('email', '').strip().lower()
            password = data.get('password', '')
            telefono = data.get('telefono', '').strip()
            
            # Validaciones
            is_name_valid, name_msg = validate_name_frontend(nombre)
            if not is_name_valid:
                return jsonify({'success': False, 'error': name_msg}), 400
            
            if not validate_email_frontend(email):
                return jsonify({
                    'success': False,
                    'error': 'Formato de email inválido'
                }), 400
            
            is_password_valid, password_msg = validate_password_frontend(password)
            if not is_password_valid:
                return jsonify({'success': False, 'error': password_msg}), 400
            
            if telefono:
                if not User.validate_phone(telefono):
                    return jsonify({
                        'success': False,
                        'error': 'Formato de teléfono inválido'
                    }), 400
            
            # Verificar si el email ya existe
            if User.find_by_email(email):
                return jsonify({
                    'success': False,
                    'error': 'El email ya está registrado'
                }), 409
            
            # Crear usuario
            # Determinar rol (primer usuario = admin, otros = user)
            user_count = User.query.count()
            rol = 'admin' if user_count == 0 else 'user'
            
            usuario = User(
                nombre=nombre,
                email=email,
                telefono=telefono,
                rol=rol,
                email_verificado=False,
                activo=True,
                fecha_registro=datetime.utcnow(),
                last_activity=datetime.utcnow()
            )
            usuario.set_password(password)
            
            db.session.add(usuario)
            db.session.commit()
            
            # Crear tokens automáticamente después de registro
            identity_dict = {
                'id': usuario.id,
                'email': usuario.email
            }
            
            access_token = create_access_token(
                identity=identity_dict,
                expires_delta=timedelta(days=30)
            )
            
            refresh_token = create_refresh_token(
                identity=identity_dict,
                expires_delta=timedelta(days=365)
            )
            
            logger.info(f"✅ Nuevo usuario registrado: {email} (ID: {usuario.id}, Rol: {rol})")
            
            return jsonify({
                'success': True,
                'message': 'Registro exitoso. ¡Bienvenido/a!',
                'token': access_token,  # ← Lo que busca el frontend
                'access_token': access_token,  # ← Para compatibilidad
                'refresh_token': refresh_token,
                'user': usuario.to_auth_dict(),
                'is_first_user': rol == 'admin',
                'expires_in': timedelta(days=30).total_seconds(),
                'timestamp': datetime.utcnow().isoformat()
            }), 201
            
        except Exception as e:
            logger.error(f"❌ Error en registro: {str(e)}", exc_info=True)
            db.session.rollback()
            return jsonify({
                'success': False,
                'error': 'Error al crear el usuario',
                'details': str(e) if app.config['DEBUG'] else None
            }), 500
    
    @app.route('/api/auth/verify', methods=['GET'])
    @jwt_required()
    def verify_token():
        """
        Validar token JWT
        GET /api/auth/verify
        Headers: Authorization: Bearer <token>
        """
        try:
            # get_jwt_identity() devuelve lo que guardamos en el token
            current_identity = get_jwt_identity()
            jwt_data = get_jwt()
            
            logger.debug(f"Verificando token - Identity: {current_identity}")
            
            # current_identity puede ser un dict o string dependiendo de cómo lo guardamos
            user_id = None
            if isinstance(current_identity, dict):
                user_id = current_identity.get('id')
            elif isinstance(current_identity, (int, str)):
                # Si es string, intentar convertir
                try:
                    user_id = int(current_identity)
                except:
                    user_id = None
            
            if not user_id:
                return jsonify({
                    'success': False,
                    'valid': False,
                    'error': 'Token inválido - ID no encontrado'
                }), 401
            
            usuario = User.find_by_id(user_id)
            if not usuario:
                return jsonify({
                    'success': False,
                    'valid': False,
                    'error': 'Usuario no encontrado'
                }), 404
            
            if not usuario.is_active():
                return jsonify({
                    'success': False,
                    'valid': False,
                    'error': 'Usuario desactivado'
                }), 403
            
            # Actualizar actividad
            update_user_activity(usuario.id)
            
            # Calcular tiempo restante
            expires_at = jwt_data.get('exp')
            import time
            current_time = time.time()
            time_left = expires_at - current_time if expires_at else 0
            
            return jsonify({
                'success': True,
                'valid': True,
                'user': usuario.to_auth_dict(),
                'token_info': {
                    'identity': current_identity,
                    'expires_at': expires_at,
                    'expires_date': datetime.fromtimestamp(expires_at).isoformat() if expires_at else None,
                    'time_left_seconds': time_left,
                    'time_left_days': time_left / (24 * 3600) if time_left > 0 else 0,
                    'time_left_hours': time_left / 3600 if time_left > 0 else 0,
                    'type': 'access'
                },
                'timestamp': datetime.utcnow().isoformat()
            }), 200
            
        except Exception as e:
            logger.error(f"❌ Error validando token: {str(e)}", exc_info=True)
            return jsonify({
                'success': False,
                'valid': False,
                'error': 'Error al validar token',
                'details': str(e) if app.config['DEBUG'] else None
            }), 500
    
    @app.route('/api/auth/refresh', methods=['POST'])
    @jwt_required(refresh=True)
    def refresh():
        """
        Refrescar token de acceso
        POST /api/auth/refresh
        Headers: Authorization: Bearer <refresh_token>
        """
        try:
            current_identity = get_jwt_identity()
            logger.debug(f"Refresh token - Identity recibido: {current_identity}")
            
            # Obtener ID del usuario
            user_id = None
            if isinstance(current_identity, dict):
                user_id = current_identity.get('id')
            elif isinstance(current_identity, (int, str)):
                try:
                    user_id = int(current_identity)
                except:
                    user_id = None
            
            if not user_id:
                return jsonify({
                    'success': False,
                    'error': 'Token inválido - ID no encontrado'
                }), 401
            
            # Verificar usuario
            user = User.find_by_id(user_id)
            if not user or not user.activo:
                return jsonify({
                    'success': False,
                    'error': 'Usuario no encontrado o inactivo'
                }), 401
            
            # Actualizar actividad
            user.last_activity = datetime.utcnow()
            db.session.commit()
            
            # Obtener duración
            jwt_expires = app.config.get('JWT_ACCESS_TOKEN_EXPIRES', timedelta(days=30))
            
            # Crear nuevo access token
            new_access_token = create_access_token(
                identity=current_identity,  # Usar el mismo identity
                expires_delta=jwt_expires
            )
            
            logger.info(f"✅ Token refrescado para usuario ID: {user_id}")
            
            return jsonify({
                'success': True,
                'token': new_access_token,  # ← Lo que busca el frontend
                'access_token': new_access_token,  # ← Para compatibilidad
                'user': user.to_auth_dict(),
                'message': 'Token refrescado exitosamente',
                'expires_in': int(jwt_expires.total_seconds()),
                'timestamp': datetime.utcnow().isoformat()
            }), 200
            
        except Exception as e:
            logger.error(f"❌ Error refrescando token: {str(e)}")
            return jsonify({
                'success': False,
                'error': 'Error al refrescar token',
                'details': str(e) if app.config['DEBUG'] else None
            }), 401
    
    @app.route('/api/auth/profile', methods=['GET'])
    @jwt_required()
    def get_profile():
        """
        Obtener perfil del usuario autenticado
        GET /api/auth/profile
        """
        try:
            current_identity = get_jwt_identity()
            
            # Obtener ID del usuario
            user_id = None
            if isinstance(current_identity, dict):
                user_id = current_identity.get('id')
            elif isinstance(current_identity, (int, str)):
                try:
                    user_id = int(current_identity)
                except:
                    user_id = None
            
            if not user_id:
                return jsonify({
                    'success': False,
                    'error': 'Token inválido'
                }), 401
            
            usuario = User.find_by_id(user_id)
            if not usuario:
                return jsonify({
                    'success': False,
                    'error': 'Usuario no encontrado'
                }), 404
            
            # Actualizar actividad
            update_user_activity(usuario.id)
            
            return jsonify({
                'success': True,
                'profile': usuario.to_dict(include_sensitive=True),
                'timestamp': datetime.utcnow().isoformat()
            }), 200
            
        except Exception as e:
            logger.error(f"Error obteniendo perfil: {str(e)}")
            return jsonify({
                'success': False,
                'error': 'Error al obtener perfil',
                'details': str(e) if app.config['DEBUG'] else None
            }), 500
    
    @app.route('/api/auth/logout', methods=['POST'])
    @jwt_required()
    def logout():
        """
        Cerrar sesión
        POST /api/auth/logout
        """
        try:
            current_identity = get_jwt_identity()
            logger.info(f"Logout solicitado por: {current_identity}")
            
            return jsonify({
                'success': True,
                'message': 'Sesión cerrada exitosamente',
                'timestamp': datetime.utcnow().isoformat()
            }), 200
            
        except Exception as e:
            logger.error(f"Error en logout: {e}")
            return jsonify({
                'success': False,
                'error': 'Error al cerrar sesión'
            }), 500
    
    @app.route('/api/auth/session-info', methods=['GET'])
    @jwt_required()
    def get_session_info():
        """
        Obtener información detallada de la sesión actual
        GET /api/auth/session-info
        """
        try:
            current_identity = get_jwt_identity()
            jwt_data = get_jwt()
            
            from datetime import datetime
            import time
            
            expires_at = jwt_data.get('exp')
            issued_at = jwt_data.get('iat')
            
            current_time = time.time()
            
            if expires_at:
                time_left = expires_at - current_time
                expires_date = datetime.fromtimestamp(expires_at)
            else:
                time_left = 0
                expires_date = None
            
            # Obtener ID del usuario
            user_id = None
            if isinstance(current_identity, dict):
                user_id = current_identity.get('id')
            elif isinstance(current_identity, (int, str)):
                try:
                    user_id = int(current_identity)
                except:
                    user_id = None
            
            response_data = {
                'success': True,
                'session': {
                    'identity': current_identity,
                    'issued_at': issued_at,
                    'issued_date': datetime.fromtimestamp(issued_at).isoformat() if issued_at else None,
                    'expires_at': expires_at,
                    'expires_date': expires_date.isoformat() if expires_date else None,
                    'time_left_seconds': time_left,
                    'time_left_days': time_left / (24 * 3600) if time_left > 0 else 0,
                    'time_left_hours': time_left / 3600 if time_left > 0 else 0,
                    'token_type': jwt_data.get('type', 'access'),
                    'is_valid': time_left > 0 if expires_at else False,
                    'jwt_config': {
                        'access_token_days': app.config['JWT_ACCESS_TOKEN_EXPIRES'].days,
                        'refresh_token_days': app.config['JWT_REFRESH_TOKEN_EXPIRES'].days
                    }
                }
            }
            
            if user_id:
                usuario = User.find_by_id(user_id)
                if usuario:
                    response_data['user'] = usuario.to_dict(include_sensitive=False)
                    response_data['user']['last_activity'] = usuario.last_activity.isoformat() if usuario.last_activity else None
            
            return jsonify(response_data), 200
            
        except Exception as e:
            logger.error(f"Error obteniendo información de sesión: {str(e)}")
            return jsonify({
                'success': False,
                'error': 'Error al obtener información de sesión'
            }), 500
    
    @app.route('/api/auth/check', methods=['GET'])
    def auth_check():
        """
        Verificar estado del servicio de autenticación
        GET /api/auth/check
        """
        try:
            user_count = User.query.count()
            
            return jsonify({
                'success': True,
                'status': 'active',
                'service': 'authentication',
                'users_registered': user_count,
                'jwt_configuration': {
                    'access_token_expires': str(app.config['JWT_ACCESS_TOKEN_EXPIRES']),
                    'access_token_expires_days': app.config['JWT_ACCESS_TOKEN_EXPIRES'].days,
                    'access_token_expires_seconds': app.config['JWT_ACCESS_TOKEN_EXPIRES'].total_seconds(),
                    'refresh_token_expires': str(app.config['JWT_REFRESH_TOKEN_EXPIRES']),
                    'refresh_token_expires_days': app.config['JWT_REFRESH_TOKEN_EXPIRES'].days
                },
                'timestamp': datetime.utcnow().isoformat()
            }), 200
        except Exception as e:
            logger.error(f"Error en auth check: {e}")
            return jsonify({
                'success': False,
                'status': 'error',
                'service': 'authentication',
                'error': str(e)
            }), 500
    
    # ========== RUTAS PÚBLICAS ==========
    
    @app.route('/api/tours', methods=['GET'])
    def get_tours():
        try:
            tours = Tour.query.filter_by(disponible=True).order_by(Tour.precio).all()
            tours_list = []
            for tour in tours:
                tours_list.append(tour.to_dict())
            return jsonify(tours_list)
        except Exception as e:
            logger.error(f"Error obteniendo tours: {e}")
            return jsonify({'error': 'Error obteniendo tours'}), 500
    
    @app.route('/api/blog', methods=['GET'])
    def get_blog_posts():
        try:
            posts = BlogPost.query.filter_by(publicado=True).order_by(BlogPost.created_at.desc()).limit(10).all()
            posts_list = []
            for post in posts:
                posts_list.append(post.to_dict())
            return jsonify(posts_list)
        except Exception as e:
            logger.error(f"Error obteniendo posts: {e}")
            return jsonify({'error': 'Error obteniendo posts'}), 500
    
    # ========== RUTAS PROTEGIDAS ==========
    
    @app.route('/api/user/profile', methods=['GET'])
    @jwt_required()
    def get_user_profile():
        try:
            current_identity = get_jwt_identity()
            
            # Obtener ID del usuario
            user_id = None
            if isinstance(current_identity, dict):
                user_id = current_identity.get('id')
            elif isinstance(current_identity, (int, str)):
                try:
                    user_id = int(current_identity)
                except:
                    user_id = None
            
            if not user_id:
                return jsonify({'error': 'Token inválido'}), 401
            
            update_user_activity(user_id)
            
            user = User.query.get(user_id)
            if not user:
                return jsonify({'error': 'Usuario no encontrado'}), 404
            
            return jsonify(user.to_dict())
        except Exception as e:
            logger.error(f"Error obteniendo perfil: {e}")
            return jsonify({'error': 'Error obteniendo perfil'}), 500
    
    @app.route('/api/user/bookings', methods=['GET'])
    @jwt_required()
    def get_user_bookings():
        try:
            current_identity = get_jwt_identity()
            
            # Obtener ID del usuario
            user_id = None
            if isinstance(current_identity, dict):
                user_id = current_identity.get('id')
            elif isinstance(current_identity, (int, str)):
                try:
                    user_id = int(current_identity)
                except:
                    user_id = None
            
            if not user_id:
                return jsonify({'success': False, 'error': 'Token inválido'}), 401
            
            update_user_activity(user_id)
            
            bookings = Booking.query.filter_by(user_id=user_id).order_by(Booking.created_at.desc()).all()
            bookings_list = []
            
            for booking in bookings:
                booking_dict = booking.to_dict()
                if booking.tour:
                    booking_dict['tour_nombre'] = booking.tour.nombre
                else:
                    booking_dict['tour_nombre'] = 'Tour no disponible'
                
                bookings_list.append(booking_dict)
            
            return jsonify({
                'success': True,
                'bookings': bookings_list,
                'count': len(bookings_list)
            })
            
        except Exception as e:
            logger.error(f"Get user bookings error: {e}")
            return jsonify({'success': False, 'error': 'Error obteniendo reservas'}), 500
    
    # ========== RUTAS DE ADMINISTRADOR ==========
    
    def admin_required(fn):
        @functools.wraps(fn)
        @jwt_required()
        def wrapper(*args, **kwargs):
            current_identity = get_jwt_identity()
            
            # Obtener ID del usuario
            user_id = None
            if isinstance(current_identity, dict):
                user_id = current_identity.get('id')
            elif isinstance(current_identity, (int, str)):
                try:
                    user_id = int(current_identity)
                except:
                    user_id = None
            
            if not user_id:
                return jsonify({'error': 'Token inválido'}), 401
            
            user = User.query.get(user_id)
            if not user or user.rol != 'admin':
                return jsonify({'error': 'Acceso solo para administradores'}), 403
            
            update_user_activity(user.id)
            return fn(*args, **kwargs)
        return wrapper
    
    @app.route('/api/admin/dashboard', methods=['GET'])
    @admin_required
    def admin_dashboard():
        try:
            stats = {
                'total_users': User.query.count(),
                'total_tours': Tour.query.count(),
                'total_bookings': Booking.query.count(),
                'total_blog_posts': BlogPost.query.count(),
                'pending_bookings': Booking.query.filter_by(estado='pending').count(),
                'active_tours': Tour.query.filter_by(disponible=True).count(),
                'active_users': User.query.filter_by(activo=True).count(),
                'active_sessions': User.query.filter(
                    User.last_activity > (datetime.utcnow() - timedelta(hours=24))
                ).count(),
                'recent_registrations': User.query.filter(
                    User.created_at > (datetime.utcnow() - timedelta(days=7))
                ).count()
            }
            
            return jsonify(stats)
        except Exception as e:
            logger.error(f"Error dashboard admin: {e}")
            return jsonify({'error': 'Error obteniendo estadísticas'}), 500
    
    @app.route('/api/admin/users', methods=['GET'])
    @admin_required
    def get_all_users():
        try:
            users = User.query.all()
            users_list = [user.to_dict() for user in users]
            
            return jsonify({
                'success': True,
                'users': users_list,
                'count': len(users_list)
            })
        except Exception as e:
            logger.error(f"Error obteniendo usuarios: {e}")
            return jsonify({'success': False, 'error': 'Error obteniendo usuarios'}), 500
    
    # ========== MIDDLEWARE PARA TOKEN EXPIRADO ==========
    
    @app.after_request
    def add_cors_headers(response):
        """Añadir headers CORS a todas las respuestas"""
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
        return response
    
    # ========== MANEJADORES DE ERROR ==========
    
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({
            'success': False,
            'error': 'not_found',
            'message': 'Endpoint no encontrado',
            'path': request.path,
            'timestamp': datetime.utcnow().isoformat()
        }), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        logger.error(f'Server error: {error}')
        return jsonify({
            'success': False,
            'error': 'internal_server_error',
            'message': 'Error interno del servidor',
            'timestamp': datetime.utcnow().isoformat()
        }), 500
    
    @app.errorhandler(401)
    def unauthorized(error):
        return jsonify({
            'success': False,
            'error': 'unauthorized',
            'message': 'No autorizado',
            'timestamp': datetime.utcnow().isoformat()
        }), 401
    
    @app.errorhandler(403)
    def forbidden(error):
        return jsonify({
            'success': False,
            'error': 'forbidden',
            'message': 'Acceso prohibido',
            'timestamp': datetime.utcnow().isoformat()
        }), 403
    
    # ========== IMPRIMIR RESUMEN ==========
    print("\n" + "="*60)
    print("✅ APLICACIÓN CREADA EXITOSAMENTE - VERSIÓN CORREGIDA")
    print(f"📡 URL: http://{app.config['HOST']}:{app.config['PORT']}")
    print(f"🗄️  Base de datos: {app.config['SQLALCHEMY_DATABASE_URI'][:50]}...")
    print(f"🔐 Admin: admin@canosalao.com / admin123")
    print(f"⏱️  Access Token: {app.config['JWT_ACCESS_TOKEN_EXPIRES']} (30 días)")
    print(f"🔄 Refresh Token: {app.config['JWT_REFRESH_TOKEN_EXPIRES']} (1 año)")
    print(f"🌍 CORS Origins: {len(app.config['CORS_ORIGINS'])} configurados")
    print("✅ /health endpoint CORREGIDO para SQLAlchemy 2.x")
    print("="*60)
    print("📋 Endpoints disponibles:")
    print("  • GET  /                    - Página de inicio")
    print("  • GET  /api/status          - Estado del API")
    print("  • GET  /health              - Health check (corregido)")
    print("  • POST /api/auth/login      - Iniciar sesión")
    print("  • POST /api/auth/register   - Registrarse")
    print("  • GET  /api/auth/verify     - Verificar token")
    print("  • POST /api/auth/refresh    - Refrescar token")
    print("  • GET  /api/auth/profile    - Perfil de usuario")
    print("  • GET  /api/tours           - Listar tours")
    print("  • GET  /api/blog            - Listar posts del blog")
    print("  • GET  /api/admin/dashboard - Dashboard admin")
    print("="*60)
    
    return app

# ========== CREAR APLICACIÓN ==========
app = create_app()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"\n🚀 Iniciando servidor en puerto {port}...")
    app.run(
        host=app.config['HOST'],
        port=port,
        debug=app.config['DEBUG']
    )
