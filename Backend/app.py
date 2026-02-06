# Backend/app.py - APLICACIÓN FLASK CORREGIDA CON JWT FUNCIONAL
import os
import sys
import logging
import functools
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
print("🚀 INICIANDO CAÑO SALAO - BACKEND API")
print("="*60)

# ========== CONFIGURACIÓN BÁSICA ==========
class Config:
    # Claves secretas
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-cano-salao-2024')
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'jwt-secret-key-cano-salao-2024')
    
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
    JWT_TOKEN_LOCATION = ['headers']  # También podemos usar cookies
    
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
    
    # ========== CALLBACKS JWT CORREGIDOS ==========
    
    # ¡IMPORTANTE! user_identity_lookup debe devolver un STRING, no un dict
    @jwt.user_identity_loader
    def user_identity_lookup(user):
        """
        user_identity_lookup debe devolver un STRING (no dict)
        Se llama cuando creamos un token
        """
        # user es un dict con datos del usuario
        # Devolvemos solo el ID como string
        return str(user.get('id', ''))
    
    # ¡IMPORTANTE! user_lookup_callback se usa cuando verificamos un token
    @jwt.user_lookup_loader
    def user_lookup_callback(_jwt_header, jwt_data):
        """
        Se llama cuando verificamos un token
        jwt_data["sub"] contiene el identity (el string que devolvimos arriba)
        """
        identity = jwt_data["sub"]  # Esto es el string ID del usuario
        
        # Buscar usuario en base de datos
        user = User.query.get(int(identity)) if identity else None
        
        if user:
            # Devolvemos un dict con los datos del usuario
            return {
                'id': user.id,
                'email': user.email,
                'nombre': user.nombre,
                'rol': user.rol
            }
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
        last_login = db.Column(db.DateTime)
        last_activity = db.Column(db.DateTime)
        created_at = db.Column(db.DateTime, default=datetime.utcnow)
        updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
        
        def to_dict(self):
            return {
                'id': self.id,
                'nombre': self.nombre,
                'email': self.email,
                'rol': self.rol,
                'activo': self.activo,
                'telefono': self.telefono,
                'last_login': self.last_login.isoformat() if self.last_login else None,
                'created_at': self.created_at.isoformat() if self.created_at else None
            }
        
        def to_auth_dict(self):
            return {
                'id': self.id,
                'nombre': self.nombre,
                'email': self.email,
                'rol': self.rol,
                'telefono': self.telefono
            }
    
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
                    password=generate_password_hash('admin123'),
                    rol='admin',
                    telefono='+58 412-205-6558',
                    last_login=datetime.utcnow()
                )
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
    
    # ========== RUTAS BÁSICAS ==========
    
    @app.route('/')
    def home():
        return jsonify({
            'success': True,
            'message': '🚤 API Caño Salao - Sistema de Turismo',
            'version': '1.0.0',
            'status': 'online',
            'timestamp': datetime.utcnow().isoformat()
        })
    
    @app.route('/api/status')
    def api_status():
        return jsonify({
            'success': True,
            'status': 'online',
            'service': 'cano-salao-api',
            'environment': app.config['ENV'],
            'timestamp': datetime.utcnow().isoformat(),
            'jwt_expires_access': str(app.config['JWT_ACCESS_TOKEN_EXPIRES']),
            'jwt_expires_refresh': str(app.config['JWT_REFRESH_TOKEN_EXPIRES'])
        })
    
    @app.route('/health')
    def health():
        try:
            db.session.execute('SELECT 1')
            return jsonify({'status': 'healthy', 'database': 'connected'})
        except:
            return jsonify({'status': 'unhealthy', 'database': 'disconnected'}), 500
    
    # ========== RUTAS DE AUTENTICACIÓN CORREGIDAS ==========
    
    @app.route('/api/auth/login', methods=['POST'])
    def login():
        try:
            data = request.get_json()
            if not data or not data.get('email') or not data.get('password'):
                return jsonify({'success': False, 'error': 'Email y contraseña requeridos'}), 400
            
            user = User.query.filter_by(email=data['email'], activo=True).first()
            if not user:
                return jsonify({'success': False, 'error': 'Credenciales incorrectas'}), 401
            
            if not check_password_hash(user.password, data['password']):
                return jsonify({'success': False, 'error': 'Credenciales incorrectas'}), 401
            
            # Actualizar último login
            user.last_login = datetime.utcnow()
            user.last_activity = datetime.utcnow()
            db.session.commit()
            
            # Crear tokens - ¡IMPORTANTE: identity debe ser un STRING (el ID del usuario)
            identity = str(user.id)  # Convertir ID a string
            
            access_token = create_access_token(
                identity=identity,
                expires_delta=app.config['JWT_ACCESS_TOKEN_EXPIRES']
            )
            
            refresh_token = create_refresh_token(
                identity=identity,
                expires_delta=app.config['JWT_REFRESH_TOKEN_EXPIRES']
            )
            
            response_data = {
                'success': True,
                'token': access_token,  # El frontend busca "token"
                'access_token': access_token,  # Para compatibilidad
                'refresh_token': refresh_token,
                'user': user.to_auth_dict(),
                'token_type': 'Bearer',
                'expires_in': int(app.config['JWT_ACCESS_TOKEN_EXPIRES'].total_seconds()),
                'refresh_expires_in': int(app.config['JWT_REFRESH_TOKEN_EXPIRES'].total_seconds()),
                'persistent_session': True
            }
            
            return jsonify(response_data)
            
        except Exception as e:
            logger.error(f"Login error: {e}")
            return jsonify({'success': False, 'error': 'Error en el servidor'}), 500
    
    # ========== ENDPOINT REFRESH TOKEN ==========
    
    @app.route('/api/auth/refresh', methods=['POST'])
    @jwt_required(refresh=True)
    def refresh():
        try:
            current_user_id = get_jwt_identity()  # Esto es un string ID
            
            # Verificar usuario
            user = User.query.get(int(current_user_id))
            if not user or not user.activo:
                return jsonify({
                    'success': False,
                    'error': 'Usuario no encontrado o inactivo'
                }), 401
            
            # Actualizar actividad
            user.last_activity = datetime.utcnow()
            db.session.commit()
            
            # Crear nuevo access token
            new_access_token = create_access_token(
                identity=current_user_id,  # Ya es string
                expires_delta=app.config['JWT_ACCESS_TOKEN_EXPIRES']
            )
            
            # Opcional: también refrescar el refresh token (rotación)
            new_refresh_token = create_refresh_token(
                identity=current_user_id,
                expires_delta=app.config['JWT_REFRESH_TOKEN_EXPIRES']
            )
            
            return jsonify({
                'success': True,
                'token': new_access_token,  # El frontend busca "token"
                'access_token': new_access_token,
                'refresh_token': new_refresh_token,
                'user': user.to_auth_dict(),
                'message': 'Token refrescado exitosamente',
                'expires_in': int(app.config['JWT_ACCESS_TOKEN_EXPIRES'].total_seconds())
            })
            
        except Exception as e:
            logger.error(f"Refresh error: {e}")
            return jsonify({
                'success': False,
                'error': 'Error refrescando token'
            }), 401
    
    # ========== ENDPOINT VERIFICACIÓN ==========
    
    @app.route('/api/auth/verify', methods=['GET'])
    @jwt_required()
    def verify_token():
        try:
            current_user_id = get_jwt_identity()  # String ID
            jwt_data = get_jwt()
            
            user = User.query.get(int(current_user_id))
            if not user or not user.activo:
                return jsonify({
                    'success': False,
                    'valid': False,
                    'error': 'Usuario no encontrado o inactivo'
                }), 401
            
            # Actualizar actividad
            update_user_activity(user.id)
            
            # Calcular tiempo restante
            expires_at = jwt_data.get('exp')
            import time
            current_time = time.time()
            time_left = expires_at - current_time if expires_at else 0
            
            return jsonify({
                'success': True,
                'valid': True,
                'user': user.to_auth_dict(),
                'token_info': {
                    'expires_at': expires_at,
                    'issued_at': jwt_data.get('iat'),
                    'time_left_seconds': time_left,
                    'time_left_days': time_left / (24 * 3600) if time_left > 0 else 0,
                    'type': 'access' if 'fresh' in jwt_data and jwt_data['fresh'] else 'refresh'
                }
            })
            
        except Exception as e:
            logger.error(f"Verify error: {e}")
            return jsonify({
                'success': False,
                'valid': False,
                'error': 'Error verificando token'
            }), 401
    
    @app.route('/api/auth/register', methods=['POST'])
    def register():
        try:
            data = request.get_json()
            if not data or not data.get('email') or not data.get('password') or not data.get('nombre'):
                return jsonify({'success': False, 'error': 'Datos incompletos'}), 400
            
            existing_user = User.query.filter_by(email=data['email']).first()
            if existing_user:
                return jsonify({'success': False, 'error': 'El email ya está registrado'}), 400
            
            new_user = User(
                nombre=data['nombre'],
                email=data['email'],
                password=generate_password_hash(data['password']),
                rol='user',
                telefono=data.get('telefono', ''),
                last_login=datetime.utcnow(),
                last_activity=datetime.utcnow()
            )
            
            db.session.add(new_user)
            db.session.commit()
            
            # Crear tokens automáticamente después de registro
            identity = str(new_user.id)  # Convertir ID a string
            
            access_token = create_access_token(
                identity=identity,
                expires_delta=app.config['JWT_ACCESS_TOKEN_EXPIRES']
            )
            
            refresh_token = create_refresh_token(
                identity=identity,
                expires_delta=app.config['JWT_REFRESH_TOKEN_EXPIRES']
            )
            
            return jsonify({
                'success': True,
                'token': access_token,  # El frontend busca "token"
                'access_token': access_token,
                'refresh_token': refresh_token,
                'user': new_user.to_auth_dict(),
                'message': 'Usuario registrado exitosamente'
            }), 201
            
        except Exception as e:
            logger.error(f"Register error: {e}")
            db.session.rollback()
            return jsonify({'success': False, 'error': 'Error en el servidor'}), 500
    
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
    def get_profile():
        try:
            current_user_id = get_jwt_identity()  # String ID
            update_user_activity(int(current_user_id))
            
            user = User.query.get(int(current_user_id))
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
            current_user_id = get_jwt_identity()  # String ID
            update_user_activity(int(current_user_id))
            
            bookings = Booking.query.filter_by(user_id=int(current_user_id)).order_by(Booking.created_at.desc()).all()
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
    
    @app.route('/api/bookings', methods=['POST'])
    @jwt_required()
    def create_booking():
        try:
            current_user_id = get_jwt_identity()  # String ID
            update_user_activity(int(current_user_id))
            
            data = request.get_json()
            
            if not data.get('tour_id') or not data.get('fecha') or not data.get('personas'):
                return jsonify({'error': 'Datos incompletos'}), 400
            
            tour = Tour.query.get(data['tour_id'])
            if not tour or not tour.disponible:
                return jsonify({'error': 'Tour no disponible'}), 400
            
            total = tour.precio * data['personas']
            codigo = f"RES-{datetime.now().strftime('%Y%m%d%H%M%S')}-{current_user_id.zfill(3)}"
            
            new_booking = Booking(
                codigo=codigo,
                user_id=int(current_user_id),
                tour_id=tour.id,
                fecha=datetime.strptime(data['fecha'], '%Y-%m-%d').date(),
                personas=data['personas'],
                total=total,
                estado='pending'
            )
            
            db.session.add(new_booking)
            db.session.commit()
            
            return jsonify({
                'success': True,
                'booking': {
                    'id': new_booking.id,
                    'codigo': new_booking.codigo,
                    'tour_nombre': tour.nombre,
                    'fecha': new_booking.fecha.isoformat(),
                    'personas': new_booking.personas,
                    'total': new_booking.total,
                    'estado': new_booking.estado
                }
            }), 201
            
        except Exception as e:
            logger.error(f"Booking error: {e}")
            db.session.rollback()
            return jsonify({'error': 'Error creando reserva'}), 500
    
    # ========== MIDDLEWARE PARA TOKEN EXPIRADO ==========
    
    @app.after_request
    def refresh_expiring_jwts(response):
        try:
            # Verificar si la respuesta contiene un token expirado
            if response.status_code == 401:
                response_json = response.get_json()
                if response_json and response_json.get('error') == 'token_expired':
                    # Aquí podríamos intentar un refresh automático
                    pass
            return response
        except:
            return response
    
    # ========== RUTAS DE ADMINISTRADOR ==========
    
    def admin_required(fn):
        @functools.wraps(fn)
        @jwt_required()
        def wrapper(*args, **kwargs):
            current_user_id = get_jwt_identity()
            user = User.query.get(int(current_user_id))
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
                'active_sessions': User.query.filter(
                    User.last_activity > (datetime.utcnow() - timedelta(hours=24))
                ).count()
            }
            
            return jsonify(stats)
        except Exception as e:
            logger.error(f"Error dashboard admin: {e}")
            return jsonify({'error': 'Error obteniendo estadísticas'}), 500
    
    # ========== MANEJADORES DE ERROR ==========
    
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({
            'success': False,
            'error': 'not_found',
            'message': 'Endpoint no encontrado'
        }), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        logger.error(f'Server error: {error}')
        return jsonify({
            'success': False,
            'error': 'internal_server_error',
            'message': 'Error interno del servidor'
        }), 500
    
    # ========== IMPRIMIR RESUMEN ==========
    print("\n" + "="*60)
    print("✅ APLICACIÓN CREADA EXITOSAMENTE")
    print(f"📡 URL: http://{app.config['HOST']}:{app.config['PORT']}")
    print(f"🗄️  Base de datos: {app.config['SQLALCHEMY_DATABASE_URI'][:50]}...")
    print(f"🔐 Admin: admin@canosalao.com / admin123")
    print(f"⏱️  Access Token: {app.config['JWT_ACCESS_TOKEN_EXPIRES']} (30 días)")
    print(f"🔄 Refresh Token: {app.config['JWT_REFRESH_TOKEN_EXPIRES']} (1 año)")
    print("="*60)
    
    return app

# ========== CREAR APLICACIÓN ==========
app = create_app()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(
        host=app.config['HOST'],
        port=port,
        debug=app.config['DEBUG']
    )
