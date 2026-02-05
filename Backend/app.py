# Backend/app.py - APLICACIÓN FLASK PARA RENDER.COM
import os
import sys
import logging
import functools  # ¡NUEVO IMPORT NECESARIO!
from datetime import timedelta, datetime
from flask import Flask, jsonify, request, send_from_directory
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
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
    # Claves secretas - Usar variables de entorno en producción
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-cano-salao-2024')
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'jwt-secret-key-cano-salao-2024')
    
    # Configuración de base de datos para Render
    # NOTA IMPORTANTE: En Render, necesitamos manejar DATABASE_URL que incluye postgresql://
    if os.environ.get('DATABASE_URL'):
        # Si hay DATABASE_URL de Render (PostgreSQL)
        SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL').replace('postgres://', 'postgresql://')
    else:
        # Usar SQLite localmente
        basedir = os.path.abspath(os.path.dirname(__file__))
        DATABASE_PATH = os.path.join(basedir, 'instance', 'cano_salao.db')
        SQLALCHEMY_DATABASE_URI = f'sqlite:///{DATABASE_PATH}'
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # ========== NUEVO: CONFIGURACIÓN DE SESIONES PERSISTENTES ==========
    # Configuración de JWT para sesiones más largas
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)  # Token de acceso: 24 horas
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)  # Token de refresh: 30 días
    
    # Configuración para tokens en cookies (más seguras)
    JWT_TOKEN_LOCATION = ['headers']  # También puedes usar ['cookies', 'headers']
    JWT_COOKIE_CSRF_PROTECT = False  # Desactivar para facilitar desarrollo
    
    # Configuración de sesiones Flask
    PERMANENT_SESSION_LIFETIME = timedelta(days=30)  # Sesiones de 30 días
    SESSION_COOKIE_NAME = 'cano_salao_session'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_SECURE = os.environ.get('FLASK_ENV') == 'production'  # True en producción
    
    # ========== FIN CONFIGURACIÓN SESIONES ==========
    
    # Configuración CORS para GitHub Pages y localhost
    CORS_ORIGINS = [
        'https://ricardjf.github.io',  # Tu GitHub Pages
        'http://localhost:5500',
        'http://127.0.0.1:5500',
        'http://localhost:3000',
        'http://127.0.0.1:3000',
    ]
    
    # Configuración del servidor para Render
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
            "allow_headers": ["Content-Type", "Authorization"],
            "supports_credentials": True,
            "expose_headers": ["Authorization"],  # Para que el frontend pueda leer el token
        }
    })
    print("✅ CORS configurado")
    
    # Inicializar JWT
    jwt = JWTManager(app)
    
    # Configurar JWT callbacks
    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        return jsonify({
            'success': False,
            'error': 'token_expired',
            'message': 'Tu sesión ha expirado'
        }), 401
    
    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        return jsonify({
            'success': False,
            'error': 'invalid_token',
            'message': 'Token inválido'
        }), 401
    
    @jwt.unauthorized_loader
    def unauthorized_callback(error):
        return jsonify({
            'success': False,
            'error': 'unauthorized',
            'message': 'No autorizado'
        }), 401
    
    print("✅ JWT configurado")
    
    # Inicializar base de datos
    db = SQLAlchemy(app)
    
    # Inicializar migraciones (solo si existe)
    try:
        migrate = Migrate(app, db)
        print("✅ Migraciones configuradas")
    except:
        print("⚠️  Migraciones no disponibles")
    
    # ========== MODELOS BÁSICOS ==========
    class User(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        nombre = db.Column(db.String(100), nullable=False)
        email = db.Column(db.String(120), unique=True, nullable=False)
        password = db.Column(db.String(200), nullable=False)
        rol = db.Column(db.String(20), default='user')
        activo = db.Column(db.Boolean, default=True)
        telefono = db.Column(db.String(20))
        created_at = db.Column(db.DateTime, default=datetime.utcnow)
        updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
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
    
    # ========== INICIALIZAR BASE DE DATOS ==========
    with app.app_context():
        try:
            # En Render con PostgreSQL, no necesitamos crear directorios
            if 'sqlite' in app.config['SQLALCHEMY_DATABASE_URI']:
                # Solo para SQLite: crear directorio instance si no existe
                os.makedirs(os.path.dirname(app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')), exist_ok=True)
            
            # Crear tablas
            db.create_all()
            print("✅ Base de datos inicializada")
            print(f"📁 URI de BD: {app.config['SQLALCHEMY_DATABASE_URI'][:50]}...")
            
            # Crear admin por defecto si no existe
            if User.query.count() == 0:
                admin = User(
                    nombre='Administrador',
                    email='admin@canosalao.com',
                    password=generate_password_hash('admin123'),
                    rol='admin',
                    telefono='+58 412-205-6558'
                )
                db.session.add(admin)
                
                # Crear tours de ejemplo
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
                
                # Crear artículo de blog de ejemplo
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
    
    # ========== RUTAS BÁSICAS ==========
    
    @app.route('/')
    def home():
        return jsonify({
            'success': True,
            'message': '🚤 API Caño Salao - Sistema de Turismo',
            'version': '1.0.0',
            'status': 'online',
            'endpoints': {
                'status': '/api/status',
                'health': '/health',
                'login': '/api/auth/login [POST]',
                'register': '/api/auth/register [POST]',
                'tours': '/api/tours [GET]',
                'blog': '/api/blog [GET]'
            },
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
            'database': 'connected' if db.engine.connect() else 'disconnected'
        })
    
    @app.route('/health')
    def health():
        try:
            db.session.execute('SELECT 1')
            return jsonify({'status': 'healthy', 'database': 'connected'})
        except:
            return jsonify({'status': 'unhealthy', 'database': 'disconnected'}), 500
    
    # ========== RUTAS DE AUTENTICACIÓN MEJORADAS ==========
    
    @app.route('/api/auth/login', methods=['POST'])
    def login():
        try:
            data = request.get_json()
            if not data or not data.get('email') or not data.get('password'):
                return jsonify({'success': False, 'error': 'Email y contraseña requeridos'}), 400
            
            # Verificar si el usuario quiere "recordar sesión"
            remember_me = data.get('remember_me', False)
            
            user = User.query.filter_by(email=data['email'], activo=True).first()
            if not user:
                return jsonify({'success': False, 'error': 'Credenciales incorrectas'}), 401
            
            if not check_password_hash(user.password, data['password']):
                return jsonify({'success': False, 'error': 'Credenciales incorrectas'}), 401
            
            # Configurar tiempo de expiración basado en remember_me
            expires_delta = timedelta(hours=24)  # Por defecto 24 horas
            
            # Crear token JWT
            access_token = create_access_token(
                identity={
                    'id': user.id,
                    'email': user.email,
                    'nombre': user.nombre,
                    'rol': user.rol
                },
                expires_delta=expires_delta
            )
            
            response_data = {
                'success': True,
                'token': access_token,
                'user': {
                    'id': user.id,
                    'nombre': user.nombre,
                    'email': user.email,
                    'rol': user.rol,
                    'telefono': user.telefono
                },
                'expires_in': int(expires_delta.total_seconds())
            }
            
            # Si remember_me es True, también crear refresh token
            if remember_me:
                # En un sistema más complejo, aquí crearías un refresh token
                # Por ahora, solo extendemos el tiempo del access token
                response_data['refresh_available'] = True
                response_data['message'] = 'Sesión recordada por 24 horas'
            else:
                response_data['message'] = 'Sesión iniciada correctamente'
            
            return jsonify(response_data)
            
        except Exception as e:
            logger.error(f"Login error: {e}")
            return jsonify({'success': False, 'error': 'Error en el servidor'}), 500
    
    # ========== NUEVO: ENDPOINT PARA REFRESCAR TOKEN ==========
    
    @app.route('/api/auth/refresh', methods=['POST'])
    @jwt_required(refresh=True)
    def refresh_token():
        try:
            current_user = get_jwt_identity()
            
            # Buscar usuario en la base de datos
            user = User.query.get(current_user['id'])
            if not user or not user.activo:
                return jsonify({
                    'success': False,
                    'error': 'usuario_no_encontrado',
                    'message': 'Usuario no encontrado o inactivo'
                }), 401
            
            # Crear nuevo token de acceso
            new_access_token = create_access_token(
                identity={
                    'id': user.id,
                    'email': user.email,
                    'nombre': user.nombre,
                    'rol': user.rol
                }
            )
            
            return jsonify({
                'success': True,
                'token': new_access_token,
                'user': {
                    'id': user.id,
                    'nombre': user.nombre,
                    'email': user.email,
                    'rol': user.rol
                },
                'message': 'Token refrescado correctamente'
            })
            
        except Exception as e:
            logger.error(f"Refresh token error: {e}")
            return jsonify({
                'success': False,
                'error': 'refresh_failed',
                'message': 'Error refrescando token'
            }), 401
    
    # ========== NUEVO: ENDPOINT PARA VERIFICAR SESIÓN ==========
    
    @app.route('/api/auth/validate', methods=['GET'])
    @jwt_required()
    def validate_session():
        try:
            current_user = get_jwt_identity()
            
            user = User.query.get(current_user['id'])
            if not user or not user.activo:
                return jsonify({
                    'success': False,
                    'valid': False,
                    'error': 'Sesión inválida'
                }), 401
            
            return jsonify({
                'success': True,
                'valid': True,
                'user': {
                    'id': user.id,
                    'nombre': user.nombre,
                    'email': user.email,
                    'rol': user.rol,
                    'telefono': user.telefono
                },
                'message': 'Sesión válida'
            })
            
        except Exception as e:
            logger.error(f"Session validation error: {e}")
            return jsonify({
                'success': False,
                'valid': False,
                'error': 'Error validando sesión'
            }), 401
    
    @app.route('/api/auth/register', methods=['POST'])
    def register():
        try:
            data = request.get_json()
            if not data or not data.get('email') or not data.get('password') or not data.get('nombre'):
                return jsonify({'success': False, 'error': 'Datos incompletos'}), 400
            
            # Verificar si el email ya existe
            existing_user = User.query.filter_by(email=data['email']).first()
            if existing_user:
                return jsonify({'success': False, 'error': 'El email ya está registrado'}), 400
            
            new_user = User(
                nombre=data['nombre'],
                email=data['email'],
                password=generate_password_hash(data['password']),
                rol='user',
                telefono=data.get('telefono', '')
            )
            
            db.session.add(new_user)
            db.session.commit()
            
            # Crear token JWT
            access_token = create_access_token(
                identity={
                    'id': new_user.id,
                    'email': new_user.email,
                    'nombre': new_user.nombre,
                    'rol': new_user.rol
                }
            )
            
            return jsonify({
                'success': True,
                'token': access_token,
                'user': {
                    'id': new_user.id,
                    'nombre': new_user.nombre,
                    'email': new_user.email,
                    'rol': new_user.rol
                },
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
                tours_list.append({
                    'id': tour.id,
                    'nombre': tour.nombre,
                    'descripcion': tour.descripcion,
                    'precio': tour.precio,
                    'capacidad': tour.capacidad,
                    'duracion': tour.duracion,
                    'imagen_url': tour.imagen_url
                })
            return jsonify(tours_list)
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/blog', methods=['GET'])
    def get_blog_posts():
        try:
            posts = BlogPost.query.filter_by(publicado=True).order_by(BlogPost.created_at.desc()).limit(10).all()
            posts_list = []
            for post in posts:
                posts_list.append({
                    'id': post.id,
                    'titulo': post.titulo,
                    'excerpt': post.excerpt,
                    'categoria': post.categoria,
                    'autor': post.autor,
                    'imagen_url': post.imagen_url,
                    'vistas': post.vistas,
                    'created_at': post.created_at.isoformat()
                })
            return jsonify(posts_list)
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    # ========== RUTAS PROTEGIDAS ==========
    
    @app.route('/api/user/profile', methods=['GET'])
    @jwt_required()
    def get_profile():
        try:
            current_user = get_jwt_identity()
            user = User.query.get(current_user['id'])
            if not user:
                return jsonify({'error': 'Usuario no encontrado'}), 404
            
            return jsonify({
                'id': user.id,
                'nombre': user.nombre,
                'email': user.email,
                'rol': user.rol,
                'telefono': user.telefono,
                'created_at': user.created_at.isoformat(),
                'session_expires_in': int(app.config['JWT_ACCESS_TOKEN_EXPIRES'].total_seconds())
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    # ========== NUEVO: ENDPOINT PARA OBTENER TODAS LAS RESERVAS DEL USUARIO ==========
    
    @app.route('/api/user/bookings', methods=['GET'])
    @jwt_required()
    def get_user_bookings():
        try:
            current_user = get_jwt_identity()
            user_id = current_user['id']
            
            bookings = Booking.query.filter_by(user_id=user_id).order_by(Booking.created_at.desc()).all()
            bookings_list = []
            
            for booking in bookings:
                bookings_list.append({
                    'id': booking.id,
                    'codigo': booking.codigo,
                    'tour_nombre': booking.tour.nombre if booking.tour else 'Tour no disponible',
                    'fecha': booking.fecha.isoformat(),
                    'personas': booking.personas,
                    'total': booking.total,
                    'estado': booking.estado,
                    'created_at': booking.created_at.isoformat()
                })
            
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
            current_user = get_jwt_identity()
            data = request.get_json()
            
            if not data.get('tour_id') or not data.get('fecha') or not data.get('personas'):
                return jsonify({'error': 'Datos incompletos'}), 400
            
            tour = Tour.query.get(data['tour_id'])
            if not tour or not tour.disponible:
                return jsonify({'error': 'Tour no disponible'}), 400
            
            total = tour.precio * data['personas']
            codigo = f"RES-{datetime.now().strftime('%Y%m%d')}-{current_user['id']:03d}"
            
            new_booking = Booking(
                codigo=codigo,
                user_id=current_user['id'],
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
    
    # ========== RUTAS DE ADMINISTRADOR ==========
    
    def admin_required(fn):
        @functools.wraps(fn)  # ¡ESTO ES LO IMPORTANTE QUE FALTA!
        @jwt_required()
        def wrapper(*args, **kwargs):
            current_user = get_jwt_identity()
            if current_user['rol'] != 'admin':
                return jsonify({'error': 'Acceso solo para administradores'}), 403
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
                'active_tours': Tour.query.filter_by(disponible=True).count()
            }
            
            return jsonify(stats)
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/admin/tours', methods=['POST'])
    @admin_required
    def create_tour():
        try:
            data = request.get_json()
            if not data.get('nombre') or not data.get('precio'):
                return jsonify({'error': 'Nombre y precio requeridos'}), 400
            
            new_tour = Tour(
                nombre=data['nombre'],
                descripcion=data.get('descripcion', ''),
                precio=float(data['precio']),
                capacidad=data.get('capacidad', 15),
                duracion=data.get('duracion', ''),
                imagen_url=data.get('imagen_url', '')
            )
            
            db.session.add(new_tour)
            db.session.commit()
            
            return jsonify({
                'success': True,
                'tour': {
                    'id': new_tour.id,
                    'nombre': new_tour.nombre,
                    'precio': new_tour.precio,
                    'disponible': new_tour.disponible
                }
            }), 201
            
        except Exception as e:
            logger.error(f"Create tour error: {e}")
            db.session.rollback()
            return jsonify({'error': 'Error creando tour'}), 500
    
    # ========== NUEVO: MIDDLEWARE PARA MANEJAR SESIONES ==========
    
    @app.before_request
    def log_request_info():
        if app.config['DEBUG']:
            logger.info(f"Request: {request.method} {request.path}")
    
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
    print(f"⏱️  Duración de sesión: {app.config['JWT_ACCESS_TOKEN_EXPIRES']}")
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
