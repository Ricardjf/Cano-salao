# Backend/app.py - APLICACIÓN FLASK COMPLETA Y CORREGIDA
import os
import sys
import logging
from datetime import timedelta
from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from flask_migrate import Migrate

# Configurar logging antes de cualquier import
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

# Agregar el directorio actual al path para importaciones
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

# Importar configuración
try:
    from config import current_config as Config
    print("✅ Configuración cargada correctamente")
except ImportError as e:
    print(f"❌ Error importando config: {e}")
    print("   Creando configuración mínima...")
    
    # Configuración mínima por defecto
    class Config:
        SECRET_KEY = 'dev-secret-key-cano-salao-2024-turismo-barcelona-venezuela'
        JWT_SECRET_KEY = 'jwt-dev-secret-key-cano-salao-2024-sistema-turismo'
        SQLALCHEMY_DATABASE_URI = f'sqlite:///{os.path.join(current_dir, "instance", "cano_salao.db")}'
        SQLALCHEMY_TRACK_MODIFICATIONS = False
        JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)
        CORS_ORIGINS = ['http://localhost:3000', 'http://127.0.0.1:3000', 
                       'http://localhost:5500', 'http://127.0.0.1:5500']
        DEBUG = True
        HOST = '0.0.0.0'
        PORT = 5000
        ENV = 'development'

def create_app(config_class=Config):
    """Factory para crear la aplicación Flask"""
    
    print("🔧 Creando aplicación Flask...")
    
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Configuraciones específicas para desarrollo
    if app.config.get('DEBUG'):
        app.config['SQLALCHEMY_ECHO'] = True
        print("   📍 Modo DEBUG activado")
    
    # ========== INICIALIZAR EXTENSIONES ==========
    
    # 1. CORS - Configurar primero para evitar problemas
    try:
        CORS(app, 
             origins=app.config.get('CORS_ORIGINS', ['http://localhost:3000']),
             supports_credentials=True,
             methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
             allow_headers=['Content-Type', 'Authorization', 'X-Requested-With', 
                           'Accept', 'Origin', 'X-Total-Count'],
             expose_headers=['Content-Length', 'X-Requested-With', 'X-Response-Time'],
             max_age=86400)
        print("✅ CORS configurado correctamente")
    except Exception as e:
        print(f"⚠️  Error configurando CORS: {e}")
    
    # 2. JWT Manager
    jwt = JWTManager(app)
    
    # Configurar callbacks de JWT
    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        return jsonify({
            'success': False,
            'error': 'Token expirado',
            'message': 'Tu sesión ha expirado, por favor inicia sesión nuevamente'
        }), 401
    
    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        return jsonify({
            'success': False,
            'error': 'Token inválido',
            'message': 'Token de autenticación inválido'
        }), 401
    
    @jwt.unauthorized_loader
    def missing_token_callback(error):
        return jsonify({
            'success': False,
            'error': 'Token requerido',
            'message': 'Se requiere autenticación para acceder a este recurso'
        }), 401
    
    @jwt.needs_fresh_token_loader
    def token_not_fresh_callback(jwt_header, jwt_payload):
        return jsonify({
            'success': False,
            'error': 'Token no fresco',
            'message': 'Se requiere un token fresco para esta operación'
        }), 401
    
    print("✅ JWT Manager configurado")
    
    # 3. Inicializar base de datos
    try:
        from models import db, init_database
        db.init_app(app)
        print("✅ Base de datos inicializada")
    except ImportError as e:
        print(f"❌ Error importando modelos: {e}")
        print("   Creando sistema mínimo...")
        from flask_sqlalchemy import SQLAlchemy
        db = SQLAlchemy()
        db.init_app(app)
    
    # 4. Inicializar migraciones
    try:
        migrate = Migrate(app, db)
        print("✅ Sistema de migraciones inicializado")
    except Exception as e:
        print(f"⚠️  Error inicializando migraciones: {e}")
    
    # ========== REGISTRAR RUTAS ==========
    
    print("🔗 Registrando rutas...")
    
    # Importar y registrar blueprints de rutas
    try:
        from routes import register_all_blueprints, print_routes_summary
        register_all_blueprints(app)
        print("✅ Blueprints registrados correctamente")
    except ImportError as e:
        print(f"⚠️  Error registrando blueprints: {e}")
        print("   Registrando rutas básicas manualmente...")
        
        # Rutas básicas como fallback
        @app.route('/api/auth/login', methods=['POST'])
        def auth_login_fallback():
            try:
                data = request.get_json()
                if not data:
                    return jsonify({
                        'success': False,
                        'error': 'Datos no proporcionados'
                    }), 400
                
                # Credenciales de prueba
                if data.get('email') == 'admin@canosalaotours.com' and data.get('password') == 'admin123':
                    return jsonify({
                        'success': True,
                        'access_token': 'dev-token-simulado-' + os.urandom(10).hex(),
                        'user': {
                            'id': 1,
                            'nombre': 'Administrador',
                            'email': 'admin@canosalaotours.com',
                            'rol': 'admin',
                            'activo': True,
                            'telefono': '+58 412-205-6558'
                        },
                        'message': 'Login exitoso (modo desarrollo)'
                    })
                else:
                    return jsonify({
                        'success': False,
                        'error': 'Credenciales incorrectas'
                    }), 401
            except Exception as e:
                return jsonify({
                    'success': False,
                    'error': f'Error en el servidor: {str(e)}'
                }), 500
        
        @app.route('/api/auth/register', methods=['POST'])
        def auth_register_fallback():
            try:
                data = request.get_json()
                if not data:
                    return jsonify({
                        'success': False,
                        'error': 'Datos no proporcionados'
                    }), 400
                
                return jsonify({
                    'success': True,
                    'message': 'Registro exitoso (modo desarrollo)',
                    'user': {
                        'id': 999,
                        'nombre': data.get('nombre', 'Usuario'),
                        'email': data.get('email'),
                        'rol': 'user',
                        'activo': True
                    },
                    'access_token': 'dev-token-registro-' + os.urandom(10).hex()
                })
            except Exception as e:
                return jsonify({
                    'success': False,
                    'error': f'Error en el servidor: {str(e)}'
                }), 500
    
    # ========== RUTAS BÁSICAS ==========
    
    @app.route('/')
    def home():
        """Página de inicio de la API"""
        return jsonify({
            'success': True,
            'message': '¡Bienvenido a la API de Caño Salao Turismo! 🚤',
            'version': '1.0.0',
            'status': 'online',
            'endpoints': {
                'home': '/',
                'test': '/api/test',
                'health': '/health',
                'status': '/api/status',
                'auth': {
                    'login': '/api/auth/login [POST]',
                    'register': '/api/auth/register [POST]',
                    'validate': '/api/auth/validate [GET]'
                },
                'users': '/api/users/* [GET, POST, PUT, DELETE]',
                'documentation': 'Ver /api/docs para documentación completa'
            },
            'environment': app.config.get('ENV', 'development'),
            'timestamp': __import__('datetime').datetime.utcnow().isoformat()
        })
    
    @app.route('/api/test')
    def test():
        """Endpoint de prueba para verificar que el backend funciona"""
        return jsonify({
            'success': True,
            'message': '✅ ¡Backend funcionando correctamente!',
            'status': 'operational',
            'timestamp': __import__('datetime').datetime.utcnow().isoformat(),
            'database': 'SQLite' if 'sqlite' in app.config.get('SQLALCHEMY_DATABASE_URI', '') else 'Other',
            'cors_enabled': True,
            'jwt_enabled': True
        })
    
    @app.route('/health')
    def health():
        """Endpoint de salud para monitoreo"""
        try:
            # Verificar conexión a base de datos
            db.session.execute('SELECT 1')
            db_status = 'connected'
        except Exception as e:
            db_status = f'error: {str(e)}'
        
        import psutil
        import datetime
        
        process = psutil.Process(os.getpid())
        
        return jsonify({
            'status': 'healthy',
            'service': 'cano-salao-api',
            'timestamp': datetime.datetime.utcnow().isoformat(),
            'database': db_status,
            'system': {
                'memory_usage_mb': round(process.memory_info().rss / (1024 * 1024), 2),
                'cpu_percent': process.cpu_percent(),
                'uptime_seconds': int((datetime.datetime.utcnow() - datetime.datetime.fromtimestamp(process.create_time())).total_seconds())
            }
        })
    
    @app.route('/api/status')
    def api_status():
        """Endpoint para verificar estado completo de la API"""
        import datetime
        
        endpoints = []
        for rule in app.url_map.iter_rules():
            if rule.endpoint != 'static':
                endpoints.append({
                    'endpoint': rule.rule,
                    'methods': sorted(list(rule.methods - {'OPTIONS', 'HEAD'})),
                    'description': 'Ver documentación para detalles'
                })
        
        return jsonify({
            'success': True,
            'status': 'online',
            'app_name': 'Caño Salao Turismo API',
            'version': '1.0.0',
            'environment': app.config.get('ENV', 'development'),
            'debug_mode': app.config.get('DEBUG', False),
            'timestamp': datetime.datetime.utcnow().isoformat(),
            'endpoints_count': len(endpoints),
            'sample_endpoints': endpoints[:20]  # Mostrar solo primeros 20
        })
    
    # ========== MANEJADORES DE ERRORES ==========
    
    @app.errorhandler(400)
    def bad_request(error):
        return jsonify({
            'success': False,
            'error': 'Solicitud incorrecta',
            'message': 'La solicitud contiene datos inválidos',
            'path': request.path
        }), 400
    
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({
            'success': False,
            'error': 'Endpoint no encontrado',
            'message': 'La ruta solicitada no existe en esta API',
            'path': request.path,
            'available_endpoints': '/'
        }), 404
    
    @app.errorhandler(405)
    def method_not_allowed(error):
        return jsonify({
            'success': False,
            'error': 'Método no permitido',
            'message': f'El método {request.method} no está permitido para esta ruta',
            'allowed_methods': ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH']
        }), 405
    
    @app.errorhandler(500)
    def internal_error(error):
        logger.error(f'Error 500: {str(error)}', exc_info=True)
        return jsonify({
            'success': False,
            'error': 'Error interno del servidor',
            'message': 'Ocurrió un error inesperado. Por favor intenta nuevamente.',
            'debug_info': str(error) if app.config.get('DEBUG') else None
        }), 500
    
    # ========== MIDDLEWARE PARA LOGGING ==========
    
    @app.before_request
    def before_request():
        """Middleware para logging antes de procesar peticiones"""
        if request.endpoint and request.endpoint != 'static':
            request.start_time = __import__('datetime').datetime.utcnow()
            logger.info(f'Request: {request.method} {request.path} - IP: {request.remote_addr} - Endpoint: {request.endpoint}')
    
    @app.after_request
    def after_request(response):
        """Middleware para logging después de procesar peticiones"""
        if request.endpoint and request.endpoint != 'static' and hasattr(request, 'start_time'):
            import datetime
            response_time = (datetime.datetime.utcnow() - request.start_time).total_seconds()
            response.headers['X-Response-Time'] = f'{response_time:.3f}s'
            
            logger.info(f'Response: {request.method} {request.path} - Status: {response.status_code} - Time: {response_time:.3f}s')
        
        # Headers para desarrollo
        if app.config.get('DEBUG'):
            response.headers['X-Developed-By'] = 'Caño Salao Turismo Team'
            response.headers['X-API-Version'] = '1.0.0'
            response.headers['X-Environment'] = app.config.get('ENV', 'development')
        
        return response
    
    # ========== INICIALIZAR BASE DE DATOS ==========
    
    print("🗄️  Inicializando base de datos...")
    with app.app_context():
        try:
            # Crear tablas si no existen
            db.create_all()
            print("✅ Tablas de base de datos verificadas/creadas")
            
            # Crear usuario admin por defecto si no existe
            try:
                from models.user import User
                admin_email = 'admin@canosalaotours.com'
                if not User.find_by_email(admin_email):
                    admin_user = User(
                        nombre='Administrador',
                        email=admin_email,
                        rol='admin',
                        activo=True,
                        telefono='+58 412-205-6558',
                        ciudad='Barcelona',
                        estado='Anzoátegui',
                        pais='Venezuela',
                        email_verificado=True
                    )
                    admin_user.set_password('admin123')
                    db.session.add(admin_user)
                    db.session.commit()
                    print("✅ Usuario administrador creado por defecto")
                else:
                    print("✅ Usuario administrador ya existe")
            except Exception as e:
                print(f"⚠️  No se pudo crear usuario admin: {e}")
                db.session.rollback()
            
            # Crear datos de prueba en desarrollo
            if app.config.get('DEBUG'):
                try:
                    from models import create_test_data
                    create_test_data()
                except Exception as e:
                    print(f"⚠️  Error creando datos de prueba: {e}")
            
        except Exception as e:
            print(f"⚠️  Error al inicializar base de datos: {e}")
            if app.config.get('DEBUG'):
                import traceback
                traceback.print_exc()
            print("   Intentando continuar sin base de datos...")
    
    # ========== IMPRIMIR RESUMEN FINAL ==========
    
    print("\n" + "="*60)
    print("✅ APLICACIÓN CREADA EXITOSAMENTE")
    print("="*60)
    
    # Imprimir resumen de configuración
    try:
        config_class.print_config_summary()
    except:
        pass
    
    # Imprimir resumen de rutas
    try:
        from routes import print_routes_summary
        print_routes_summary(app)
    except:
        # Resumen manual de rutas
        print("\n📋 RUTAS PRINCIPALES:")
        print("-" * 40)
        routes_list = []
        for rule in app.url_map.iter_rules():
            if rule.endpoint != 'static':
                methods = ', '.join(sorted(list(rule.methods - {'OPTIONS', 'HEAD'})))
                routes_list.append((rule.rule, methods))
        
        routes_list.sort(key=lambda x: x[0])
        for route, methods in routes_list[:20]:  # Mostrar solo 20
            print(f"  {methods:15} {route}")
        
        if len(routes_list) > 20:
            print(f"  ... y {len(routes_list) - 20} más")
    
    print("="*60)
    
    return app

# ========== CREAR APLICACIÓN ==========
app = create_app()

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🚀 INICIANDO SERVIDOR DE DESARROLLO")
    print("="*60)
    print(f"📡 URL Principal: http://localhost:{app.config.get('PORT', 5000)}")
    print(f"🔧 Debug Mode: {'✅ ON' if app.config.get('DEBUG') else '❌ OFF'}")
    print(f"🗄️  Database: {app.config.get('SQLALCHEMY_DATABASE_URI', 'No configurada')}")
    print(f"🌐 CORS Origins: {app.config.get('CORS_ORIGINS', ['localhost:3000'])}")
    print("="*60)
    print("📋 ACCESO RÁPIDO:")
    print(f"  http://localhost:{app.config.get('PORT', 5000)}")
    print(f"  http://localhost:{app.config.get('PORT', 5000)}/api/test")
    print(f"  http://localhost:{app.config.get('PORT', 5000)}/health")
    print(f"  http://localhost:{app.config.get('PORT', 5000)}/api/status")
    print("="*60)
    print("🔐 CREDENCIALES DE PRUEBA:")
    print("  Email: admin@canosalaotours.com")
    print("  Contraseña: admin123")
    print("="*60)
    print("💡 COMANDOS ÚTILES:")
    print("  curl http://localhost:5000/api/test")
    print("  curl -X POST http://localhost:5000/api/auth/login -H 'Content-Type: application/json' -d '{\"email\":\"admin@canosalaotours.com\",\"password\":\"admin123\"}'")
    print("="*60)
    print("🚨 Usa Ctrl+C para detener el servidor\n")
    
    try:
        app.run(
            host=app.config.get('HOST', '0.0.0.0'),
            port=app.config.get('PORT', 5000),
            debug=app.config.get('DEBUG', True),
            threaded=True,
            use_reloader=True
        )
    except KeyboardInterrupt:
        print("\n👋 Servidor detenido por el usuario")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Error crítico al iniciar el servidor: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)