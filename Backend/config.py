# Backend/config.py - CONFIGURACIÓN CORREGIDA Y SEGURA
import os
from datetime import timedelta
from dotenv import load_dotenv

# Cargar variables de entorno desde .env
load_dotenv()

class Config:
    """Configuración para la aplicación Flask - Caño Salao"""
    
    # ========== CONFIGURACIÓN DE SEGURIDAD ==========
    # Claves secretas - Usar variables de entorno o valores por defecto para desarrollo
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-cano-salao-2024-turismo-barcelona-venezuela')
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'jwt-dev-secret-key-cano-salao-2024-sistema-turismo')
    
    # Configuración de seguridad adicional
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # ========== CONFIGURACIÓN DE BASE DE DATOS ==========
    # Base de datos SQLite por defecto, PostgreSQL en producción
    DATABASE_URL = os.environ.get('DATABASE_URL')
    
    if DATABASE_URL:
        # PostgreSQL en producción (render.com, railway.app, etc.)
        if DATABASE_URL.startswith('postgres://'):
            DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)
        SQLALCHEMY_DATABASE_URI = DATABASE_URL
    else:
        # SQLite para desarrollo local
        BASE_DIR = os.path.abspath(os.path.dirname(__file__))
        SQLALCHEMY_DATABASE_URI = f'sqlite:///{os.path.join(BASE_DIR, "instance", "cano_salao.db")}'
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_recycle': 300,
        'pool_pre_ping': True,
    }
    
    # ========== CONFIGURACIÓN JWT ==========
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=int(os.environ.get('JWT_ACCESS_HOURS', 24)))
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=int(os.environ.get('JWT_REFRESH_DAYS', 30)))
    JWT_TOKEN_LOCATION = ['headers']
    JWT_HEADER_NAME = 'Authorization'
    JWT_HEADER_TYPE = 'Bearer'
    
    # ========== CONFIGURACIÓN CORS ==========
    # Orígenes permitidos para desarrollo y producción
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', '').split(',') or [
        'http://localhost:3000',      # React dev server
        'http://127.0.0.1:3000',
        'http://localhost:5500',      # Live Server VS Code
        'http://127.0.0.1:5500',
        'http://localhost:8080',      # Otros servidores locales
        'http://127.0.0.1:8080',
        'http://localhost:5000',      # Flask dev server
        'http://127.0.0.1:5000',
    ]
    
    # Agregar dominio de producción si existe
    PRODUCTION_DOMAIN = os.environ.get('PRODUCTION_DOMAIN')
    if PRODUCTION_DOMAIN:
        CORS_ORIGINS.extend([
            f'https://{PRODUCTION_DOMAIN}',
            f'http://{PRODUCTION_DOMAIN}',
        ])
    
    CORS_SUPPORTS_CREDENTIALS = True
    CORS_EXPOSE_HEADERS = ['Content-Type', 'Authorization', 'X-Total-Count']
    
    # ========== CONFIGURACIÓN DEL SERVIDOR ==========
    HOST = os.environ.get('HOST', '0.0.0.0')
    PORT = int(os.environ.get('PORT', 5000))
    DEBUG = os.environ.get('FLASK_DEBUG', 'True').lower() == 'true'
    ENV = os.environ.get('FLASK_ENV', 'development')
    
    # ========== CONFIGURACIÓN DE LOGGING ==========
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO').upper()
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    # ========== CONFIGURACIÓN DE LA APLICACIÓN ==========
    APP_NAME = 'Caño Salao - Sistema de Turismo'
    APP_VERSION = '1.0.0'
    API_PREFIX = '/api'
    
    # ========== LÍMITES Y CONFIGURACIONES ADICIONALES ==========
    # Límite de tamaño para uploads (10MB)
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024
    
    # Tiempo de caché para respuestas estáticas
    SEND_FILE_MAX_AGE_DEFAULT = 300
    
    # Configuración para emails (opcional)
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'True').lower() == 'true'
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@canosalaotours.com')
    
    # Configuración para archivos
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx'}
    
    # ========== CONFIGURACIONES ESPECÍFICAS DEL PROYECTO ==========
    # Usuario administrador por defecto
    DEFAULT_ADMIN_EMAIL = 'admin@canosalaotours.com'
    DEFAULT_ADMIN_PASSWORD = 'admin123'  # Se debe cambiar en producción
    
    # Configuración para reservas
    MAX_BOOKING_DAYS_AHEAD = 90
    MIN_BOOKING_HOURS_NOTICE = 24
    MAX_PEOPLE_PER_BOOKING = 20
    
    # Configuración para tours
    DEFAULT_TOUR_CAPACITY = 15
    MIN_TOUR_DURATION_HOURS = 1
    MAX_TOUR_DURATION_HOURS = 8
    
    # ========== MÉTODOS ÚTILES ==========
    @classmethod
    def is_production(cls):
        """Verificar si estamos en producción"""
        return cls.ENV == 'production'
    
    @classmethod
    def is_development(cls):
        """Verificar si estamos en desarrollo"""
        return cls.ENV == 'development'
    
    @classmethod
    def print_config_summary(cls):
        """Imprimir resumen de configuración (seguro)"""
        import json
        
        config_summary = {
            'environment': cls.ENV,
            'debug': cls.DEBUG,
            'host': cls.HOST,
            'port': cls.PORT,
            'database': 'PostgreSQL' if 'postgresql' in cls.SQLALCHEMY_DATABASE_URI else 'SQLite',
            'cors_origins_count': len(cls.CORS_ORIGINS),
            'jwt_expires_hours': cls.JWT_ACCESS_TOKEN_EXPIRES.total_seconds() / 3600,
            'app_name': cls.APP_NAME,
            'api_prefix': cls.API_PREFIX,
        }
        
        print("\n" + "="*60)
        print("📋 RESUMEN DE CONFIGURACIÓN - Caño Salao")
        print("="*60)
        for key, value in config_summary.items():
            print(f"  {key.replace('_', ' ').title()}: {value}")
        print("="*60)
        
        # Advertencia de seguridad en desarrollo
        if cls.is_development():
            print("⚠️  MODO DESARROLLO - No usar en producción")
            print("   Considera configurar variables de entorno para:")
            print("   - SECRET_KEY")
            print("   - JWT_SECRET_KEY")
            print("   - DATABASE_URL (para PostgreSQL)")
            print("="*60)


# Configuración de producción
class ProductionConfig(Config):
    """Configuración para producción"""
    
    ENV = 'production'
    DEBUG = False
    SESSION_COOKIE_SECURE = True
    
    # En producción, se espera que todas las claves vengan de variables de entorno
    SECRET_KEY = os.environ.get('SECRET_KEY')
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY')
    
    # Validar configuraciones críticas en producción
    @classmethod
    def validate_production_config(cls):
        errors = []
        
        if not cls.SECRET_KEY or cls.SECRET_KEY.startswith('dev-'):
            errors.append("SECRET_KEY no configurada o insegura")
        
        if not cls.JWT_SECRET_KEY or cls.JWT_SECRET_KEY.startswith('dev-'):
            errors.append("JWT_SECRET_KEY no configurada o insegura")
        
        if not os.environ.get('DATABASE_URL'):
            errors.append("DATABASE_URL no configurada")
        
        if errors:
            raise RuntimeError(f"Errores en configuración de producción: {', '.join(errors)}")


# Configuración de testing
class TestingConfig(Config):
    """Configuración para testing"""
    
    ENV = 'testing'
    DEBUG = True
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'  # Base de datos en memoria
    CORS_ORIGINS = ['http://localhost:3000']
    
    # Desactivar JWT para testing
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(seconds=30)


# Configuración de desarrollo (por defecto)
class DevelopmentConfig(Config):
    """Configuración para desarrollo"""
    
    ENV = 'development'
    DEBUG = True
    
    # Habilitar logging SQL en desarrollo
    SQLALCHEMY_ECHO = True
    
    # Orígenes adicionales para desarrollo
    CORS_ORIGINS = Config.CORS_ORIGINS + [
        'http://localhost:8000',
        'http://127.0.0.1:8000',
    ]


# Diccionario de configuraciones disponibles
config_by_name = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig,
}


# Cargar configuración basada en FLASK_ENV
def get_config():
    """Obtener configuración basada en entorno"""
    env = os.environ.get('FLASK_ENV', 'development')
    config_class = config_by_name.get(env, DevelopmentConfig)
    
    print(f"📁 Cargando configuración para entorno: {env}")
    
    # Validar configuración de producción
    if env == 'production':
        try:
            ProductionConfig.validate_production_config()
        except RuntimeError as e:
            print(f"❌ Error: {e}")
            print("   Usando configuración de desarrollo como fallback")
            config_class = DevelopmentConfig
    
    return config_class


# Crear instancia de configuración
current_config = get_config()

# Imprimir resumen al importar
if __name__ != '__main__':
    current_config.print_config_summary()