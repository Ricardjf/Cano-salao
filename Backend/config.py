# Backend/config.py - CONFIGURACIÓN OPTIMIZADA PARA RENDER.COM
import os
from datetime import timedelta
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

class Config:
    """Configuración base para la aplicación Flask"""
    
    # ========== CONFIGURACIÓN BÁSICA ==========
    # Nombre de la aplicación
    APP_NAME = 'Caño Salao Turismo API'
    APP_VERSION = '1.0.0'
    API_PREFIX = '/api'
    
    # ========== CONFIGURACIÓN DE SEGURIDAD ==========
    # Claves secretas - OBLIGATORIAS en producción
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-cano-salao-2024-turismo'
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'jwt-dev-secret-key-cano-salao-2024'
    
    # ========== CONFIGURACIÓN DE BASE DE DATOS ==========
    # Para Render.com: usar ruta absoluta para SQLite
    basedir = os.path.abspath(os.path.dirname(__file__))
    
    # DATABASE_URL de Render o SQLite local
    DATABASE_URL = os.environ.get('DATABASE_URL')
    
    if DATABASE_URL and DATABASE_URL.startswith('postgres://'):
        # Si Render proporciona PostgreSQL
        DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)
        SQLALCHEMY_DATABASE_URI = DATABASE_URL
        print("🗄️  Usando PostgreSQL (Render)")
    else:
        # SQLite para desarrollo y Render
        instance_dir = os.path.join(basedir, 'instance')
        os.makedirs(instance_dir, exist_ok=True)
        db_path = os.path.join(instance_dir, 'cano_salao.db')
        SQLALCHEMY_DATABASE_URI = f'sqlite:///{db_path}'
        print(f"🗄️  Usando SQLite: {db_path}")
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_recycle': 300,
        'pool_pre_ping': True,
    }
    
    # ========== CONFIGURACIÓN JWT ==========
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(days=7)  # 7 días para producción
    JWT_TOKEN_LOCATION = ['headers']
    JWT_HEADER_NAME = 'Authorization'
    JWT_HEADER_TYPE = 'Bearer'
    
    # ========== CONFIGURACIÓN CORS ==========
    # Orígenes permitidos - GitHub Pages y localhost
    CORS_ORIGINS_STRING = os.environ.get('CORS_ORIGINS', '')
    
    if CORS_ORIGINS_STRING:
        CORS_ORIGINS = [origin.strip() for origin in CORS_ORIGINS_STRING.split(',')]
    else:
        CORS_ORIGINS = [
            'http://localhost:5500',      # VS Code Live Server
            'http://127.0.0.1:5500',
            'http://localhost:5000',      # Flask dev server
            'http://127.0.0.1:5000',
            'http://localhost:3000',      # React/Node dev
            'http://127.0.0.1:3000',
            'https://*.github.io',        # Cualquier GitHub Pages
        ]
    
    # Agregar dominio específico si se proporciona
    SPECIFIC_DOMAIN = os.environ.get('SPECIFIC_DOMAIN')
    if SPECIFIC_DOMAIN:
        CORS_ORIGINS.extend([
            f'https://{SPECIFIC_DOMAIN}',
            f'http://{SPECIFIC_DOMAIN}',
        ])
    
    CORS_SUPPORTS_CREDENTIALS = True
    CORS_EXPOSE_HEADERS = ['Content-Type', 'Authorization', 'X-Total-Count']
    
    # ========== CONFIGURACIÓN DEL SERVIDOR ==========
    HOST = os.environ.get('HOST', '0.0.0.0')  # Render usa 0.0.0.0
    PORT = int(os.environ.get('PORT', 5000))  # Render asigna puerto automático
    
    # Entorno
    ENV = os.environ.get('FLASK_ENV', 'development')
    DEBUG = os.environ.get('FLASK_DEBUG', 'True').lower() == 'true'
    
    # ========== CONFIGURACIÓN DE LOGGING ==========
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    # ========== LÍMITES Y CONFIGURACIONES ADICIONALES ==========
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB máximo para uploads
    SEND_FILE_MAX_AGE_DEFAULT = 300  # 5 minutos caché
    
    # ========== CONFIGURACIONES ESPECÍFICAS DEL PROYECTO ==========
    # Credenciales por defecto (CAMBIAR EN PRODUCCIÓN)
    DEFAULT_ADMIN_EMAIL = os.environ.get('DEFAULT_ADMIN_EMAIL', 'admin@canosalao.com')
    DEFAULT_ADMIN_PASSWORD = os.environ.get('DEFAULT_ADMIN_PASSWORD', 'admin123')
    
    # Configuración de reservas
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
        """Imprimir resumen de configuración"""
        print("\n" + "="*60)
        print("📋 RESUMEN DE CONFIGURACIÓN - Caño Salao")
        print("="*60)
        print(f"  Entorno: {cls.ENV}")
        print(f"  Debug: {cls.DEBUG}")
        print(f"  Host: {cls.HOST}")
        print(f"  Puerto: {cls.PORT}")
        print(f"  Base de datos: {'PostgreSQL' if 'postgresql' in cls.SQLALCHEMY_DATABASE_URI else 'SQLite'}")
        print(f"  Orígenes CORS: {len(cls.CORS_ORIGINS)} configurados")
        print(f"  Nombre App: {cls.APP_NAME}")
        print(f"  Versión: {cls.APP_VERSION}")
        
        # Advertencias importantes
        if cls.is_production():
            print("\n⚠️  VERIFICACIONES DE PRODUCCIÓN:")
            if cls.SECRET_KEY.startswith('dev-'):
                print("  ❌ SECRET_KEY insegura - Cambia en variables de entorno")
            if cls.JWT_SECRET_KEY.startswith('dev-'):
                print("  ❌ JWT_SECRET_KEY insegura - Cambia en variables de entorno")
            if cls.DEFAULT_ADMIN_PASSWORD == 'admin123':
                print("  ⚠️  Contraseña admin por defecto - Cambia DEFAULT_ADMIN_PASSWORD")
        else:
            print(f"\n🔧 MODO DESARROLLO - Credenciales de prueba:")
            print(f"  Email: {cls.DEFAULT_ADMIN_EMAIL}")
            print(f"  Contraseña: {cls.DEFAULT_ADMIN_PASSWORD}")
        
        print("="*60)


# Configuración de producción - Render.com
class ProductionConfig(Config):
    """Configuración optimizada para producción en Render.com"""
    
    ENV = 'production'
    DEBUG = False
    
    # En producción, NO usar valores por defecto
    SECRET_KEY = os.environ.get('SECRET_KEY')
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY')
    
    # CORS más restrictivo en producción
    @property
    def CORS_ORIGINS(self):
        origins = []
        
        # Tu dominio específico de GitHub Pages
        github_pages = os.environ.get('GITHUB_PAGES_URL')
        if github_pages:
            origins.append(github_pages)
        
        # Render dashboard (opcional)
        render_dashboard = os.environ.get('RENDER_DASHBOARD_URL')
        if render_dashboard:
            origins.append(render_dashboard)
        
        return origins if origins else ['https://*.github.io']
    
    @classmethod
    def validate_production_config(cls):
        """Validar configuración crítica para producción"""
        errors = []
        
        # Verificar claves secretas
        if not cls.SECRET_KEY:
            errors.append("SECRET_KEY no configurada en variables de entorno")
        elif cls.SECRET_KEY.startswith('dev-') or len(cls.SECRET_KEY) < 32:
            errors.append("SECRET_KEY insegura - debe tener al menos 32 caracteres")
        
        if not cls.JWT_SECRET_KEY:
            errors.append("JWT_SECRET_KEY no configurada en variables de entorno")
        elif cls.JWT_SECRET_KEY.startswith('dev-') or len(cls.JWT_SECRET_KEY) < 32:
            errors.append("JWT_SECRET_KEY insegura - debe tener al menos 32 caracteres")
        
        # Verificar origen CORS para producción
        if not cls.CORS_ORIGINS:
            errors.append("CORS_ORIGINS no configurada para producción")
        
        if errors:
            error_msg = "\n".join([f"  • {error}" for error in errors])
            raise ValueError(f"Errores en configuración de producción:\n{error_msg}")


# Configuración de desarrollo
class DevelopmentConfig(Config):
    """Configuración para desarrollo local"""
    
    ENV = 'development'
    DEBUG = True
    
    # Mostrar consultas SQL en desarrollo
    SQLALCHEMY_ECHO = True
    
    # Más orígenes para desarrollo
    @property
    def CORS_ORIGINS(self):
        return super().CORS_ORIGINS + [
            'http://localhost:8080',
            'http://127.0.0.1:8080',
            'http://localhost:8000',
            'http://127.0.0.1:8000',
        ]


# Configuración de testing
class TestingConfig(Config):
    """Configuración para pruebas"""
    
    ENV = 'testing'
    DEBUG = True
    TESTING = True
    
    # Base de datos en memoria para pruebas
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    
    # CORS mínimo para pruebas
    CORS_ORIGINS = ['http://localhost:3000']


# Diccionario de configuraciones
config_by_name = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig,
}


# Función para obtener la configuración correcta
def get_config():
    """Obtener configuración basada en FLASK_ENV"""
    env = os.environ.get('FLASK_ENV', 'development').lower()
    
    print(f"\n🌍 Entorno detectado: {env}")
    
    # Obtener clase de configuración
    config_class = config_by_name.get(env, DevelopmentConfig)
    
    # Crear instancia de configuración
    config_instance = config_class()
    
    # Validar configuración de producción
    if env == 'production':
        try:
            ProductionConfig.validate_production_config()
            print("✅ Configuración de producción validada")
        except ValueError as e:
            print(f"❌ ERROR en configuración de producción:")
            print(e)
            print("\n⚠️  Cambiando a configuración de desarrollo")
            config_instance = DevelopmentConfig()
    
    return config_instance


# Configuración actual
current_config = get_config()

# Imprimir resumen al cargar el módulo
if __name__ != '__main__':
    current_config.print_config_summary()
