# Backend/models/__init__.py
"""
Módulo de modelos para Caño Salao Turismo
Inicializa la base de datos y exporta los modelos
"""

from flask_sqlalchemy import SQLAlchemy

# Inicializar SQLAlchemy
db = SQLAlchemy()

# Importar modelos para que estén disponibles
from .user import User, EmailVerificationToken, PasswordResetToken, create_default_admin
# Aquí puedes agregar más modelos cuando los crees:
# from .tour import Tour
# from .booking import Booking
# from .review import Review

# Lista de todos los modelos para facilitar importaciones
__all__ = [
    'db',
    'User',
    'EmailVerificationToken', 
    'PasswordResetToken',
    'create_default_admin',
    # 'Tour',
    # 'Booking',
    # 'Review'
]

# Función para inicializar la base de datos
def init_database(app):
    """
    Inicializa la base de datos con la aplicación Flask
    
    Args:
        app: Instancia de la aplicación Flask
    """
    db.init_app(app)
    
    # Crear tablas si no existen
    with app.app_context():
        try:
            db.create_all()
            print("✅ Tablas de base de datos creadas/verificadas")
            
            # Crear usuario admin por defecto
            create_default_admin()
            
            # Agregar datos de prueba en desarrollo
            if app.config.get('DEBUG', False):
                create_test_data()
                
        except Exception as e:
            print(f"⚠️  Error inicializando base de datos: {e}")
            if app.config.get('DEBUG', False):
                import traceback
                traceback.print_exc()


def create_test_data():
    """Crea datos de prueba para desarrollo"""
    try:
        from .user import User
        
        # Contar usuarios existentes
        user_count = User.query.count()
        
        # Si no hay usuarios además del admin, crear algunos de prueba
        if user_count <= 1:  # Solo admin existe
            test_users = [
                {
                    'nombre': 'Juan Pérez',
                    'email': 'juan.perez@example.com',
                    'password': 'demo123',
                    'rol': 'user',
                    'telefono': '+58 412-1234567',
                    'ciudad': 'Barcelona',
                    'estado': 'Anzoátegui',
                    'email_verificado': True
                },
                {
                    'nombre': 'María Gómez',
                    'email': 'maria.gomez@example.com',
                    'password': 'demo123',
                    'rol': 'user',
                    'telefono': '+58 414-9876543',
                    'ciudad': 'Puerto La Cruz',
                    'estado': 'Anzoátegui',
                    'email_verificado': True
                },
                {
                    'nombre': 'Carlos Rodríguez',
                    'email': 'carlos.rodriguez@example.com',
                    'password': 'demo123',
                    'rol': 'editor',
                    'telefono': '+58 424-5551234',
                    'ciudad': 'Lechería',
                    'estado': 'Anzoátegui',
                    'email_verificado': True
                }
            ]
            
            created_count = 0
            for user_data in test_users:
                # Verificar si el usuario ya existe
                existing_user = User.find_by_email(user_data['email'])
                if not existing_user:
                    try:
                        user = User(
                            nombre=user_data['nombre'],
                            email=user_data['email'],
                            telefono=user_data['telefono'],
                            rol=user_data['rol'],
                            ciudad=user_data['ciudad'],
                            estado=user_data['estado'],
                            email_verificado=user_data['email_verificado']
                        )
                        user.set_password(user_data['password'])
                        db.session.add(user)
                        created_count += 1
                    except Exception as e:
                        print(f"⚠️  Error creando usuario de prueba {user_data['email']}: {e}")
            
            if created_count > 0:
                db.session.commit()
                print(f"✅ {created_count} usuarios de prueba creados")
            else:
                print("✅ Datos de prueba ya existen")
                
    except Exception as e:
        db.session.rollback()
        print(f"⚠️  Error creando datos de prueba: {e}")


# Función para limpiar la base de datos (solo para testing)
def clear_database():
    """
    Elimina todas las tablas (¡PELIGROSO! Solo para testing)
    """
    with db.engine.connect() as conn:
        conn.execute("PRAGMA foreign_keys = OFF")
        db.drop_all()
        db.create_all()
        conn.execute("PRAGMA foreign_keys = ON")
    print("⚠️  Base de datos limpiada completamente")


# Función para obtener información de la base de datos
def get_database_info():
    """
    Obtiene información sobre el estado de la base de datos
    """
    info = {
        'engine': str(db.engine),
        'tables': [],
        'models': []
    }
    
    try:
        # Obtener tablas existentes
        inspector = db.inspect(db.engine)
        info['tables'] = inspector.get_table_names()
        
        # Obtener modelos registrados
        info['models'] = [cls.__name__ for cls in db.Model._decl_class_registry.values() 
                         if hasattr(cls, '__table__')]
        
    except Exception as e:
        info['error'] = str(e)
    
    return info


# Configurar para evitar imports circulares
def setup_models(app):
    """
    Configura los modelos con la aplicación Flask
    """
    db.init_app(app)
    return db


print(f"✅ Módulo de modelos cargado: {__name__}")