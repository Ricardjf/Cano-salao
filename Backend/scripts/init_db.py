# Backend/scripts/init_db.py - VERSIÓN CORREGIDA
import sys
import os

# Agregar el directorio padre al path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def init_database():
    """Inicializar la base de datos con datos de ejemplo"""
    
    # Importar DENTRO de la función para evitar import circular
    from app import create_app
    from config import Config
    from models import db
    from models.usuarios import Usuario
    from models.tours import Tour
    
    # Crear app
    app = create_app(Config)
    
    with app.app_context():
        # Crear todas las tablas
        db.create_all()
        print("✅ Tablas creadas")
        
        # Verificar si ya hay datos
        if Usuario.query.first():
            print("⚠️  La base de datos ya tiene datos. Saltando inicialización.")
            return
        
        # Crear usuario administrador
        try:
            admin = Usuario(
                nombre='Administrador',
                email='admin@canosalao.com',
                password='Admin123',
                rol='admin'
            )
            db.session.add(admin)
            
            # Crear usuario normal
            usuario = Usuario(
                nombre='Usuario Demo',
                email='usuario@demo.com',
                password='Demo123',
                rol='user'
            )
            db.session.add(usuario)
            
            # Crear tours de ejemplo
            tours = [
                Tour(
                    nombre='Tour por el Río Caño Salao',
                    descripcion='Descubre la belleza natural del río Caño Salao con nuestro tour guiado. Observa la flora y fauna local mientras navegas por aguas cristalinas.',
                    duracion='3 horas',
                    precio=25.00,
                    capacidad_maxima=15,
                    imagen_url='/media/tour-rio.jpg'
                ),
                Tour(
                    nombre='Aventura en Kayak',
                    descripcion='Explora el río en kayak con nuestro equipo de guías expertos. Perfecto para aventureros y amantes de la naturaleza.',
                    duracion='2 horas',
                    precio=35.00,
                    capacidad_maxima=10,
                    imagen_url='/media/kayak.jpg'
                ),
                Tour(
                    nombre='Tour Fotográfico',
                    descripcion='Captura los mejores momentos del paisaje con nuestro tour especializado para fotógrafos. Incluye guía experto en fotografía.',
                    duracion='4 horas',
                    precio=45.00,
                    capacidad_maxima=8,
                    imagen_url='/media/fotografico.jpg'
                )
            ]
            
            for tour in tours:
                db.session.add(tour)
            
            # Guardar cambios
            db.session.commit()
            
            print("✅ Datos de ejemplo creados:")
            print(f"   • {Usuario.query.count()} usuarios")
            print(f"   • {Tour.query.count()} tours")
            print("✅ Base de datos inicializada correctamente!")
            
        except Exception as e:
            db.session.rollback()
            print(f"❌ Error al inicializar base de datos: {str(e)}")

if __name__ == '__main__':
    init_database()