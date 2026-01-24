# Backend/scripts/setup.py - Script simple para inicializar
import sqlite3
import os

def setup_database():
    """Crear base de datos SQLite directamente"""
    
    # Crear carpeta instance si no existe
    if not os.path.exists('instance'):
        os.makedirs('instance')
    
    # Ruta de la base de datos
    db_path = 'instance/canosalao.db'
    
    # Conectar a SQLite
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    print("🗄️  Creando base de datos SQLite...")
    
    # Crear tabla usuarios
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nombre TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        rol TEXT DEFAULT 'user',
        activo BOOLEAN DEFAULT 1,
        fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        ultimo_login TIMESTAMP
    )
    ''')
    
    # Crear tabla tours
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS tours (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nombre TEXT NOT NULL,
        descripcion TEXT NOT NULL,
        duracion TEXT NOT NULL,
        precio REAL NOT NULL,
        capacidad_maxima INTEGER NOT NULL,
        disponible BOOLEAN DEFAULT 1,
        imagen_url TEXT,
        fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Crear tabla reservas
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS reservas (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        usuario_id INTEGER NOT NULL,
        tour_id INTEGER NOT NULL,
        fecha_reserva DATE NOT NULL,
        cantidad_personas INTEGER NOT NULL,
        precio_total REAL NOT NULL,
        estado TEXT DEFAULT 'pendiente',
        notas TEXT,
        fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (usuario_id) REFERENCES usuarios (id),
        FOREIGN KEY (tour_id) REFERENCES tours (id)
    )
    ''')
    
    # Crear tabla contactos
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS contactos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nombre TEXT NOT NULL,
        email TEXT NOT NULL,
        telefono TEXT,
        asunto TEXT NOT NULL,
        mensaje TEXT NOT NULL,
        leido BOOLEAN DEFAULT 0,
        fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Insertar datos de ejemplo
    # Verificar si ya hay usuarios
    cursor.execute("SELECT COUNT(*) FROM usuarios")
    if cursor.fetchone()[0] == 0:
        # Insertar usuario admin (contraseña: Admin123)
        cursor.execute('''
        INSERT INTO usuarios (nombre, email, password_hash, rol) 
        VALUES (?, ?, ?, ?)
        ''', (
            'Administrador',
            'admin@canosalao.com',
            'pbkdf2:sha256:260000$K1YfG8zTkQ7LwHpJ$hash_admin',  # Hash de Admin123
            'admin'
        ))
        
        # Insertar usuario normal (contraseña: Demo123)
        cursor.execute('''
        INSERT INTO usuarios (nombre, email, password_hash) 
        VALUES (?, ?, ?)
        ''', (
            'Usuario Demo',
            'usuario@demo.com',
            'pbkdf2:sha256:260000$A2XgH9zUlR8MxIoK$hash_demo'  # Hash de Demo123
        ))
        
        # Insertar tours
        tours = [
            ('Tour por el Río Caño Salao', 
             'Descubre la belleza natural del río Caño Salao...',
             '3 horas', 25.00, 15, '/media/tour-rio.jpg'),
            ('Aventura en Kayak',
             'Explora el río en kayak con nuestro equipo de guías expertos...',
             '2 horas', 35.00, 10, '/media/kayak.jpg'),
            ('Tour Fotográfico',
             'Captura los mejores momentos del paisaje...',
             '4 horas', 45.00, 8, '/media/fotografico.jpg')
        ]
        
        for tour in tours:
            cursor.execute('''
            INSERT INTO tours (nombre, descripcion, duracion, precio, capacidad_maxima, imagen_url)
            VALUES (?, ?, ?, ?, ?, ?)
            ''', tour)
        
        print("✅ Datos de ejemplo insertados:")
        print("   • 2 usuarios creados")
        print("   • 3 tours creados")
    else:
        print("⚠️  La base de datos ya tiene datos")
    
    # Guardar cambios
    conn.commit()
    conn.close()
    
    print(f"✅ Base de datos creada en: {db_path}")
    print("📊 Tablas creadas: usuarios, tours, reservas, contactos")

if __name__ == '__main__':
    setup_database()