# Backend/scripts/init_simple.py
import sys
import os

def main():
    print("🔧 INICIALIZADOR SIMPLIFICADO - CAÑO SALAO")
    print("=" * 50)
    
    # Configurar path
    backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, backend_dir)
    
    try:
        print("📦 Importando módulos...")
        from app import init_database
        
        print("🗄️  Inicializando base de datos...")
        success = init_database()
        
        if success:
            print("\n🎉 ¡TODO LISTO!")
            print("=" * 50)
            print("✅ Base de datos inicializada correctamente")
            print("✅ Usuario admin: admin@canosalao.com / admin123")
            print("\n🚀 Ahora puedes ejecutar el servidor:")
            print("   python Backend/Run.py")
        else:
            print("\n❌ La inicialización falló. Revisa los mensajes de error.")
            
    except ImportError as e:
        print(f"❌ Error de importación: {e}")
        print("\n💡 Soluciones:")
        print("1. Asegúrate de que app.py existe en Backend/")
        print("2. Ejecuta: pip install flask flask-sqlalchemy flask-jwt-extended flask-cors")
        print("3. Verifica la estructura de carpetas")
        
    except Exception as e:
        print(f"❌ Error inesperado: {e}")

if __name__ == '__main__':
    main()