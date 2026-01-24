# Backend/routes/__init__.py
"""
Módulo de rutas para Caño Salao Turismo
Organiza y registra todos los blueprints de la API
"""

from flask import Blueprint
import importlib
import pkgutil
import os
import logging

# Configurar logging
logger = logging.getLogger(__name__)

# Diccionario para almacenar todos los blueprints
blueprints = {}

# Blueprint principal de la API
api_bp = Blueprint('api', __name__, url_prefix='/api')
blueprints['api'] = api_bp


def register_all_blueprints(app):
    """
    Registra automáticamente todos los blueprints del directorio routes
    
    Args:
        app: Instancia de la aplicación Flask
    """
    print("🔧 Registrando blueprints...")
    
    # Obtener la ruta del directorio actual
    current_dir = os.path.dirname(__file__)
    
    # Listar todos los módulos en el directorio routes
    modules = []
    for _, module_name, is_pkg in pkgutil.iter_modules([current_dir]):
        if not is_pkg and module_name.endswith('_routes'):
            modules.append(module_name)
    
    print(f"📁 Encontrados {len(modules)} módulos de rutas: {', '.join(modules)}")
    
    # Importar y registrar cada blueprint
    for module_name in modules:
        try:
            # Importar el módulo
            module = importlib.import_module(f'.{module_name}', package='routes')
            
            # Buscar el blueprint en el módulo (debe llamarse <nombre>_bp)
            bp_name = module_name.replace('_routes', '_bp')
            if hasattr(module, bp_name):
                blueprint = getattr(module, bp_name)
                
                # Registrar el blueprint
                app.register_blueprint(blueprint)
                blueprints[module_name] = blueprint
                
                print(f"  ✅ {module_name}: registrado como {blueprint.name} ({blueprint.url_prefix})")
                
                # También registrar en el blueprint principal de API si aplica
                if blueprint.name != 'api':
                    api_bp.register_blueprint(blueprint, url_prefix=blueprint.url_prefix)
                    
            else:
                print(f"  ⚠️  {module_name}: No se encontró blueprint '{bp_name}'")
                
        except Exception as e:
            print(f"  ❌ Error registrando {module_name}: {e}")
            logger.error(f"Error registrando blueprint {module_name}: {str(e)}", exc_info=True)
    
    # Registrar el blueprint principal de API
    app.register_blueprint(api_bp)
    
    print(f"✅ Total blueprints registrados: {len(blueprints)}")
    return blueprints


def get_registered_routes(app):
    """
    Obtiene todas las rutas registradas en la aplicación
    
    Args:
        app: Instancia de la aplicación Flask
    
    Returns:
        Lista de diccionarios con información de las rutas
    """
    routes = []
    
    for rule in app.url_map.iter_rules():
        # Excluir rutas estáticas
        if rule.endpoint != 'static':
            route_info = {
                'endpoint': rule.endpoint,
                'methods': sorted(list(rule.methods - {'OPTIONS', 'HEAD'})),
                'path': rule.rule,
                'blueprint': rule.endpoint.split('.')[0] if '.' in rule.endpoint else 'main'
            }
            routes.append(route_info)
    
    # Ordenar por ruta
    routes.sort(key=lambda x: x['path'])
    
    return routes


def print_routes_summary(app):
    """
    Imprime un resumen de todas las rutas registradas
    
    Args:
        app: Instancia de la aplicación Flask
    """
    routes = get_registered_routes(app)
    
    print("\n" + "="*80)
    print("🗺️  RESUMEN DE RUTAS DE LA API")
    print("="*80)
    
    # Agrupar rutas por blueprint
    routes_by_bp = {}
    for route in routes:
        bp = route['blueprint']
        if bp not in routes_by_bp:
            routes_by_bp[bp] = []
        routes_by_bp[bp].append(route)
    
    # Imprimir por blueprint
    for bp_name in sorted(routes_by_bp.keys()):
        print(f"\n📋 {bp_name.upper()}:")
        print("-" * 40)
        
        for route in routes_by_bp[bp_name]:
            methods = ', '.join(route['methods'])
            print(f"  {methods:15} {route['path']}")
    
    print("="*80)
    print(f"Total rutas: {len(routes)}")
    print("="*80)


# Blueprints predefinidos (se registrarán automáticamente si existen)
__all__ = [
    'api_bp',
    'blueprints',
    'register_all_blueprints',
    'get_registered_routes',
    'print_routes_summary'
]

# Rutas de ejemplo para el blueprint principal
@api_bp.route('/')
def api_root():
    """
    Raíz de la API - Muestra información sobre los endpoints disponibles
    """
    from flask import current_app
    import json
    
    routes_info = []
    for rule in current_app.url_map.iter_rules():
        if rule.endpoint != 'static' and rule.rule.startswith('/api'):
            routes_info.append({
                'path': rule.rule,
                'methods': sorted(list(rule.methods - {'OPTIONS', 'HEAD'}))
            })
    
    return {
        'success': True,
        'message': 'Bienvenido a la API de Caño Salao Turismo',
        'version': '1.0.0',
        'endpoints': routes_info,
        'documentation': 'Ver /api/docs para documentación completa'
    }


@api_bp.route('/health')
def api_health():
    """
    Verificar estado de salud de la API
    """
    import datetime
    import psutil
    import os
    
    try:
        # Obtener información del sistema
        process = psutil.Process(os.getpid())
        memory_info = process.memory_info()
        
        health_info = {
            'status': 'healthy',
            'timestamp': datetime.datetime.utcnow().isoformat(),
            'service': 'cano-salao-api',
            'version': '1.0.0',
            'memory_usage_mb': round(memory_info.rss / (1024 * 1024), 2),
            'cpu_percent': process.cpu_percent(),
            'uptime_seconds': int((datetime.datetime.utcnow() - datetime.datetime.fromtimestamp(process.create_time())).total_seconds())
        }
        
        return {
            'success': True,
            'health': health_info
        }
        
    except Exception as e:
        return {
            'success': False,
            'status': 'degraded',
            'error': str(e),
            'timestamp': datetime.datetime.utcnow().isoformat()
        }, 503


@api_bp.route('/version')
def api_version():
    """
    Obtener información de versión de la API
    """
    import datetime
    
    return {
        'success': True,
        'api': {
            'name': 'Caño Salao Turismo API',
            'version': '1.0.0',
            'environment': 'development',
            'build_date': '2024-01-01',
            'documentation': '/api/docs'
        },
        'server': {
            'timestamp': datetime.datetime.utcnow().isoformat(),
            'timezone': 'UTC'
        }
    }


# Middleware para logging de peticiones API
@api_bp.before_request
def before_api_request():
    """
    Middleware para logging antes de procesar peticiones API
    """
    from flask import request
    import datetime
    
    # Registrar petición (excepto health checks)
    if request.endpoint not in ['api.api_health', 'static']:
        logger.info(f"API Request: {request.method} {request.path} - IP: {request.remote_addr}")
    
    # Añadir timestamp de inicio
    request.start_time = datetime.datetime.utcnow()


@api_bp.after_request
def after_api_request(response):
    """
    Middleware para logging después de procesar peticiones API
    """
    from flask import request
    import datetime
    
    # Calcular tiempo de respuesta
    if hasattr(request, 'start_time'):
        response_time = (datetime.datetime.utcnow() - request.start_time).total_seconds()
        response.headers['X-Response-Time'] = f'{response_time:.3f}s'
    
    # Headers personalizados para API
    response.headers['X-API-Version'] = '1.0.0'
    response.headers['X-API-Service'] = 'Caño Salao Turismo'
    
    # Registrar respuesta (excepto health checks)
    if request.endpoint not in ['api.api_health', 'static']:
        logger.info(f"API Response: {request.method} {request.path} - Status: {response.status_code} - Time: {response_time if hasattr(request, 'start_time') else 'N/A'}s")
    
    return response


print(f"✅ Módulo de rutas cargado: {__name__}")