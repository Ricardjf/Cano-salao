# Backend/routes/auth_routes.py - VERSIÓN FINAL CORREGIDA
from datetime import timedelta
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import (
    create_access_token, 
    create_refresh_token,
    jwt_required, 
    get_jwt_identity,
    get_jwt
)
import re
import logging

# Configurar logging
logger = logging.getLogger(__name__)

auth_bp = Blueprint('auth', __name__)

# ========== VALIDACIONES ==========
def validate_email(email):
    """Valida formato de email"""
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(email_regex, email) is not None

def validate_password(password):
    """Valida fortaleza de contraseña"""
    if len(password) < 6:
        return False, "La contraseña debe tener al menos 6 caracteres"
    
    if len(password) > 50:
        return False, "La contraseña no puede exceder 50 caracteres"
    
    return True, "Contraseña válida"

def validate_name(name):
    """Valida nombre"""
    if not name or len(name.strip()) < 2:
        return False, "El nombre debe tener al menos 2 caracteres"
    
    if len(name) > 100:
        return False, "El nombre no puede exceder 100 caracteres"
    
    return True, "Nombre válido"

# ========== RUTAS DE AUTENTICACIÓN ==========
@auth_bp.route('/login', methods=['POST'])
def login():
    """
    Iniciar sesión
    POST /api/auth/login
    Body: { "email": "usuario@email.com", "password": "contraseña" }
    """
    try:
        data = request.get_json()
        
        if not data:
            logger.warning("Intento de login sin datos JSON")
            return jsonify({
                'success': False,
                'error': 'Se requiere datos en formato JSON'
            }), 400
        
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        # Validaciones básicas
        if not email or not password:
            return jsonify({
                'success': False,
                'error': 'Email y contraseña son requeridos'
            }), 400
        
        if not validate_email(email):
            return jsonify({
                'success': False,
                'error': 'Formato de email inválido'
            }), 400
        
        # Buscar usuario en base de datos
        try:
            from models.user import User
            usuario = User.find_by_email(email)
        except Exception as e:
            logger.error(f"Error al buscar usuario: {e}")
            return jsonify({
                'success': False,
                'error': 'Error interno del servidor'
            }), 500
        
        # Verificar usuario
        if not usuario:
            logger.warning(f"Intento de login con email no registrado: {email}")
            return jsonify({
                'success': False,
                'error': 'Credenciales inválidas'
            }), 401
        
        # Verificar si el usuario está activo
        if not usuario.is_active():
            logger.warning(f"Intento de login con usuario inactivo: {email}")
            return jsonify({
                'success': False,
                'error': 'Tu cuenta está desactivada. Contacta al administrador.'
            }), 403
        
        # Verificar contraseña
        if not usuario.check_password(password):
            logger.warning(f"Contraseña incorrecta para: {email}")
            return jsonify({
                'success': False,
                'error': 'Credenciales inválidas'
            }), 401
        
        # Actualizar último acceso
        try:
            from models import db
            usuario.ultimo_acceso = db.func.now()
            db.session.commit()
        except Exception as e:
            logger.warning(f"Error al actualizar último acceso: {e}")
            # Continuar aunque falle esta parte
        
        # Crear tokens - IDENTITY DEBE SER UN STRING (solo el ID)
        identity = str(usuario.id)  # ¡IMPORTANTE: Solo el ID como string!
        
        # OBTENER DURACIÓN CORRECTA - SESIONES DE 30 DÍAS
        jwt_expires = current_app.config.get('JWT_ACCESS_TOKEN_EXPIRES')
        
        # Manejar diferentes formatos de duración
        if isinstance(jwt_expires, (int, float)):
            expires_delta = timedelta(seconds=jwt_expires)
        elif isinstance(jwt_expires, timedelta):
            expires_delta = jwt_expires
        else:
            expires_delta = timedelta(days=30)
            logger.warning(f"Usando valor por defecto de 30 días para JWT")
        
        # Crear token de acceso con duración extendida
        access_token = create_access_token(
            identity=identity,
            expires_delta=expires_delta
        )
        
        # Crear refresh token (1 año)
        refresh_token = create_refresh_token(
            identity=identity,
            expires_delta=timedelta(days=365)
        )
        
        logger.info(f"Login exitoso: {email} (ID: {usuario.id}), Token expira en: {expires_delta}")
        
        # RESPUESTA CORREGIDA
        return jsonify({
            'success': True,
            'message': 'Inicio de sesión exitoso',
            'token': access_token,
            'access_token': access_token,
            'refresh_token': refresh_token,
            'user': {
                'id': usuario.id,
                'nombre': usuario.nombre,
                'email': usuario.email,
                'rol': usuario.rol,
                'activo': usuario.activo,
                'telefono': usuario.telefono
            },
            'token_type': 'Bearer',
            'expires_in': expires_delta.total_seconds(),
            'expires_days': expires_delta.days
        }), 200
        
    except Exception as e:
        logger.error(f"Error en login: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': 'Error interno del servidor'
        }), 500

@auth_bp.route('/register', methods=['POST'])
def register():
    """
    Registrar nuevo usuario
    POST /api/auth/register
    Body: {
        "nombre": "Nombre Completo",
        "email": "usuario@email.com", 
        "password": "contraseña",
        "telefono": "+58 412-1234567" (opcional)
    }
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'error': 'Se requiere datos en formato JSON'
            }), 400
        
        nombre = data.get('nombre', '').strip()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        telefono = data.get('telefono', '').strip()
        
        # Validaciones
        is_name_valid, name_msg = validate_name(nombre)
        if not is_name_valid:
            return jsonify({'success': False, 'error': name_msg}), 400
        
        if not validate_email(email):
            return jsonify({
                'success': False,
                'error': 'Formato de email inválido'
            }), 400
        
        is_password_valid, password_msg = validate_password(password)
        if not is_password_valid:
            return jsonify({'success': False, 'error': password_msg}), 400
        
        if telefono:
            from models.user import User
            if not User.validate_phone(telefono):
                return jsonify({
                    'success': False,
                    'error': 'Formato de teléfono inválido'
                }), 400
        
        # Verificar si el email ya existe
        try:
            from models.user import User
            if User.find_by_email(email):
                return jsonify({
                    'success': False,
                    'error': 'El email ya está registrado'
                }), 409
        except Exception as e:
            logger.error(f"Error al verificar email: {e}")
            return jsonify({
                'success': False,
                'error': 'Error interno del servidor'
            }), 500
        
        # Crear usuario
        try:
            from models import db
            from models.user import User
            
            # Determinar rol (primer usuario = admin, otros = user)
            user_count = User.query.count()
            rol = 'admin' if user_count == 0 else 'user'
            
            usuario = User(
                nombre=nombre,
                email=email,
                telefono=telefono,
                rol=rol,
                email_verificado=False
            )
            usuario.set_password(password)
            
            db.session.add(usuario)
            db.session.commit()
            
            # Crear tokens - IDENTITY DEBE SER UN STRING
            identity = str(usuario.id)  # Solo el ID como string
            
            access_token = create_access_token(
                identity=identity,
                expires_delta=timedelta(days=30)
            )
            
            refresh_token = create_refresh_token(
                identity=identity,
                expires_delta=timedelta(days=365)
            )
            
            logger.info(f"Nuevo usuario registrado: {email} (ID: {usuario.id}, Rol: {rol})")
            
            return jsonify({
                'success': True,
                'message': 'Registro exitoso. ¡Bienvenido/a!',
                'token': access_token,
                'access_token': access_token,
                'refresh_token': refresh_token,
                'user': {
                    'id': usuario.id,
                    'nombre': usuario.nombre,
                    'email': usuario.email,
                    'rol': usuario.rol,
                    'activo': usuario.activo,
                    'telefono': usuario.telefono
                },
                'is_first_user': rol == 'admin',
                'expires_in': timedelta(days=30).total_seconds()
            }), 201
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error al crear usuario: {str(e)}", exc_info=True)
            return jsonify({
                'success': False,
                'error': 'Error al crear el usuario'
            }), 500
            
    except Exception as e:
        logger.error(f"Error en registro: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': 'Error interno del servidor'
        }), 500

@auth_bp.route('/validate', methods=['GET'])
@jwt_required()
def validate_token():
    """
    Validar token JWT
    GET /api/auth/validate
    Headers: Authorization: Bearer <token>
    """
    try:
        # get_jwt_identity() ahora devuelve un string (el ID)
        current_user_id = get_jwt_identity()
        
        if not current_user_id:
            return jsonify({
                'success': False,
                'error': 'Token inválido'
            }), 401
        
        # Buscar usuario en base de datos
        from models.user import User
        usuario = User.find_by_id(int(current_user_id))  # Convertir a int
        
        if not usuario:
            return jsonify({
                'success': False,
                'error': 'Usuario no encontrado'
            }), 404
        
        if not usuario.is_active():
            return jsonify({
                'success': False,
                'error': 'Usuario desactivado'
            }), 403
        
        # Obtener información del token
        jwt_data = get_jwt()
        expires_at = jwt_data.get('exp')
        
        # Calcular tiempo restante
        import time
        current_time = time.time()
        time_left = expires_at - current_time if expires_at else 0
        
        return jsonify({
            'success': True,
            'message': 'Token válido',
            'user': {
                'id': usuario.id,
                'nombre': usuario.nombre,
                'email': usuario.email,
                'rol': usuario.rol,
                'activo': usuario.activo,
                'telefono': usuario.telefono
            },
            'token_info': {
                'identity': current_user_id,
                'expires_at': expires_at,
                'time_left_seconds': time_left,
                'time_left_days': time_left / (24 * 3600) if time_left > 0 else 0,
                'type': jwt_data.get('type', 'access')
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error validando token: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': 'Error al validar token'
        }), 500

@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """
    Refrescar token de acceso
    POST /api/auth/refresh
    Headers: Authorization: Bearer <refresh_token>
    """
    try:
        current_user_id = get_jwt_identity()  # Esto es un string ID
        
        # Verificar usuario
        from models.user import User
        user = User.find_by_id(int(current_user_id))
        if not user or not user.activo:
            return jsonify({
                'success': False,
                'error': 'Usuario no encontrado o inactivo'
            }), 401
        
        # Obtener duración
        jwt_expires = current_app.config.get('JWT_ACCESS_TOKEN_EXPIRES', timedelta(days=30))
        
        if isinstance(jwt_expires, (int, float)):
            expires_delta = timedelta(seconds=jwt_expires)
        elif isinstance(jwt_expires, timedelta):
            expires_delta = jwt_expires
        else:
            expires_delta = timedelta(days=30)
        
        access_token = create_access_token(
            identity=current_user_id,  # Ya es un string
            expires_delta=expires_delta
        )
        
        logger.info(f"Token refrescado para usuario ID: {current_user_id}")
        
        return jsonify({
            'success': True,
            'token': access_token,
            'access_token': access_token,
            'token_type': 'Bearer',
            'expires_in': expires_delta.total_seconds()
        }), 200
        
    except Exception as e:
        logger.error(f"Error refrescando token: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Error al refrescar token'
        }), 500

@auth_bp.route('/profile', methods=['GET'])
@jwt_required()
def get_profile():
    """
    Obtener perfil del usuario autenticado
    GET /api/auth/profile
    """
    try:
        current_user_id = get_jwt_identity()
        
        from models.user import User
        usuario = User.find_by_id(int(current_user_id))
        
        if not usuario:
            return jsonify({
                'success': False,
                'error': 'Usuario no encontrado'
            }), 404
        
        return jsonify({
            'success': True,
            'profile': usuario.to_dict(include_sensitive=True)
        }), 200
        
    except Exception as e:
        logger.error(f"Error obteniendo perfil: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Error al obtener perfil'
        }), 500

@auth_bp.route('/profile', methods=['PUT'])
@jwt_required()
def update_profile():
    """
    Actualizar perfil del usuario
    PUT /api/auth/profile
    """
    try:
        current_user_id = get_jwt_identity()
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'error': 'Se requiere datos en formato JSON'
            }), 400
        
        from models.user import User
        from models import db
        
        usuario = User.find_by_id(int(current_user_id))
        
        if not usuario:
            return jsonify({
                'success': False,
                'error': 'Usuario no encontrado'
            }), 404
        
        # Actualizar campos permitidos
        allowed_fields = ['nombre', 'telefono', 'direccion', 'ciudad', 'estado', 'pais',
                         'notificaciones_email', 'notificaciones_push', 'idioma']
        
        updates = {}
        for field in allowed_fields:
            if field in data and data[field] is not None:
                if field == 'nombre':
                    is_valid, msg = validate_name(data[field])
                    if not is_valid:
                        return jsonify({'success': False, 'error': msg}), 400
                elif field == 'telefono':
                    if not User.validate_phone(data[field]):
                        return jsonify({
                            'success': False,
                            'error': 'Formato de teléfono inválido'
                        }), 400
                updates[field] = data[field]
        
        # Aplicar actualizaciones
        for field, value in updates.items():
            setattr(usuario, field, value)
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Perfil actualizado exitosamente',
            'profile': usuario.to_dict(include_sensitive=True)
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error actualizando perfil: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': 'Error al actualizar perfil'
        }), 500

@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    """
    Cerrar sesión (en el lado del cliente)
    POST /api/auth/logout
    """
    current_user_id = get_jwt_identity()
    logger.info(f"Logout solicitado por usuario ID: {current_user_id}")
    
    return jsonify({
        'success': True,
        'message': 'Sesión cerrada exitosamente'
    }), 200

@auth_bp.route('/check', methods=['GET'])
def check():
    """
    Verificar estado del servicio de autenticación
    GET /api/auth/check
    """
    try:
        from models.user import User
        user_count = User.query.count()
        
        # Obtener configuración de JWT actual
        jwt_expires = current_app.config.get('JWT_ACCESS_TOKEN_EXPIRES', timedelta(days=30))
        
        if isinstance(jwt_expires, (int, float)):
            expires_delta = timedelta(seconds=jwt_expires)
        elif isinstance(jwt_expires, timedelta):
            expires_delta = jwt_expires
        else:
            expires_delta = timedelta(days=30)
        
        return jsonify({
            'success': True,
            'status': 'active',
            'service': 'authentication',
            'users_registered': user_count,
            'jwt_configuration': {
                'access_token_expires': str(expires_delta),
                'access_token_expires_days': expires_delta.days,
                'access_token_expires_seconds': expires_delta.total_seconds()
            },
            'timestamp': __import__('datetime').datetime.utcnow().isoformat()
        }), 200
    except Exception as e:
        logger.error(f"Error en check: {e}")
        return jsonify({
            'success': False,
            'status': 'error',
            'service': 'authentication',
            'error': str(e)
        }), 500

@auth_bp.route('/test-login', methods=['POST'])
def test_login():
    """
    Login de prueba para desarrollo
    POST /api/auth/test-login
    Body: { "as": "admin"|"user" }
    """
    if not current_app.config.get('DEBUG', False):
        return jsonify({
            'success': False,
            'error': 'Endpoint solo disponible en modo desarrollo'
        }), 403
    
    try:
        data = request.get_json() or {}
        role = data.get('as', 'admin').lower()
        
        if role not in ['admin', 'user']:
            role = 'admin'
        
        # Crear usuario de prueba - identity debe ser string
        identity = '999' if role == 'admin' else '998'
        
        # Token de 30 días para pruebas
        access_token = create_access_token(
            identity=identity,
            expires_delta=timedelta(days=30)
        )
        
        user_data = {
            'id': int(identity),
            'nombre': 'Administrador' if role == 'admin' else 'Usuario Demo',
            'email': f'{role}@canosalaotours.com',
            'rol': role,
            'activo': True,
            'telefono': '+58 412-205-6558' if role == 'admin' else '+58 414-123-4567'
        }
        
        return jsonify({
            'success': True,
            'message': f'Login de prueba como {role}',
            'token': access_token,
            'access_token': access_token,
            'user': user_data,
            'expires_in': timedelta(days=30).total_seconds(),
            'note': 'Este es un usuario de prueba para desarrollo (30 días de sesión)'
        }), 200
        
    except Exception as e:
        logger.error(f"Error en test-login: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Error en login de prueba'
        }), 500

# ========== RUTAS ADMINISTRATIVAS ==========
@auth_bp.route('/users', methods=['GET'])
@jwt_required()
def get_users():
    """
    Obtener lista de usuarios (solo administradores)
    GET /api/auth/users
    """
    try:
        current_user_id = get_jwt_identity()
        
        # Verificar si es admin
        from models.user import User
        usuario = User.find_by_id(int(current_user_id))
        
        if not usuario or usuario.rol != 'admin':
            return jsonify({
                'success': False,
                'error': 'Se requieren permisos de administrador'
            }), 403
        
        users = User.query.all()
        
        return jsonify({
            'success': True,
            'users': [user.to_dict() for user in users],
            'count': len(users),
            'timestamp': __import__('datetime').datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"Error obteniendo usuarios: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': 'Error al obtener usuarios'
        }), 500

@auth_bp.route('/session-info', methods=['GET'])
@jwt_required()
def get_session_info():
    """
    Obtener información detallada de la sesión actual
    GET /api/auth/session-info
    """
    try:
        current_user_id = get_jwt_identity()
        jwt_data = get_jwt()
        
        from datetime import datetime
        import time
        
        expires_at = jwt_data.get('exp')
        issued_at = jwt_data.get('iat')
        
        current_time = time.time()
        
        if expires_at:
            time_left = expires_at - current_time
            expires_date = datetime.fromtimestamp(expires_at)
        else:
            time_left = 0
            expires_date = None
        
        from models.user import User
        usuario = User.find_by_id(int(current_user_id))
        
        response_data = {
            'success': True,
            'session': {
                'user_id': current_user_id,
                'issued_at': issued_at,
                'issued_date': datetime.fromtimestamp(issued_at).isoformat() if issued_at else None,
                'expires_at': expires_at,
                'expires_date': expires_date.isoformat() if expires_date else None,
                'time_left_seconds': time_left,
                'time_left_days': time_left / (24 * 3600) if time_left > 0 else 0,
                'time_left_hours': time_left / 3600 if time_left > 0 else 0,
                'token_type': jwt_data.get('type', 'access'),
                'is_valid': time_left > 0 if expires_at else False
            }
        }
        
        if usuario:
            response_data['user'] = {
                'id': usuario.id,
                'nombre': usuario.nombre,
                'email': usuario.email,
                'rol': usuario.rol,
                'last_login': usuario.ultimo_acceso.isoformat() if usuario.ultimo_acceso else None,
                'email_verified': usuario.email_verificado,
                'active': usuario.activo
            }
        
        return jsonify(response_data), 200
        
    except Exception as e:
        logger.error(f"Error obteniendo información de sesión: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Error al obtener información de sesión'
        }), 500
