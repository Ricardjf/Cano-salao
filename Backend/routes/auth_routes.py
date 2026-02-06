# Backend/routes/auth_routes.py - VERSIÓN CORREGIDA Y FUNCIONAL
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
            from datetime import datetime
            usuario.ultimo_acceso = datetime.utcnow()
            db.session.commit()
        except Exception as e:
            logger.warning(f"Error al actualizar último acceso: {e}")
            # Continuar aunque falle esta parte
        
        # ¡IMPORTANTE! Para Flask-JWT-Extended, identity debe ser un STRING
        # Pasamos solo el ID como string
        identity = str(usuario.id)
        
        # Obtener duración de la configuración
        jwt_expires = current_app.config.get('JWT_ACCESS_TOKEN_EXPIRES', timedelta(days=30))
        
        # Crear token de acceso con duración extendida
        access_token = create_access_token(
            identity=identity,
            expires_delta=jwt_expires
        )
        
        # Crear refresh token (1 año)
        refresh_token = create_refresh_token(
            identity=identity,
            expires_delta=timedelta(days=365)
        )
        
        logger.info(f"✅ Login exitoso: {email} (ID: {usuario.id}), Token expira en: {jwt_expires}")
        
        # RESPUESTA CORREGIDA - El frontend busca "token" como campo principal
        return jsonify({
            'success': True,
            'message': 'Inicio de sesión exitoso',
            'token': access_token,  # ← ¡IMPORTANTE! El frontend busca "token"
            'access_token': access_token,  # ← Para compatibilidad
            'refresh_token': refresh_token,
            'user': usuario.to_auth_dict(),
            'token_type': 'Bearer',
            'expires_in': int(jwt_expires.total_seconds()),
            'expires_days': jwt_expires.days,
            'persistent_session': True
        }), 200
        
    except Exception as e:
        logger.error(f"❌ Error en login: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': 'Error interno del servidor',
            'details': str(e) if current_app.config.get('DEBUG') else None
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
            from datetime import datetime
            
            # Determinar rol (primer usuario = admin, otros = user)
            user_count = User.query.count()
            rol = 'admin' if user_count == 0 else 'user'
            
            usuario = User(
                nombre=nombre,
                email=email,
                telefono=telefono,
                rol=rol,
                email_verificado=False,
                fecha_registro=datetime.utcnow(),
                activo=True
            )
            usuario.set_password(password)
            
            db.session.add(usuario)
            db.session.commit()
            
            # ¡IMPORTANTE! Identity debe ser string (solo el ID)
            identity = str(usuario.id)
            
            # Crear token de acceso con duración extendida (30 días)
            access_token = create_access_token(
                identity=identity,
                expires_delta=timedelta(days=30)
            )
            
            # Crear refresh token (1 año)
            refresh_token = create_refresh_token(
                identity=identity,
                expires_delta=timedelta(days=365)
            )
            
            logger.info(f"✅ Nuevo usuario registrado: {email} (ID: {usuario.id}, Rol: {rol})")
            
            # RESPUESTA CORREGIDA
            return jsonify({
                'success': True,
                'message': 'Registro exitoso. ¡Bienvenido/a!',
                'token': access_token,  # ← ¡IMPORTANTE!
                'access_token': access_token,  # ← Para compatibilidad
                'refresh_token': refresh_token,
                'user': usuario.to_auth_dict(),
                'is_first_user': rol == 'admin',
                'expires_in': timedelta(days=30).total_seconds()
            }), 201
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"❌ Error al crear usuario: {str(e)}", exc_info=True)
            return jsonify({
                'success': False,
                'error': 'Error al crear el usuario',
                'details': str(e) if current_app.config.get('DEBUG') else None
            }), 500
            
    except Exception as e:
        logger.error(f"❌ Error en registro: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': 'Error interno del servidor',
            'details': str(e) if current_app.config.get('DEBUG') else None
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
        # get_jwt_identity() devuelve el string que guardamos (el ID)
        current_user_id = get_jwt_identity()
        
        if not current_user_id:
            return jsonify({
                'success': False,
                'error': 'Token inválido'
            }), 401
        
        # Convertir a int para buscar en BD
        user_id = int(current_user_id)
        
        # Buscar usuario en base de datos
        from models.user import User
        usuario = User.find_by_id(user_id)
        
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
        from datetime import datetime
        import time
        current_time = time.time()
        time_left = expires_at - current_time if expires_at else 0
        
        return jsonify({
            'success': True,
            'message': 'Token válido',
            'user': usuario.to_auth_dict(),
            'token_info': {
                'identity': current_user_id,
                'expires_at': expires_at,
                'expires_date': datetime.fromtimestamp(expires_at).isoformat() if expires_at else None,
                'time_left_seconds': time_left,
                'time_left_days': time_left / (24 * 3600) if time_left > 0 else 0,
                'time_left_hours': time_left / 3600 if time_left > 0 else 0,
                'type': jwt_data.get('type', 'access')
            }
        }), 200
        
    except (ValueError, TypeError) as e:
        logger.error(f"❌ Error de conversión de ID: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Token inválido - formato incorrecto'
        }), 401
    except Exception as e:
        logger.error(f"❌ Error validando token: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': 'Error al validar token',
            'details': str(e) if current_app.config.get('DEBUG') else None
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
        # get_jwt_identity() devuelve el string ID
        current_user_id = get_jwt_identity()
        
        if not current_user_id:
            return jsonify({
                'success': False,
                'error': 'Token inválido'
            }), 401
        
        # Convertir a int para buscar en BD
        user_id = int(current_user_id)
        
        # Verificar usuario
        from models.user import User
        user = User.find_by_id(user_id)
        if not user or not user.activo:
            return jsonify({
                'success': False,
                'error': 'Usuario no encontrado o inactivo'
            }), 401
        
        # Actualizar actividad
        try:
            from models import db
            from datetime import datetime
            user.last_activity = datetime.utcnow()
            db.session.commit()
        except Exception as e:
            logger.warning(f"Error actualizando actividad: {e}")
        
        # Obtener duración
        jwt_expires = current_app.config.get('JWT_ACCESS_TOKEN_EXPIRES', timedelta(days=30))
        
        # Crear nuevo access token
        new_access_token = create_access_token(
            identity=current_user_id,  # Ya es string
            expires_delta=jwt_expires
        )
        
        logger.info(f"✅ Token refrescado para usuario ID: {user_id}")
        
        return jsonify({
            'success': True,
            'token': new_access_token,  # ← ¡IMPORTANTE!
            'access_token': new_access_token,  # ← Para compatibilidad
            'user': user.to_auth_dict(),
            'message': 'Token refrescado exitosamente',
            'expires_in': int(jwt_expires.total_seconds())
        }), 200
        
    except (ValueError, TypeError) as e:
        logger.error(f"❌ Error de conversión en refresh: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Token inválido - formato incorrecto'
        }), 401
    except Exception as e:
        logger.error(f"❌ Error refrescando token: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Error al refrescar token',
            'details': str(e) if current_app.config.get('DEBUG') else None
        }), 500

@auth_bp.route('/profile', methods=['GET'])
@jwt_required()
def get_profile():
    """
    Obtener perfil del usuario autenticado
    GET /api/auth/profile
    """
    try:
        # get_jwt_identity() devuelve string ID
        current_user_id = get_jwt_identity()
        
        if not current_user_id:
            return jsonify({
                'success': False,
                'error': 'Token inválido'
            }), 401
        
        # Convertir a int
        user_id = int(current_user_id)
        
        from models.user import User
        usuario = User.find_by_id(user_id)
        
        if not usuario:
            return jsonify({
                'success': False,
                'error': 'Usuario no encontrado'
            }), 404
        
        # Actualizar última actividad
        try:
            from models import db
            from datetime import datetime
            usuario.last_activity = datetime.utcnow()
            db.session.commit()
        except Exception as e:
            logger.warning(f"Error actualizando actividad: {e}")
        
        return jsonify({
            'success': True,
            'profile': usuario.to_dict(include_sensitive=True)
        }), 200
        
    except (ValueError, TypeError) as e:
        logger.error(f"❌ Error de conversión en perfil: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Token inválido - formato incorrecto'
        }), 401
    except Exception as e:
        logger.error(f"❌ Error obteniendo perfil: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Error al obtener perfil',
            'details': str(e) if current_app.config.get('DEBUG') else None
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
        
        if not current_user_id:
            return jsonify({
                'success': False,
                'error': 'Token inválido'
            }), 401
        
        # Convertir a int
        user_id = int(current_user_id)
        
        from models.user import User
        from models import db
        
        usuario = User.find_by_id(user_id)
        
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
        
    except (ValueError, TypeError) as e:
        logger.error(f"❌ Error de conversión en update: {str(e)}")
        db.session.rollback()
        return jsonify({
            'success': False,
            'error': 'Token inválido - formato incorrecto'
        }), 401
    except Exception as e:
        db.session.rollback()
        logger.error(f"❌ Error actualizando perfil: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': 'Error al actualizar perfil',
            'details': str(e) if current_app.config.get('DEBUG') else None
        }), 500

@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    """
    Cerrar sesión (en el lado del cliente)
    POST /api/auth/logout
    """
    try:
        current_user_id = get_jwt_identity()
        logger.info(f"Logout solicitado por usuario ID: {current_user_id}")
        
        return jsonify({
            'success': True,
            'message': 'Sesión cerrada exitosamente'
        }), 200
        
    except Exception as e:
        logger.error(f"Error en logout: {e}")
        return jsonify({
            'success': False,
            'error': 'Error al cerrar sesión'
        }), 500

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
        
        return jsonify({
            'success': True,
            'status': 'active',
            'service': 'authentication',
            'users_registered': user_count,
            'jwt_configuration': {
                'access_token_expires': str(jwt_expires),
                'access_token_expires_days': jwt_expires.days,
                'access_token_expires_seconds': jwt_expires.total_seconds()
            },
            'timestamp': __import__('datetime').datetime.utcnow().isoformat()
        }), 200
    except Exception as e:
        logger.error(f"❌ Error en check: {e}")
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
        
        # Crear identity como string ID
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
            'token': access_token,  # ← ¡IMPORTANTE!
            'access_token': access_token,  # ← Para compatibilidad
            'user': user_data,
            'expires_in': timedelta(days=30).total_seconds(),
            'note': 'Este es un usuario de prueba para desarrollo (30 días de sesión)'
        }), 200
        
    except Exception as e:
        logger.error(f"❌ Error en test-login: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Error en login de prueba'
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
        
        # Convertir a int para buscar usuario
        user_id = int(current_user_id) if current_user_id else None
        
        from models.user import User
        usuario = User.find_by_id(user_id) if user_id else None
        
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
        
    except (ValueError, TypeError) as e:
        logger.error(f"❌ Error de conversión en session-info: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Token inválido - formato incorrecto'
        }), 401
    except Exception as e:
        logger.error(f"❌ Error obteniendo información de sesión: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Error al obtener información de sesión'
        }), 500

# ========== RUTAS ADMINISTRATIVAS (solo para admins) ==========
@auth_bp.route('/users', methods=['GET'])
@jwt_required()
def get_users():
    """
    Obtener lista de usuarios (solo administradores)
    GET /api/auth/users
    """
    try:
        current_user_id = get_jwt_identity()
        
        if not current_user_id:
            return jsonify({
                'success': False,
                'error': 'Token inválido'
            }), 401
        
        # Convertir a int y verificar si es admin
        user_id = int(current_user_id)
        
        from models.user import User
        usuario = User.find_by_id(user_id)
        
        if not usuario or not usuario.is_admin():
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
        
    except (ValueError, TypeError) as e:
        logger.error(f"❌ Error de conversión en get_users: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Token inválido - formato incorrecto'
        }), 401
    except Exception as e:
        logger.error(f"❌ Error obteniendo usuarios: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': 'Error al obtener usuarios'
        }), 500

@auth_bp.route('/debug-token', methods=['GET'])
@jwt_required()
def debug_token():
    """
    Endpoint de depuración para ver información del token
    GET /api/auth/debug-token
    """
    try:
        current_user_id = get_jwt_identity()
        jwt_data = get_jwt()
        
        # Obtener configuración actual
        jwt_expires = current_app.config.get('JWT_ACCESS_TOKEN_EXPIRES', timedelta(days=30))
        
        # Convertir a int para buscar usuario
        user_id = int(current_user_id) if current_user_id else None
        
        from models.user import User
        usuario = User.find_by_id(user_id) if user_id else None
        
        return jsonify({
            'success': True,
            'debug_info': {
                'current_identity': current_user_id,
                'identity_type': type(current_user_id).__name__,
                'jwt_data_keys': list(jwt_data.keys()),
                'jwt_exp': jwt_data.get('exp'),
                'jwt_iat': jwt_data.get('iat'),
                'jwt_type': jwt_data.get('type'),
                'config_jwt_expires': str(jwt_expires),
                'config_jwt_expires_days': jwt_expires.days,
                'user_found': usuario is not None,
                'user_id_from_db': usuario.id if usuario else None,
                'user_name': usuario.nombre if usuario else None
            }
        }), 200
        
    except Exception as e:
        logger.error(f"❌ Error en debug-token: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Error en depuración',
            'details': str(e)
        }), 500
