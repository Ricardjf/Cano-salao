# Backend/routes/auth_routes.py - RUTAS DE AUTENTICACIÓN CORREGIDAS
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
        
        # Crear tokens
        identity = {
            'id': usuario.id,
            'email': usuario.email,
            'rol': usuario.rol
        }
        
        access_token = create_access_token(
            identity=identity,
            expires_delta=timedelta(hours=current_app.config.get('JWT_ACCESS_TOKEN_EXPIRES', timedelta(hours=24)))
        )
        
        refresh_token = create_refresh_token(identity=identity)
        
        logger.info(f"Login exitoso: {email} (ID: {usuario.id})")
        
        return jsonify({
            'success': True,
            'message': 'Inicio de sesión exitoso',
            'access_token': access_token,
            'refresh_token': refresh_token,
            'user': usuario.to_auth_dict(),
            'token_type': 'Bearer',
            'expires_in': current_app.config.get('JWT_ACCESS_TOKEN_EXPIRES', timedelta(hours=24)).total_seconds()
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
                email_verificado=False  # En producción, requerir verificación
            )
            usuario.set_password(password)
            
            db.session.add(usuario)
            db.session.commit()
            
            # Crear token de acceso
            identity = {
                'id': usuario.id,
                'email': usuario.email,
                'rol': usuario.rol
            }
            
            access_token = create_access_token(identity=identity)
            
            logger.info(f"Nuevo usuario registrado: {email} (ID: {usuario.id}, Rol: {rol})")
            
            return jsonify({
                'success': True,
                'message': 'Registro exitoso. ¡Bienvenido/a!',
                'access_token': access_token,
                'user': usuario.to_auth_dict(),
                'is_first_user': rol == 'admin'
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
        current_user = get_jwt_identity()
        
        if not current_user or 'id' not in current_user:
            return jsonify({
                'success': False,
                'error': 'Token inválido'
            }), 401
        
        # Buscar usuario en base de datos
        from models.user import User
        usuario = User.find_by_id(current_user['id'])
        
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
        
        return jsonify({
            'success': True,
            'message': 'Token válido',
            'user': usuario.to_auth_dict(),
            'token_info': {
                'identity': current_user,
                'jti': get_jwt().get('jti'),
                'type': get_jwt().get('type', 'access')
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
        current_user = get_jwt_identity()
        
        access_token = create_access_token(identity=current_user)
        
        return jsonify({
            'success': True,
            'access_token': access_token,
            'token_type': 'Bearer'
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
        current_user = get_jwt_identity()
        
        from models.user import User
        usuario = User.find_by_id(current_user['id'])
        
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
        current_user = get_jwt_identity()
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'error': 'Se requiere datos en formato JSON'
            }), 400
        
        from models.user import User
        from models import db
        
        usuario = User.find_by_id(current_user['id'])
        
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
    # Nota: JWT es stateless, este endpoint es principalmente para limpieza en el cliente
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
        
        return jsonify({
            'success': True,
            'status': 'active',
            'service': 'authentication',
            'users_registered': user_count,
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
        
        # Crear usuario de prueba
        identity = {
            'id': 999 if role == 'admin' else 998,
            'email': f'{role}@canosalaotours.com',
            'rol': role
        }
        
        access_token = create_access_token(identity=identity)
        
        user_data = {
            'id': identity['id'],
            'nombre': 'Administrador' if role == 'admin' else 'Usuario Demo',
            'email': identity['email'],
            'rol': role,
            'activo': True,
            'telefono': '+58 412-205-6558' if role == 'admin' else '+58 414-123-4567'
        }
        
        return jsonify({
            'success': True,
            'message': f'Login de prueba como {role}',
            'access_token': access_token,
            'user': user_data,
            'note': 'Este es un usuario de prueba para desarrollo'
        }), 200
        
    except Exception as e:
        logger.error(f"Error en test-login: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Error en login de prueba'
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
        current_user = get_jwt_identity()
        
        if current_user.get('rol') != 'admin':
            return jsonify({
                'success': False,
                'error': 'Se requieren permisos de administrador'
            }), 403
        
        from models.user import User
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