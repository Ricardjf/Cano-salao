# Backend/routes/user_routes.py - RUTAS PARA GESTIÓN DE USUARIOS
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
import logging
from datetime import datetime

# Configurar logging
logger = logging.getLogger(__name__)

user_bp = Blueprint('users', __name__)

# ========== VALIDACIONES ==========
def validate_user_data(data, for_update=False):
    """Valida datos de usuario"""
    errors = []
    
    if not for_update or 'nombre' in data:
        nombre = data.get('nombre', '').strip()
        if not nombre or len(nombre) < 2:
            errors.append("El nombre debe tener al menos 2 caracteres")
        if len(nombre) > 100:
            errors.append("El nombre no puede exceder 100 caracteres")
    
    if not for_update or 'email' in data:
        email = data.get('email', '').strip().lower()
        if email and not __import__('re').match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            errors.append("Formato de email inválido")
    
    if 'telefono' in data and data['telefono']:
        telefono = data.get('telefono', '').strip()
        from models.user import User
        if not User.validate_phone(telefono):
            errors.append("Formato de teléfono inválido")
    
    if 'rol' in data:
        rol = data.get('rol', '').lower()
        valid_roles = ['admin', 'user', 'editor']
        if rol not in valid_roles:
            errors.append(f"Rol inválido. Debe ser: {', '.join(valid_roles)}")
    
    return errors

# ========== RUTAS PÚBLICAS ==========
@user_bp.route('/check-email', methods=['POST'])
def check_email():
    """
    Verificar si un email está disponible
    POST /api/users/check-email
    Body: { "email": "usuario@email.com" }
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'error': 'Se requiere datos en formato JSON'
            }), 400
        
        email = data.get('email', '').strip().lower()
        
        if not email:
            return jsonify({
                'success': False,
                'error': 'Email es requerido'
            }), 400
        
        # Validar formato de email
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not __import__('re').match(email_regex, email):
            return jsonify({
                'success': False,
                'error': 'Formato de email inválido'
            }), 400
        
        from models.user import User
        
        # Verificar si el email existe
        usuario = User.find_by_email(email)
        
        return jsonify({
            'success': True,
            'available': usuario is None,
            'message': 'Email disponible' if usuario is None else 'Email ya registrado'
        }), 200
        
    except Exception as e:
        logger.error(f"Error verificando email: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': 'Error interno del servidor'
        }), 500

# ========== RUTAS PROTEGIDAS ==========
@user_bp.route('/profile', methods=['GET'])
@jwt_required()
def get_current_user_profile():
    """
    Obtener perfil del usuario actual
    GET /api/users/profile
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
            'user': usuario.to_dict(include_sensitive=True)
        }), 200
        
    except Exception as e:
        logger.error(f"Error obteniendo perfil: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': 'Error al obtener perfil'
        }), 500

@user_bp.route('/profile', methods=['PUT'])
@jwt_required()
def update_current_user_profile():
    """
    Actualizar perfil del usuario actual
    PUT /api/users/profile
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
        
        # Validar datos
        errors = validate_user_data(data, for_update=True)
        if errors:
            return jsonify({
                'success': False,
                'errors': errors
            }), 400
        
        # Verificar si se intenta cambiar el email
        if 'email' in data and data['email'] != usuario.email:
            # Verificar que el nuevo email no esté en uso
            existing_user = User.find_by_email(data['email'])
            if existing_user and existing_user.id != usuario.id:
                return jsonify({
                    'success': False,
                    'error': 'El email ya está en uso por otro usuario'
                }), 409
        
        # Actualizar campos permitidos
        allowed_fields = ['nombre', 'email', 'telefono', 'direccion', 'ciudad', 
                         'estado', 'pais', 'notificaciones_email', 'notificaciones_push', 
                         'idioma']
        
        for field in allowed_fields:
            if field in data and data[field] is not None:
                setattr(usuario, field, data[field])
        
        db.session.commit()
        
        logger.info(f"Perfil actualizado: {usuario.email} (ID: {usuario.id})")
        
        return jsonify({
            'success': True,
            'message': 'Perfil actualizado exitosamente',
            'user': usuario.to_dict(include_sensitive=True)
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error actualizando perfil: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': 'Error al actualizar perfil'
        }), 500

@user_bp.route('/change-password', methods=['POST'])
@jwt_required()
def change_password():
    """
    Cambiar contraseña del usuario actual
    POST /api/users/change-password
    """
    try:
        current_user = get_jwt_identity()
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'error': 'Se requiere datos en formato JSON'
            }), 400
        
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        confirm_password = data.get('confirm_password')
        
        if not current_password or not new_password or not confirm_password:
            return jsonify({
                'success': False,
                'error': 'Todos los campos de contraseña son requeridos'
            }), 400
        
        if new_password != confirm_password:
            return jsonify({
                'success': False,
                'error': 'Las contraseñas nuevas no coinciden'
            }), 400
        
        if len(new_password) < 6:
            return jsonify({
                'success': False,
                'error': 'La nueva contraseña debe tener al menos 6 caracteres'
            }), 400
        
        from models.user import User
        from models import db
        
        usuario = User.find_by_id(current_user['id'])
        
        if not usuario:
            return jsonify({
                'success': False,
                'error': 'Usuario no encontrado'
            }), 404
        
        # Verificar contraseña actual
        if not usuario.check_password(current_password):
            return jsonify({
                'success': False,
                'error': 'Contraseña actual incorrecta'
            }), 401
        
        # Actualizar contraseña
        usuario.set_password(new_password)
        db.session.commit()
        
        logger.info(f"Contraseña cambiada para: {usuario.email} (ID: {usuario.id})")
        
        return jsonify({
            'success': True,
            'message': 'Contraseña cambiada exitosamente'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error cambiando contraseña: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': 'Error al cambiar contraseña'
        }), 500

# ========== RUTAS ADMINISTRATIVAS ==========
@user_bp.route('/', methods=['GET'])
@jwt_required()
def get_all_users():
    """
    Obtener todos los usuarios (solo administradores)
    GET /api/users/
    Query parameters:
      - page: número de página (default: 1)
      - per_page: usuarios por página (default: 20)
      - role: filtrar por rol
      - active: filtrar por estado (true/false)
      - search: buscar por nombre o email
    """
    try:
        current_user = get_jwt_identity()
        
        # Verificar permisos de administrador
        if current_user.get('rol') != 'admin':
            return jsonify({
                'success': False,
                'error': 'Se requieren permisos de administrador'
            }), 403
        
        # Obtener parámetros de consulta
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        role_filter = request.args.get('role')
        active_filter = request.args.get('active', type=str)
        search_query = request.args.get('search', '').strip()
        
        # Construir query
        from models.user import User
        query = User.query
        
        # Aplicar filtros
        if role_filter:
            query = query.filter_by(rol=role_filter)
        
        if active_filter is not None:
            is_active = active_filter.lower() == 'true'
            query = query.filter_by(activo=is_active)
        
        if search_query:
            search_term = f"%{search_query}%"
            query = query.filter(
                (User.nombre.ilike(search_term)) | 
                (User.email.ilike(search_term)) |
                (User.telefono.ilike(search_term))
            )
        
        # Ordenar por fecha de registro (más recientes primero)
        query = query.order_by(User.fecha_registro.desc())
        
        # Paginación
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        users = pagination.items
        
        # Preparar datos de paginación
        pagination_data = {
            'page': pagination.page,
            'per_page': pagination.per_page,
            'total_pages': pagination.pages,
            'total_items': pagination.total,
            'has_next': pagination.has_next,
            'has_prev': pagination.has_prev
        }
        
        return jsonify({
            'success': True,
            'users': [user.to_dict() for user in users],
            'pagination': pagination_data,
            'count': len(users),
            'timestamp': datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"Error obteniendo usuarios: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': 'Error al obtener usuarios'
        }), 500

@user_bp.route('/<int:user_id>', methods=['GET'])
@jwt_required()
def get_user_by_id(user_id):
    """
    Obtener usuario por ID (solo administradores o el propio usuario)
    GET /api/users/<id>
    """
    try:
        current_user = get_jwt_identity()
        
        # Verificar permisos: admin puede ver cualquier usuario, usuarios solo pueden verse a sí mismos
        if current_user.get('rol') != 'admin' and current_user.get('id') != user_id:
            return jsonify({
                'success': False,
                'error': 'No tienes permisos para ver este usuario'
            }), 403
        
        from models.user import User
        usuario = User.find_by_id(user_id)
        
        if not usuario:
            return jsonify({
                'success': False,
                'error': 'Usuario no encontrado'
            }), 404
        
        # Determinar nivel de detalle basado en permisos
        include_sensitive = current_user.get('rol') == 'admin' or current_user.get('id') == user_id
        
        return jsonify({
            'success': True,
            'user': usuario.to_dict(include_sensitive=include_sensitive)
        }), 200
        
    except Exception as e:
        logger.error(f"Error obteniendo usuario: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': 'Error al obtener usuario'
        }), 500

@user_bp.route('/<int:user_id>', methods=['PUT'])
@jwt_required()
def update_user(user_id):
    """
    Actualizar usuario (solo administradores)
    PUT /api/users/<id>
    """
    try:
        current_user = get_jwt_identity()
        
        # Verificar permisos de administrador
        if current_user.get('rol') != 'admin':
            return jsonify({
                'success': False,
                'error': 'Se requieren permisos de administrador'
            }), 403
        
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'error': 'Se requiere datos en formato JSON'
            }), 400
        
        from models.user import User
        from models import db
        
        usuario = User.find_by_id(user_id)
        
        if not usuario:
            return jsonify({
                'success': False,
                'error': 'Usuario no encontrado'
            }), 404
        
        # Validar datos
        errors = validate_user_data(data, for_update=True)
        if errors:
            return jsonify({
                'success': False,
                'errors': errors
            }), 400
        
        # Verificar si se intenta cambiar el email
        if 'email' in data and data['email'] != usuario.email:
            # Verificar que el nuevo email no esté en uso
            existing_user = User.find_by_email(data['email'])
            if existing_user and existing_user.id != usuario.id:
                return jsonify({
                    'success': False,
                    'error': 'El email ya está en uso por otro usuario'
                }), 409
        
        # Actualizar campos permitidos para admin
        allowed_fields = ['nombre', 'email', 'telefono', 'direccion', 'ciudad', 
                         'estado', 'pais', 'rol', 'activo', 'email_verificado',
                         'notificaciones_email', 'notificaciones_push', 'idioma']
        
        updates_made = []
        for field in allowed_fields:
            if field in data and data[field] is not None:
                old_value = getattr(usuario, field)
                new_value = data[field]
                
                if old_value != new_value:
                    setattr(usuario, field, new_value)
                    updates_made.append(f"{field}: {old_value} → {new_value}")
        
        if not updates_made:
            return jsonify({
                'success': True,
                'message': 'No se realizaron cambios',
                'user': usuario.to_dict(include_sensitive=True)
            }), 200
        
        db.session.commit()
        
        logger.info(f"Usuario actualizado por admin: {usuario.email} (ID: {usuario.id})")
        logger.info(f"Cambios: {', '.join(updates_made)}")
        
        return jsonify({
            'success': True,
            'message': 'Usuario actualizado exitosamente',
            'user': usuario.to_dict(include_sensitive=True),
            'changes': updates_made
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error actualizando usuario: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': 'Error al actualizar usuario'
        }), 500

@user_bp.route('/<int:user_id>/status', methods=['PATCH'])
@jwt_required()
def toggle_user_status(user_id):
    """
    Activar/desactivar usuario (solo administradores)
    PATCH /api/users/<id>/status
    Body: { "active": true/false }
    """
    try:
        current_user = get_jwt_identity()
        
        # Verificar permisos de administrador
        if current_user.get('rol') != 'admin':
            return jsonify({
                'success': False,
                'error': 'Se requieren permisos de administrador'
            }), 403
        
        # Evitar que un admin se desactive a sí mismo
        if current_user.get('id') == user_id:
            return jsonify({
                'success': False,
                'error': 'No puedes cambiar tu propio estado'
            }), 400
        
        data = request.get_json() or {}
        active = data.get('active')
        
        if active is None:
            return jsonify({
                'success': False,
                'error': 'El campo "active" es requerido'
            }), 400
        
        from models.user import User
        from models import db
        
        usuario = User.find_by_id(user_id)
        
        if not usuario:
            return jsonify({
                'success': False,
                'error': 'Usuario no encontrado'
            }), 404
        
        # Verificar si ya está en el estado solicitado
        if usuario.activo == active:
            return jsonify({
                'success': True,
                'message': f'El usuario ya está {"activado" if active else "desactivado"}',
                'user': usuario.to_dict()
            }), 200
        
        # Actualizar estado
        usuario.activo = active
        db.session.commit()
        
        action = "activado" if active else "desactivado"
        logger.info(f"Usuario {action}: {usuario.email} (ID: {usuario.id}) por admin: {current_user.get('email')}")
        
        return jsonify({
            'success': True,
            'message': f'Usuario {action} exitosamente',
            'user': usuario.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error cambiando estado de usuario: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': 'Error al cambiar estado del usuario'
        }), 500

@user_bp.route('/<int:user_id>/role', methods=['PATCH'])
@jwt_required()
def change_user_role(user_id):
    """
    Cambiar rol de usuario (solo administradores)
    PATCH /api/users/<id>/role
    Body: { "role": "admin"|"user"|"editor" }
    """
    try:
        current_user = get_jwt_identity()
        
        # Verificar permisos de administrador
        if current_user.get('rol') != 'admin':
            return jsonify({
                'success': False,
                'error': 'Se requieren permisos de administrador'
            }), 403
        
        # Evitar que un admin cambie su propio rol
        if current_user.get('id') == user_id:
            return jsonify({
                'success': False,
                'error': 'No puedes cambiar tu propio rol'
            }), 400
        
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'error': 'Se requiere datos en formato JSON'
            }), 400
        
        new_role = data.get('role', '').lower()
        
        if not new_role:
            return jsonify({
                'success': False,
                'error': 'El campo "role" es requerido'
            }), 400
        
        valid_roles = ['admin', 'user', 'editor']
        if new_role not in valid_roles:
            return jsonify({
                'success': False,
                'error': f'Rol inválido. Debe ser: {", ".join(valid_roles)}'
            }), 400
        
        from models.user import User
        from models import db
        
        usuario = User.find_by_id(user_id)
        
        if not usuario:
            return jsonify({
                'success': False,
                'error': 'Usuario no encontrado'
            }), 404
        
        # Verificar si ya tiene el rol solicitado
        if usuario.rol == new_role:
            return jsonify({
                'success': True,
                'message': f'El usuario ya tiene el rol {new_role}',
                'user': usuario.to_dict()
            }), 200
        
        old_role = usuario.rol
        usuario.rol = new_role
        db.session.commit()
        
        logger.info(f"Rol cambiado: {usuario.email} (ID: {usuario.id}) de {old_role} a {new_role} por admin: {current_user.get('email')}")
        
        return jsonify({
            'success': True,
            'message': f'Rol cambiado de {old_role} a {new_role} exitosamente',
            'user': usuario.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error cambiando rol de usuario: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': 'Error al cambiar rol del usuario'
        }), 500

@user_bp.route('/<int:user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    """
    Eliminar usuario (solo administradores)
    DELETE /api/users/<id>
    """
    try:
        current_user = get_jwt_identity()
        
        # Verificar permisos de administrador
        if current_user.get('rol') != 'admin':
            return jsonify({
                'success': False,
                'error': 'Se requieren permisos de administrador'
            }), 403
        
        # Evitar que un admin se elimine a sí mismo
        if current_user.get('id') == user_id:
            return jsonify({
                'success': False,
                'error': 'No puedes eliminar tu propia cuenta'
            }), 400
        
        from models.user import User
        from models import db
        
        usuario = User.find_by_id(user_id)
        
        if not usuario:
            return jsonify({
                'success': False,
                'error': 'Usuario no encontrado'
            }), 404
        
        # Guardar información para logging
        user_email = usuario.email
        user_name = usuario.nombre
        
        # Eliminar usuario
        db.session.delete(usuario)
        db.session.commit()
        
        logger.warning(f"Usuario eliminado: {user_email} (Nombre: {user_name}, ID: {user_id}) por admin: {current_user.get('email')}")
        
        return jsonify({
            'success': True,
            'message': f'Usuario {user_email} eliminado exitosamente'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error eliminando usuario: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': 'Error al eliminar usuario'
        }), 500

@user_bp.route('/stats', methods=['GET'])
@jwt_required()
def get_user_stats():
    """
    Obtener estadísticas de usuarios (solo administradores)
    GET /api/users/stats
    """
    try:
        current_user = get_jwt_identity()
        
        # Verificar permisos de administrador
        if current_user.get('rol') != 'admin':
            return jsonify({
                'success': False,
                'error': 'Se requieren permisos de administrador'
            }), 403
        
        from models.user import User
        from models import db
        from sqlalchemy import func
        
        # Obtener estadísticas
        total_users = User.query.count()
        active_users = User.query.filter_by(activo=True).count()
        inactive_users = total_users - active_users
        
        # Usuarios por rol
        roles_stats = db.session.query(
            User.rol,
            func.count(User.id).label('count')
        ).group_by(User.rol).all()
        
        roles_dict = {role: count for role, count in roles_stats}
        
        # Usuarios por mes (últimos 6 meses)
        six_months_ago = datetime.utcnow().replace(day=1)
        for _ in range(6):
            # Ir 6 meses atrás
            if six_months_ago.month == 1:
                six_months_ago = six_months_ago.replace(year=six_months_ago.year-1, month=12)
            else:
                six_months_ago = six_months_ago.replace(month=six_months_ago.month-1)
        
        monthly_stats = db.session.query(
            func.strftime('%Y-%m', User.fecha_registro).label('month'),
            func.count(User.id).label('count')
        ).filter(User.fecha_registro >= six_months_ago)\
         .group_by('month')\
         .order_by('month')\
         .all()
        
        # Usuarios verificados vs no verificados
        verified_users = User.query.filter_by(email_verificado=True).count()
        not_verified_users = total_users - verified_users
        
        return jsonify({
            'success': True,
            'stats': {
                'total': total_users,
                'active': active_users,
                'inactive': inactive_users,
                'verified': verified_users,
                'not_verified': not_verified_users,
                'by_role': roles_dict,
                'monthly_registrations': [
                    {'month': month, 'count': count} 
                    for month, count in monthly_stats
                ],
                'last_updated': datetime.utcnow().isoformat()
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error obteniendo estadísticas: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': 'Error al obtener estadísticas'
        }), 500