# Backend/routes/tour_routes.py - RUTAS PARA GESTIÓN DE TOURS
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
import logging
from datetime import datetime
import os

# Configurar logging
logger = logging.getLogger(__name__)

tour_bp = Blueprint('tours', __name__)

# ========== VALIDACIONES ==========
def validate_tour_data(data, for_update=False):
    """Valida datos del tour"""
    errors = []
    
    if not for_update or 'nombre' in data:
        nombre = data.get('nombre', '').strip()
        if not nombre or len(nombre) < 3:
            errors.append("El nombre debe tener al menos 3 caracteres")
        if len(nombre) > 200:
            errors.append("El nombre no puede exceder 200 caracteres")
    
    if not for_update or 'descripcion' in data:
        descripcion = data.get('descripcion', '').strip()
        if descripcion and len(descripcion) > 2000:
            errors.append("La descripción no puede exceder 2000 caracteres")
    
    if not for_update or 'duracion' in data:
        duracion = data.get('duracion', '').strip()
        if duracion and len(duracion) > 50:
            errors.append("La duración no puede exceder 50 caracteres")
    
    if not for_update or 'precio' in data:
        precio = data.get('precio')
        if precio is not None:
            try:
                precio_float = float(precio)
                if precio_float < 0:
                    errors.append("El precio no puede ser negativo")
                if precio_float > 10000:
                    errors.append("El precio no puede exceder $10,000")
            except ValueError:
                errors.append("El precio debe ser un número válido")
    
    if not for_update or 'capacidad_maxima' in data:
        capacidad = data.get('capacidad_maxima')
        if capacidad is not None:
            try:
                capacidad_int = int(capacidad)
                if capacidad_int < 1:
                    errors.append("La capacidad debe ser al menos 1")
                if capacidad_int > 100:
                    errors.append("La capacidad no puede exceder 100 personas")
            except ValueError:
                errors.append("La capacidad debe ser un número entero válido")
    
    if 'categoria' in data:
        categoria = data.get('categoria', '').strip()
        valid_categories = ['aventura', 'naturaleza', 'cultura', 'educativo', 
                           'fotografia', 'familiar', 'romantico', 'gastronomico']
        if categoria and categoria not in valid_categories:
            errors.append(f"Categoría inválida. Debe ser: {', '.join(valid_categories)}")
    
    if 'dificultad' in data:
        dificultad = data.get('dificultad', '').strip()
        valid_difficulties = ['facil', 'moderado', 'dificil', 'extremo']
        if dificultad and dificultad not in valid_difficulties:
            errors.append(f"Dificultad inválida. Debe ser: {', '.join(valid_difficulties)}")
    
    return errors

def allowed_file(filename):
    """Verifica si la extensión del archivo es permitida"""
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ========== RUTAS PÚBLICAS ==========
@tour_bp.route('/', methods=['GET'])
def get_all_tours():
    """
    Obtener todos los tours (público)
    GET /api/tours/
    Query parameters:
      - page: número de página (default: 1)
      - per_page: tours por página (default: 12)
      - categoria: filtrar por categoría
      - dificultad: filtrar por dificultad
      - disponible: filtrar por disponibilidad (true/false)
      - min_price: precio mínimo
      - max_price: precio máximo
      - search: buscar por nombre o descripción
      - sort: ordenar por (nombre, precio, fecha_creacion)
      - order: orden (asc, desc)
    """
    try:
        # Obtener parámetros de consulta
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 12, type=int)
        categoria_filter = request.args.get('categoria')
        dificultad_filter = request.args.get('dificultad')
        disponible_filter = request.args.get('disponible', type=str)
        min_price = request.args.get('min_price', type=float)
        max_price = request.args.get('max_price', type=float)
        search_query = request.args.get('search', '').strip()
        sort_by = request.args.get('sort', 'fecha_creacion')
        sort_order = request.args.get('order', 'desc')
        
        # Construir query
        from models.tour import Tour
        query = Tour.query
        
        # Aplicar filtros
        if categoria_filter:
            query = query.filter_by(categoria=categoria_filter)
        
        if dificultad_filter:
            query = query.filter_by(dificultad=dificultad_filter)
        
        if disponible_filter is not None:
            is_disponible = disponible_filter.lower() == 'true'
            query = query.filter_by(disponible=is_disponible)
        
        if min_price is not None:
            query = query.filter(Tour.precio >= min_price)
        
        if max_price is not None:
            query = query.filter(Tour.precio <= max_price)
        
        if search_query:
            search_term = f"%{search_query}%"
            query = query.filter(
                (Tour.nombre.ilike(search_term)) | 
                (Tour.descripcion.ilike(search_term)) |
                (Tour.incluye.ilike(search_term))
            )
        
        # Ordenar
        if sort_by in ['nombre', 'precio', 'fecha_creacion', 'capacidad_maxima']:
            sort_column = getattr(Tour, sort_by)
            if sort_order == 'desc':
                sort_column = sort_column.desc()
            query = query.order_by(sort_column)
        else:
            # Orden por defecto: más recientes primero
            query = query.order_by(Tour.fecha_creacion.desc())
        
        # Paginación
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        tours = pagination.items
        
        # Preparar datos de paginación
        pagination_data = {
            'page': pagination.page,
            'per_page': pagination.per_page,
            'total_pages': pagination.pages,
            'total_items': pagination.total,
            'has_next': pagination.has_next,
            'has_prev': pagination.has_prev
        }
        
        # Obtener estadísticas de filtros
        filter_stats = {}
        if categoria_filter:
            from models import db
            from sqlalchemy import func
            category_stats = db.session.query(
                Tour.categoria,
                func.count(Tour.id).label('count')
            ).group_by(Tour.categoria).all()
            filter_stats['categories'] = {cat: cnt for cat, cnt in category_stats}
        
        return jsonify({
            'success': True,
            'tours': [tour.to_dict() for tour in tours],
            'pagination': pagination_data,
            'count': len(tours),
            'filter_stats': filter_stats,
            'timestamp': datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"Error obteniendo tours: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': 'Error al obtener tours'
        }), 500

@tour_bp.route('/<int:tour_id>', methods=['GET'])
def get_tour(tour_id):
    """
    Obtener tour por ID (público)
    GET /api/tours/<id>
    """
    try:
        from models.tour import Tour
        
        tour = Tour.query.get(tour_id)
        
        if not tour:
            return jsonify({
                'success': False,
                'error': 'Tour no encontrado'
            }), 404
        
        # Incrementar contador de vistas
        try:
            from models import db
            tour.vistas = (tour.vistas or 0) + 1
            db.session.commit()
        except:
            db.session.rollback()
        
        return jsonify({
            'success': True,
            'tour': tour.to_dict(detailed=True)
        }), 200
        
    except Exception as e:
        logger.error(f"Error obteniendo tour: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': 'Error al obtener tour'
        }), 500

@tour_bp.route('/categorias', methods=['GET'])
def get_categories():
    """
    Obtener todas las categorías disponibles
    GET /api/tours/categorias
    """
    try:
        from models.tour import Tour
        from models import db
        from sqlalchemy import func
        
        categories = db.session.query(
            Tour.categoria,
            func.count(Tour.id).label('count'),
            func.min(Tour.precio).label('min_price'),
            func.max(Tour.precio).label('max_price')
        ).group_by(Tour.categoria).all()
        
        return jsonify({
            'success': True,
            'categories': [
                {
                    'nombre': cat,
                    'count': cnt,
                    'min_price': min_p,
                    'max_price': max_p
                } for cat, cnt, min_p, max_p in categories
            ]
        }), 200
        
    except Exception as e:
        logger.error(f"Error obteniendo categorías: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': 'Error al obtener categorías'
        }), 500

@tour_bp.route('/destacados', methods=['GET'])
def get_featured_tours():
    """
    Obtener tours destacados (más populares/reservados)
    GET /api/tours/destacados
    Query parameters:
      - limit: número de tours (default: 6)
    """
    try:
        limit = request.args.get('limit', 6, type=int)
        
        from models.tour import Tour
        
        # Obtener tours destacados (disponibles, ordenados por vistas o calificación)
        tours = Tour.query.filter_by(disponible=True)\
                          .order_by(Tour.vistas.desc(), Tour.calificacion_promedio.desc())\
                          .limit(limit)\
                          .all()
        
        return jsonify({
            'success': True,
            'tours': [tour.to_dict() for tour in tours],
            'count': len(tours)
        }), 200
        
    except Exception as e:
        logger.error(f"Error obteniendo tours destacados: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Error al obtener tours destacados'
        }), 500

# ========== RUTAS PROTEGIDAS (admin/editor) ==========
@tour_bp.route('/', methods=['POST'])
@jwt_required()
def create_tour():
    """
    Crear nuevo tour (solo administradores/editores)
    POST /api/tours/
    """
    try:
        current_user = get_jwt_identity()
        
        # Verificar permisos
        if current_user.get('rol') not in ['admin', 'editor']:
            return jsonify({
                'success': False,
                'error': 'Se requieren permisos de administrador o editor'
            }), 403
        
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'error': 'Se requiere datos en formato JSON'
            }), 400
        
        # Validar datos
        errors = validate_tour_data(data)
        if errors:
            return jsonify({
                'success': False,
                'errors': errors
            }), 400
        
        from models.tour import Tour
        from models import db
        
        # Crear tour
        tour = Tour(
            nombre=data.get('nombre'),
            descripcion=data.get('descripcion', ''),
            duracion=data.get('duracion', ''),
            precio=float(data.get('precio', 0)),
            capacidad_maxima=int(data.get('capacidad_maxima', 10)),
            categoria=data.get('categoria', 'naturaleza'),
            dificultad=data.get('dificultad', 'moderado'),
            disponible=data.get('disponible', True),
            incluye=data.get('incluye', ''),
            no_incluye=data.get('no_incluye', ''),
            recomendaciones=data.get('recomendaciones', ''),
            punto_encuentro=data.get('punto_encuentro', ''),
            imagen_url=data.get('imagen_url', ''),
            galeria=data.get('galeria', []),
            creado_por=current_user.get('id')
        )
        
        db.session.add(tour)
        db.session.commit()
        
        logger.info(f"Tour creado: {tour.nombre} (ID: {tour.id}) por usuario: {current_user.get('email')}")
        
        return jsonify({
            'success': True,
            'message': 'Tour creado exitosamente',
            'tour': tour.to_dict(detailed=True)
        }), 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creando tour: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': 'Error al crear tour'
        }), 500

@tour_bp.route('/<int:tour_id>', methods=['PUT'])
@jwt_required()
def update_tour(tour_id):
    """
    Actualizar tour (solo administradores/editores)
    PUT /api/tours/<id>
    """
    try:
        current_user = get_jwt_identity()
        
        # Verificar permisos
        if current_user.get('rol') not in ['admin', 'editor']:
            return jsonify({
                'success': False,
                'error': 'Se requieren permisos de administrador o editor'
            }), 403
        
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'error': 'Se requiere datos en formato JSON'
            }), 400
        
        from models.tour import Tour
        from models import db
        
        tour = Tour.query.get(tour_id)
        
        if not tour:
            return jsonify({
                'success': False,
                'error': 'Tour no encontrado'
            }), 404
        
        # Validar datos
        errors = validate_tour_data(data, for_update=True)
        if errors:
            return jsonify({
                'success': False,
                'errors': errors
            }), 400
        
        # Actualizar campos permitidos
        allowed_fields = ['nombre', 'descripcion', 'duracion', 'precio', 'capacidad_maxima',
                         'categoria', 'dificultad', 'disponible', 'incluye', 'no_incluye',
                         'recomendaciones', 'punto_encuentro', 'imagen_url', 'galeria']
        
        updates_made = []
        for field in allowed_fields:
            if field in data and data[field] is not None:
                old_value = getattr(tour, field)
                new_value = data[field]
                
                # Convertir tipos específicos
                if field == 'precio':
                    new_value = float(new_value)
                elif field == 'capacidad_maxima':
                    new_value = int(new_value)
                
                if old_value != new_value:
                    setattr(tour, field, new_value)
                    updates_made.append(f"{field}: {old_value} → {new_value}")
        
        # Actualizar fecha de modificación
        tour.fecha_actualizacion = datetime.utcnow()
        
        if not updates_made:
            return jsonify({
                'success': True,
                'message': 'No se realizaron cambios',
                'tour': tour.to_dict(detailed=True)
            }), 200
        
        db.session.commit()
        
        logger.info(f"Tour actualizado: {tour.nombre} (ID: {tour.id}) por usuario: {current_user.get('email')}")
        logger.info(f"Cambios: {', '.join(updates_made)}")
        
        return jsonify({
            'success': True,
            'message': 'Tour actualizado exitosamente',
            'tour': tour.to_dict(detailed=True),
            'changes': updates_made
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error actualizando tour: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': 'Error al actualizar tour'
        }), 500

@tour_bp.route('/<int:tour_id>/status', methods=['PATCH'])
@jwt_required()
def toggle_tour_status(tour_id):
    """
    Activar/desactivar tour (solo administradores/editores)
    PATCH /api/tours/<id>/status
    Body: { "disponible": true/false }
    """
    try:
        current_user = get_jwt_identity()
        
        # Verificar permisos
        if current_user.get('rol') not in ['admin', 'editor']:
            return jsonify({
                'success': False,
                'error': 'Se requieren permisos de administrador o editor'
            }), 403
        
        data = request.get_json() or {}
        disponible = data.get('disponible')
        
        if disponible is None:
            return jsonify({
                'success': False,
                'error': 'El campo "disponible" es requerido'
            }), 400
        
        from models.tour import Tour
        from models import db
        
        tour = Tour.query.get(tour_id)
        
        if not tour:
            return jsonify({
                'success': False,
                'error': 'Tour no encontrado'
            }), 404
        
        # Verificar si ya está en el estado solicitado
        if tour.disponible == disponible:
            return jsonify({
                'success': True,
                'message': f'El tour ya está {"disponible" if disponible else "no disponible"}',
                'tour': tour.to_dict()
            }), 200
        
        # Actualizar estado
        tour.disponible = disponible
        tour.fecha_actualizacion = datetime.utcnow()
        db.session.commit()
        
        action = "activado" if disponible else "desactivado"
        logger.info(f"Tour {action}: {tour.nombre} (ID: {tour.id}) por usuario: {current_user.get('email')}")
        
        return jsonify({
            'success': True,
            'message': f'Tour {action} exitosamente',
            'tour': tour.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error cambiando estado del tour: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': 'Error al cambiar estado del tour'
        }), 500

@tour_bp.route('/<int:tour_id>', methods=['DELETE'])
@jwt_required()
def delete_tour(tour_id):
    """
    Eliminar tour (solo administradores)
    DELETE /api/tours/<id>
    """
    try:
        current_user = get_jwt_identity()
        
        # Verificar permisos de administrador
        if current_user.get('rol') != 'admin':
            return jsonify({
                'success': False,
                'error': 'Se requieren permisos de administrador'
            }), 403
        
        from models.tour import Tour
        from models import db
        
        tour = Tour.query.get(tour_id)
        
        if not tour:
            return jsonify({
                'success': False,
                'error': 'Tour no encontrado'
            }), 404
        
        # Verificar si hay reservas activas para este tour
        # (Necesitarías implementar esta verificación cuando tengas el modelo de reservas)
        # from models.booking import Booking
        # active_bookings = Booking.query.filter_by(tour_id=tour_id, estado__in=['pendiente', 'confirmada']).count()
        # if active_bookings > 0:
        #     return jsonify({
        #         'success': False,
        #         'error': f'No se puede eliminar el tour porque tiene {active_bookings} reservas activas'
        #     }), 400
        
        # Guardar información para logging
        tour_nombre = tour.nombre
        
        # Eliminar tour
        db.session.delete(tour)
        db.session.commit()
        
        logger.warning(f"Tour eliminado: {tour_nombre} (ID: {tour_id}) por admin: {current_user.get('email')}")
        
        return jsonify({
            'success': True,
            'message': f'Tour "{tour_nombre}" eliminado exitosamente'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error eliminando tour: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': 'Error al eliminar tour'
        }), 500

@tour_bp.route('/upload-image', methods=['POST'])
@jwt_required()
def upload_tour_image():
    """
    Subir imagen para tour (solo administradores/editores)
    POST /api/tours/upload-image
    Form data: file (imagen)
    """
    try:
        current_user = get_jwt_identity()
        
        # Verificar permisos
        if current_user.get('rol') not in ['admin', 'editor']:
            return jsonify({
                'success': False,
                'error': 'Se requieren permisos de administrador o editor'
            }), 403
        
        # Verificar si se envió un archivo
        if 'file' not in request.files:
            return jsonify({
                'success': False,
                'error': 'No se envió ningún archivo'
            }), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({
                'success': False,
                'error': 'No se seleccionó ningún archivo'
            }), 400
        
        if not allowed_file(file.filename):
            return jsonify({
                'success': False,
                'error': 'Tipo de archivo no permitido. Solo: png, jpg, jpeg, gif, webp'
            }), 400
        
        # Crear directorio de uploads si no existe
        upload_folder = current_app.config.get('UPLOAD_FOLDER', 'uploads')
        if not os.path.exists(upload_folder):
            os.makedirs(upload_folder)
        
        # Generar nombre único para el archivo
        from werkzeug.utils import secure_filename
        filename = secure_filename(file.filename)
        unique_filename = f"{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{filename}"
        filepath = os.path.join(upload_folder, unique_filename)
        
        # Guardar archivo
        file.save(filepath)
        
        # Crear URL para acceder a la imagen
        base_url = request.host_url.rstrip('/')
        image_url = f"{base_url}/uploads/{unique_filename}"
        
        logger.info(f"Imagen subida: {filename} -> {unique_filename} por usuario: {current_user.get('email')}")
        
        return jsonify({
            'success': True,
            'message': 'Imagen subida exitosamente',
            'filename': unique_filename,
            'original_name': filename,
            'url': image_url,
            'path': filepath
        }), 200
        
    except Exception as e:
        logger.error(f"Error subiendo imagen: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': 'Error al subir imagen'
        }), 500

# ========== RUTAS PARA ESTADÍSTICAS ==========
@tour_bp.route('/stats', methods=['GET'])
@jwt_required()
def get_tour_stats():
    """
    Obtener estadísticas de tours (solo administradores)
    GET /api/tours/stats
    """
    try:
        current_user = get_jwt_identity()
        
        # Verificar permisos de administrador
        if current_user.get('rol') != 'admin':
            return jsonify({
                'success': False,
                'error': 'Se requieren permisos de administrador'
            }), 403
        
        from models.tour import Tour
        from models import db
        from sqlalchemy import func
        
        # Obtener estadísticas
        total_tours = Tour.query.count()
        available_tours = Tour.query.filter_by(disponible=True).count()
        unavailable_tours = total_tours - available_tours
        
        # Tours por categoría
        category_stats = db.session.query(
            Tour.categoria,
            func.count(Tour.id).label('count'),
            func.avg(Tour.precio).label('avg_price'),
            func.sum(Tour.vistas).label('total_views')
        ).group_by(Tour.categoria).all()
        
        # Tours por dificultad
        difficulty_stats = db.session.query(
            Tour.dificultad,
            func.count(Tour.id).label('count')
        ).group_by(Tour.dificultad).all()
        
        # Tours creados por mes (últimos 6 meses)
        six_months_ago = datetime.utcnow().replace(day=1)
        for _ in range(6):
            if six_months_ago.month == 1:
                six_months_ago = six_months_ago.replace(year=six_months_ago.year-1, month=12)
            else:
                six_months_ago = six_months_ago.replace(month=six_months_ago.month-1)
        
        monthly_stats = db.session.query(
            func.strftime('%Y-%m', Tour.fecha_creacion).label('month'),
            func.count(Tour.id).label('count')
        ).filter(Tour.fecha_creacion >= six_months_ago)\
         .group_by('month')\
         .order_by('month')\
         .all()
        
        # Tours más populares (por vistas)
        popular_tours = Tour.query.order_by(Tour.vistas.desc()).limit(5).all()
        
        # Precios estadísticos
        price_stats = db.session.query(
            func.min(Tour.precio).label('min_price'),
            func.max(Tour.precio).label('max_price'),
            func.avg(Tour.precio).label('avg_price'),
            func.stddev(Tour.precio).label('std_price')
        ).first()
        
        return jsonify({
            'success': True,
            'stats': {
                'total': total_tours,
                'available': available_tours,
                'unavailable': unavailable_tours,
                'by_category': [
                    {
                        'category': cat,
                        'count': cnt,
                        'avg_price': float(avg_p) if avg_p else 0,
                        'total_views': total_v or 0
                    } for cat, cnt, avg_p, total_v in category_stats
                ],
                'by_difficulty': {diff: cnt for diff, cnt in difficulty_stats},
                'monthly_created': [
                    {'month': month, 'count': count} 
                    for month, count in monthly_stats
                ],
                'popular_tours': [
                    {
                        'id': tour.id,
                        'nombre': tour.nombre,
                        'vistas': tour.vistas,
                        'calificacion': tour.calificacion_promedio
                    } for tour in popular_tours
                ],
                'prices': {
                    'min': float(price_stats.min_price) if price_stats.min_price else 0,
                    'max': float(price_stats.max_price) if price_stats.max_price else 0,
                    'avg': float(price_stats.avg_price) if price_stats.avg_price else 0,
                    'std': float(price_stats.std_price) if price_stats.std_price else 0
                },
                'last_updated': datetime.utcnow().isoformat()
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error obteniendo estadísticas: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': 'Error al obtener estadísticas'
        }), 500

@tour_bp.route('/<int:tour_id>/reviews', methods=['GET'])
def get_tour_reviews(tour_id):
    """
    Obtener reseñas de un tour (público)
    GET /api/tours/<id>/reviews
    Query parameters:
      - page: número de página (default: 1)
      - per_page: reseñas por página (default: 10)
      - rating: filtrar por calificación (1-5)
    """
    try:
        from models.review import Review  # Necesitarías crear este modelo
        
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        rating_filter = request.args.get('rating', type=int)
        
        # Construir query
        query = Review.query.filter_by(tour_id=tour_id, aprobado=True)
        
        if rating_filter and 1 <= rating_filter <= 5:
            query = query.filter_by(calificacion=rating_filter)
        
        query = query.order_by(Review.fecha_creacion.desc())
        
        # Paginación
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        reviews = pagination.items
        
        # Calcular estadísticas de reseñas
        from models import db
        from sqlalchemy import func
        
        rating_stats = db.session.query(
            func.avg(Review.calificacion).label('avg_rating'),
            func.count(Review.id).label('total_reviews'),
            func.count(db.case((Review.calificacion == 5, 1))).label('five_stars'),
            func.count(db.case((Review.calificacion == 4, 1))).label('four_stars'),
            func.count(db.case((Review.calificacion == 3, 1))).label('three_stars'),
            func.count(db.case((Review.calificacion == 2, 1))).label('two_stars'),
            func.count(db.case((Review.calificacion == 1, 1))).label('one_star')
        ).filter_by(tour_id=tour_id, aprobado=True).first()
        
        return jsonify({
            'success': True,
            'reviews': [review.to_dict() for review in reviews],
            'stats': {
                'avg_rating': float(rating_stats.avg_rating) if rating_stats.avg_rating else 0,
                'total_reviews': rating_stats.total_reviews or 0,
                'distribution': {
                    '5': rating_stats.five_stars or 0,
                    '4': rating_stats.four_stars or 0,
                    '3': rating_stats.three_stars or 0,
                    '2': rating_stats.two_stars or 0,
                    '1': rating_stats.one_star or 0
                }
            },
            'pagination': {
                'page': pagination.page,
                'per_page': pagination.per_page,
                'total_pages': pagination.pages,
                'total_items': pagination.total
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error obteniendo reseñas: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Error al obtener reseñas'
        }), 500