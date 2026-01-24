# Backend/routes/booking_routes.py - RUTAS PARA GESTIÓN DE RESERVAS
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
import logging
import re

# Configurar logging
logger = logging.getLogger(__name__)

booking_bp = Blueprint('bookings', __name__)

# ========== VALIDACIONES ==========
def validate_booking_data(data, for_update=False):
    """Valida datos de reserva"""
    errors = []
    
    if not for_update or 'tour_id' in data:
        tour_id = data.get('tour_id')
        if not tour_id or not isinstance(tour_id, int):
            errors.append("tour_id debe ser un número entero válido")
    
    if not for_update or 'fecha' in data:
        fecha = data.get('fecha', '')
        if not fecha:
            errors.append("La fecha es requerida")
        else:
            try:
                fecha_obj = datetime.strptime(fecha, '%Y-%m-%d')
                # Verificar que no sea una fecha pasada
                if fecha_obj.date() < datetime.now().date():
                    errors.append("No se pueden hacer reservas para fechas pasadas")
                # Verificar límite de días en el futuro (ej: 90 días)
                max_future_days = current_app.config.get('MAX_BOOKING_DAYS_AHEAD', 90)
                max_date = datetime.now().date() + timedelta(days=max_future_days)
                if fecha_obj.date() > max_date:
                    errors.append(f"No se pueden hacer reservas con más de {max_future_days} días de anticipación")
            except ValueError:
                errors.append("Formato de fecha inválido. Use YYYY-MM-DD")
    
    if not for_update or 'hora' in data:
        hora = data.get('hora', '')
        if hora:
            try:
                datetime.strptime(hora, '%H:%M')
            except ValueError:
                errors.append("Formato de hora inválido. Use HH:MM (24h)")
    
    if not for_update or 'personas' in data:
        personas = data.get('personas', 1)
        if not isinstance(personas, int) or personas < 1:
            errors.append("El número de personas debe ser un entero mayor a 0")
        
        max_personas = current_app.config.get('MAX_PEOPLE_PER_BOOKING', 20)
        if personas > max_personas:
            errors.append(f"El número máximo de personas por reserva es {max_personas}")
    
    if 'notas' in data and data['notas']:
        notas = data.get('notas', '')
        if len(notas) > 500:
            errors.append("Las notas no pueden exceder 500 caracteres")
    
    if 'estado' in data and data['estado']:
        estado = data.get('estado', '').lower()
        valid_states = ['pending', 'confirmed', 'cancelled', 'completed']
        if estado not in valid_states:
            errors.append(f"Estado inválido. Debe ser: {', '.join(valid_states)}")
    
    return errors

def generate_booking_code():
    """Genera un código único para la reserva"""
    import random
    import string
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    random_chars = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
    return f'RES-{timestamp}-{random_chars}'

# ========== RUTAS PÚBLICAS ==========
@booking_bp.route('/available-dates', methods=['GET'])
def get_available_dates():
    """
    Obtener fechas disponibles para reservas
    GET /api/bookings/available-dates?tour_id=<tour_id>&month=<YYYY-MM>
    """
    try:
        tour_id = request.args.get('tour_id', type=int)
        month_param = request.args.get('month')
        
        if not tour_id:
            return jsonify({
                'success': False,
                'error': 'tour_id es requerido'
            }), 400
        
        from models.tour import Tour
        tour = Tour.find_by_id(tour_id)
        
        if not tour:
            return jsonify({
                'success': False,
                'error': 'Tour no encontrado'
            }), 404
        
        if not tour.disponible:
            return jsonify({
                'success': False,
                'error': 'Este tour no está disponible actualmente'
            }), 400
        
        # Determinar mes a consultar
        if month_param:
            try:
                target_month = datetime.strptime(month_param, '%Y-%m')
            except ValueError:
                return jsonify({
                    'success': False,
                    'error': 'Formato de mes inválido. Use YYYY-MM'
                }), 400
        else:
            target_month = datetime.now().replace(day=1)
        
        # Calcular inicio y fin del mes
        if target_month.month == 12:
            next_month = target_month.replace(year=target_month.year + 1, month=1)
        else:
            next_month = target_month.replace(month=target_month.month + 1)
        
        end_date = next_month - timedelta(days=1)
        
        # Obtener reservas existentes para este tour en el mes
        from models.booking import Booking
        existing_bookings = Booking.query.filter(
            Booking.tour_id == tour_id,
            Booking.fecha >= target_month.date(),
            Booking.fecha <= end_date.date(),
            Booking.estado.in_(['confirmed', 'pending'])
        ).all()
        
        # Calcular disponibilidad por día
        available_dates = []
        current_date = target_month.date()
        
        while current_date <= end_date.date():
            # Verificar que no sea una fecha pasada
            if current_date >= datetime.now().date():
                # Contar personas ya reservadas para esta fecha
                booked_people = sum(
                    booking.personas 
                    for booking in existing_bookings 
                    if booking.fecha == current_date
                )
                
                available_spots = tour.capacidad_maxima - booked_people
                
                if available_spots > 0:
                    available_dates.append({
                        'date': current_date.isoformat(),
                        'available_spots': available_spots,
                        'fully_booked': False
                    })
                else:
                    available_dates.append({
                        'date': current_date.isoformat(),
                        'available_spots': 0,
                        'fully_booked': True
                    })
            
            current_date += timedelta(days=1)
        
        return jsonify({
            'success': True,
            'tour': {
                'id': tour.id,
                'nombre': tour.nombre,
                'capacidad_maxima': tour.capacidad_maxima,
                'precio': float(tour.precio) if tour.precio else 0
            },
            'month': target_month.strftime('%Y-%m'),
            'available_dates': available_dates,
            'count': len([d for d in available_dates if not d['fully_booked']])
        }), 200
        
    except Exception as e:
        logger.error(f"Error obteniendo fechas disponibles: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': 'Error al obtener fechas disponibles'
        }), 500

# ========== RUTAS PROTEGIDAS ==========
@booking_bp.route('/', methods=['POST'])
@jwt_required()
def create_booking():
    """
    Crear una nueva reserva
    POST /api/bookings/
    """
    try:
        current_user = get_jwt_identity()
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'error': 'Se requiere datos en formato JSON'
            }), 400
        
        # Validar datos
        errors = validate_booking_data(data)
        if errors:
            return jsonify({
                'success': False,
                'errors': errors
            }), 400
        
        tour_id = data.get('tour_id')
        fecha_str = data.get('fecha')
        hora = data.get('hora', '10:00')
        personas = data.get('personas', 1)
        notas = data.get('notas', '')
        
        # Verificar tour
        from models.tour import Tour
        tour = Tour.find_by_id(tour_id)
        
        if not tour:
            return jsonify({
                'success': False,
                'error': 'Tour no encontrado'
            }), 404
        
        if not tour.disponible:
            return jsonify({
                'success': False,
                'error': 'Este tour no está disponible actualmente'
            }), 400
        
        # Verificar capacidad
        fecha = datetime.strptime(fecha_str, '%Y-%m-%d').date()
        
        from models.booking import Booking
        from models import db
        
        # Calcular personas ya reservadas para esta fecha y tour
        existing_bookings = Booking.query.filter(
            Booking.tour_id == tour_id,
            Booking.fecha == fecha,
            Booking.estado.in_(['confirmed', 'pending'])
        ).all()
        
        booked_people = sum(booking.personas for booking in existing_bookings)
        available_spots = tour.capacidad_maxima - booked_people
        
        if personas > available_spots:
            return jsonify({
                'success': False,
                'error': f'No hay suficiente capacidad. Quedan {available_spots} espacios disponibles'
            }), 400
        
        # Calcular total
        total = float(tour.precio) * personas if tour.precio else 0
        
        # Crear reserva
        booking = Booking(
            codigo=generate_booking_code(),
            usuario_id=current_user['id'],
            tour_id=tour_id,
            fecha=fecha,
            hora=hora,
            personas=personas,
            total=total,
            notas=notas,
            estado='pending',  # Estado inicial
            fecha_creacion=datetime.utcnow()
        )
        
        db.session.add(booking)
        db.session.commit()
        
        # Obtener datos completos para respuesta
        booking_data = booking.to_dict()
        booking_data['tour'] = tour.to_dict()
        
        logger.info(f"Nueva reserva creada: {booking.codigo} por usuario {current_user['email']}")
        
        return jsonify({
            'success': True,
            'message': 'Reserva creada exitosamente',
            'booking': booking_data,
            'confirmation': {
                'code': booking.codigo,
                'total': f"${total:.2f}",
                'date': fecha_str,
                'time': hora,
                'people': personas
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creando reserva: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': 'Error al crear la reserva'
        }), 500

@booking_bp.route('/my-bookings', methods=['GET'])
@jwt_required()
def get_my_bookings():
    """
    Obtener las reservas del usuario actual
    GET /api/bookings/my-bookings
    Query parameters:
      - status: filtrar por estado
      - from_date: filtrar desde fecha
      - to_date: filtrar hasta fecha
      - page: número de página
      - per_page: reservas por página
    """
    try:
        current_user = get_jwt_identity()
        
        # Obtener parámetros
        status_filter = request.args.get('status')
        from_date_str = request.args.get('from_date')
        to_date_str = request.args.get('to_date')
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        
        from models.booking import Booking
        from models.tour import Tour
        
        # Construir query
        query = Booking.query.filter_by(usuario_id=current_user['id'])
        
        # Aplicar filtros
        if status_filter:
            query = query.filter_by(estado=status_filter)
        
        if from_date_str:
            try:
                from_date = datetime.strptime(from_date_str, '%Y-%m-%d').date()
                query = query.filter(Booking.fecha >= from_date)
            except ValueError:
                pass
        
        if to_date_str:
            try:
                to_date = datetime.strptime(to_date_str, '%Y-%m-%d').date()
                query = query.filter(Booking.fecha <= to_date)
            except ValueError:
                pass
        
        # Ordenar por fecha (más recientes primero)
        query = query.order_by(Booking.fecha.desc(), Booking.hora.desc())
        
        # Paginación
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        bookings = pagination.items
        
        # Obtener datos completos de tours
        bookings_data = []
        for booking in bookings:
            booking_dict = booking.to_dict()
            tour = Tour.find_by_id(booking.tour_id)
            if tour:
                booking_dict['tour'] = tour.to_dict()
            bookings_data.append(booking_dict)
        
        # Datos de paginación
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
            'bookings': bookings_data,
            'pagination': pagination_data,
            'count': len(bookings),
            'summary': {
                'total': pagination.total,
                'pending': Booking.query.filter_by(
                    usuario_id=current_user['id'], 
                    estado='pending'
                ).count(),
                'confirmed': Booking.query.filter_by(
                    usuario_id=current_user['id'], 
                    estado='confirmed'
                ).count(),
                'completed': Booking.query.filter_by(
                    usuario_id=current_user['id'], 
                    estado='completed'
                ).count()
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error obteniendo reservas del usuario: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': 'Error al obtener reservas'
        }), 500

@booking_bp.route('/<booking_code>', methods=['GET'])
@jwt_required()
def get_booking_by_code(booking_code):
    """
    Obtener reserva por código
    GET /api/bookings/<booking_code>
    """
    try:
        current_user = get_jwt_identity()
        
        from models.booking import Booking
        from models.tour import Tour
        from models.user import User
        
        booking = Booking.find_by_code(booking_code)
        
        if not booking:
            return jsonify({
                'success': False,
                'error': 'Reserva no encontrada'
            }), 404
        
        # Verificar permisos: usuario puede ver sus propias reservas, admin puede ver todas
        if current_user.get('rol') != 'admin' and booking.usuario_id != current_user['id']:
            return jsonify({
                'success': False,
                'error': 'No tienes permisos para ver esta reserva'
            }), 403
        
        # Obtener datos completos
        booking_data = booking.to_dict(include_sensitive=True)
        
        tour = Tour.find_by_id(booking.tour_id)
        if tour:
            booking_data['tour'] = tour.to_dict()
        
        user = User.find_by_id(booking.usuario_id)
        if user:
            booking_data['user'] = user.to_dict()
        
        return jsonify({
            'success': True,
            'booking': booking_data
        }), 200
        
    except Exception as e:
        logger.error(f"Error obteniendo reserva: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': 'Error al obtener reserva'
        }), 500

@booking_bp.route('/<booking_code>', methods=['PUT'])
@jwt_required()
def update_booking(booking_code):
    """
    Actualizar reserva
    PUT /api/bookings/<booking_code>
    """
    try:
        current_user = get_jwt_identity()
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'error': 'Se requiere datos en formato JSON'
            }), 400
        
        from models.booking import Booking
        from models import db
        
        booking = Booking.find_by_code(booking_code)
        
        if not booking:
            return jsonify({
                'success': False,
                'error': 'Reserva no encontrada'
            }), 404
        
        # Verificar permisos: usuario puede actualizar sus propias reservas pendientes, admin puede actualizar cualquier reserva
        if current_user.get('rol') != 'admin':
            if booking.usuario_id != current_user['id']:
                return jsonify({
                    'success': False,
                    'error': 'No tienes permisos para actualizar esta reserva'
                }), 403
            
            # Usuarios normales solo pueden actualizar reservas pendientes
            if booking.estado != 'pending':
                return jsonify({
                    'success': False,
                    'error': 'Solo se pueden actualizar reservas pendientes'
                }), 400
        
        # Validar datos de actualización
        errors = validate_booking_data(data, for_update=True)
        if errors:
            return jsonify({
                'success': False,
                'errors': errors
            }), 400
        
        # Verificar cambios en fecha o número de personas
        changes_made = []
        
        if 'fecha' in data and data['fecha']:
            nueva_fecha = datetime.strptime(data['fecha'], '%Y-%m-%d').date()
            if nueva_fecha != booking.fecha:
                # Verificar disponibilidad en nueva fecha
                from models.tour import Tour
                tour = Tour.find_by_id(booking.tour_id)
                
                if tour:
                    existing_bookings = Booking.query.filter(
                        Booking.tour_id == booking.tour_id,
                        Booking.fecha == nueva_fecha,
                        Booking.estado.in_(['confirmed', 'pending']),
                        Booking.id != booking.id
                    ).all()
                    
                    booked_people = sum(b.personas for b in existing_bookings)
                    available_spots = tour.capacidad_maxima - booked_people
                    
                    personas = data.get('personas', booking.personas)
                    if personas > available_spots:
                        return jsonify({
                            'success': False,
                            'error': f'No hay suficiente capacidad en la nueva fecha. Quedan {available_spots} espacios disponibles'
                        }), 400
                
                booking.fecha = nueva_fecha
                changes_made.append(f"Fecha cambiada a {data['fecha']}")
        
        if 'personas' in data:
            nuevas_personas = data['personas']
            if nuevas_personas != booking.personas:
                # Verificar capacidad
                from models.tour import Tour
                tour = Tour.find_by_id(booking.tour_id)
                
                if tour:
                    existing_bookings = Booking.query.filter(
                        Booking.tour_id == booking.tour_id,
                        Booking.fecha == booking.fecha,
                        Booking.estado.in_(['confirmed', 'pending']),
                        Booking.id != booking.id
                    ).all()
                    
                    booked_people = sum(b.personas for b in existing_bookings)
                    available_spots = tour.capacidad_maxima - booked_people
                    
                    if nuevas_personas > available_spots + booking.personas:
                        return jsonify({
                            'success': False,
                            'error': f'No hay suficiente capacidad. Quedan {available_spots} espacios disponibles adicionales'
                        }), 400
                
                # Actualizar total si cambia el número de personas
                if tour and tour.precio:
                    booking.total = float(tour.precio) * nuevas_personas
                
                booking.personas = nuevas_personas
                changes_made.append(f"Personas cambiadas a {nuevas_personas}")
        
        # Actualizar otros campos
        if 'hora' in data and data['hora']:
            booking.hora = data['hora']
            changes_made.append(f"Hora cambiada a {data['hora']}")
        
        if 'notas' in data:
            booking.notas = data['notas']
            changes_made.append("Notas actualizadas")
        
        # Solo admin puede cambiar estado
        if 'estado' in data and current_user.get('rol') == 'admin':
            nuevo_estado = data['estado'].lower()
            if nuevo_estado != booking.estado:
                booking.estado = nuevo_estado
                changes_made.append(f"Estado cambiado a {nuevo_estado}")
        
        db.session.commit()
        
        if changes_made:
            logger.info(f"Reserva {booking_code} actualizada. Cambios: {', '.join(changes_made)}")
        
        return jsonify({
            'success': True,
            'message': 'Reserva actualizada exitosamente' if changes_made else 'No se realizaron cambios',
            'booking': booking.to_dict(),
            'changes': changes_made
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error actualizando reserva: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': 'Error al actualizar reserva'
        }), 500

@booking_bp.route('/<booking_code>/cancel', methods=['POST'])
@jwt_required()
def cancel_booking(booking_code):
    """
    Cancelar reserva
    POST /api/bookings/<booking_code>/cancel
    """
    try:
        current_user = get_jwt_identity()
        
        from models.booking import Booking
        from models import db
        
        booking = Booking.find_by_code(booking_code)
        
        if not booking:
            return jsonify({
                'success': False,
                'error': 'Reserva no encontrada'
            }), 404
        
        # Verificar permisos: usuario puede cancelar sus propias reservas, admin puede cancelar cualquier reserva
        if current_user.get('rol') != 'admin' and booking.usuario_id != current_user['id']:
            return jsonify({
                'success': False,
                'error': 'No tienes permisos para cancelar esta reserva'
            }), 403
        
        # Verificar que la reserva se pueda cancelar
        if booking.estado == 'cancelled':
            return jsonify({
                'success': False,
                'error': 'La reserva ya está cancelada'
            }), 400
        
        if booking.estado == 'completed':
            return jsonify({
                'success': False,
                'error': 'No se puede cancelar una reserva completada'
            }), 400
        
        # Verificar tiempo mínimo de cancelación (ej: 24 horas antes)
        fecha_reserva = datetime.combine(booking.fecha, datetime.strptime(booking.hora, '%H:%M').time())
        tiempo_restante = fecha_reserva - datetime.now()
        
        min_cancel_hours = current_app.config.get('MIN_BOOKING_HOURS_NOTICE', 24)
        if tiempo_restante.total_seconds() / 3600 < min_cancel_hours:
            return jsonify({
                'success': False,
                'error': f'Solo se pueden cancelar reservas con al menos {min_cancel_hours} horas de anticipación'
            }), 400
        
        # Cancelar reserva
        booking.estado = 'cancelled'
        db.session.commit()
        
        logger.info(f"Reserva {booking_code} cancelada por usuario {current_user.get('email')}")
        
        return jsonify({
            'success': True,
            'message': 'Reserva cancelada exitosamente',
            'booking': booking.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error cancelando reserva: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': 'Error al cancelar reserva'
        }), 500

# ========== RUTAS ADMINISTRATIVAS ==========
@booking_bp.route('/all', methods=['GET'])
@jwt_required()
def get_all_bookings():
    """
    Obtener todas las reservas (solo administradores)
    GET /api/bookings/all
    Query parameters:
      - status: filtrar por estado
      - from_date: filtrar desde fecha
      - to_date: filtrar hasta fecha
      - tour_id: filtrar por tour
      - user_id: filtrar por usuario
      - page: número de página
      - per_page: reservas por página
    """
    try:
        current_user = get_jwt_identity()
        
        # Verificar permisos de administrador
        if current_user.get('rol') != 'admin':
            return jsonify({
                'success': False,
                'error': 'Se requieren permisos de administrador'
            }), 403
        
        # Obtener parámetros
        status_filter = request.args.get('status')
        from_date_str = request.args.get('from_date')
        to_date_str = request.args.get('to_date')
        tour_id = request.args.get('tour_id', type=int)
        user_id = request.args.get('user_id', type=int)
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        
        from models.booking import Booking
        from models.tour import Tour
        from models.user import User
        
        # Construir query
        query = Booking.query
        
        # Aplicar filtros
        if status_filter:
            query = query.filter_by(estado=status_filter)
        
        if tour_id:
            query = query.filter_by(tour_id=tour_id)
        
        if user_id:
            query = query.filter_by(usuario_id=user_id)
        
        if from_date_str:
            try:
                from_date = datetime.strptime(from_date_str, '%Y-%m-%d').date()
                query = query.filter(Booking.fecha >= from_date)
            except ValueError:
                pass
        
        if to_date_str:
            try:
                to_date = datetime.strptime(to_date_str, '%Y-%m-%d').date()
                query = query.filter(Booking.fecha <= to_date)
            except ValueError:
                pass
        
        # Ordenar por fecha (más recientes primero)
        query = query.order_by(Booking.fecha.desc(), Booking.hora.desc())
        
        # Paginación
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        bookings = pagination.items
        
        # Obtener datos completos
        bookings_data = []
        for booking in bookings:
            booking_dict = booking.to_dict(include_sensitive=True)
            
            tour = Tour.find_by_id(booking.tour_id)
            if tour:
                booking_dict['tour'] = tour.to_dict()
            
            user = User.find_by_id(booking.usuario_id)
            if user:
                booking_dict['user'] = user.to_dict()
            
            bookings_data.append(booking_dict)
        
        # Datos de paginación
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
            'bookings': bookings_data,
            'pagination': pagination_data,
            'count': len(bookings),
            'summary': {
                'total': pagination.total,
                'pending': Booking.query.filter_by(estado='pending').count(),
                'confirmed': Booking.query.filter_by(estado='confirmed').count(),
                'cancelled': Booking.query.filter_by(estado='cancelled').count(),
                'completed': Booking.query.filter_by(estado='completed').count()
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error obteniendo todas las reservas: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': 'Error al obtener reservas'
        }), 500

@booking_bp.route('/stats', methods=['GET'])
@jwt_required()
def get_booking_stats():
    """
    Obtener estadísticas de reservas (solo administradores)
    GET /api/bookings/stats
    Query parameters:
      - period: day, week, month, year (default: month)
      - from_date: fecha inicial
      - to_date: fecha final
    """
    try:
        current_user = get_jwt_identity()
        
        # Verificar permisos de administrador
        if current_user.get('rol') != 'admin':
            return jsonify({
                'success': False,
                'error': 'Se requieren permisos de administrador'
            }), 403
        
        from models.booking import Booking
        from models import db
        from sqlalchemy import func, extract
        
        # Obtener parámetros
        period = request.args.get('period', 'month')
        from_date_str = request.args.get('from_date')
        to_date_str = request.args.get('to_date')
        
        # Construir query base
        query = Booking.query
        
        # Aplicar filtros de fecha
        if from_date_str:
            try:
                from_date = datetime.strptime(from_date_str, '%Y-%m-%d').date()
                query = query.filter(Booking.fecha >= from_date)
            except ValueError:
                pass
        
        if to_date_str:
            try:
                to_date = datetime.strptime(to_date_str, '%Y-%m-%d').date()
                query = query.filter(Booking.fecha <= to_date)
            except ValueError:
                pass
        
        # Estadísticas generales
        total_bookings = query.count()
        total_revenue = db.session.query(
            func.sum(Booking.total)
        ).filter(
            Booking.estado.in_(['confirmed', 'completed'])
        ).scalar() or 0
        
        # Reservas por estado
        status_stats = db.session.query(
            Booking.estado,
            func.count(Booking.id).label('count')
        ).group_by(Booking.estado).all()
        
        status_dict = {status: count for status, count in status_stats}
        
        # Reservas por tour
        tour_stats = db.session.query(
            Booking.tour_id,
            func.count(Booking.id).label('count'),
            func.sum(Booking.total).label('revenue')
        ).filter(
            Booking.estado.in_(['confirmed', 'completed'])
        ).group_by(Booking.tour_id).order_by(func.count(Booking.id).desc()).limit(10).all()
        
        # Reservas por fecha (según periodo)
        if period == 'day':
            date_format = '%Y-%m-%d'
            group_by = func.date(Booking.fecha)
        elif period == 'week':
            date_format = '%Y-W%W'
            group_by = func.strftime('%Y-W%W', Booking.fecha)
        elif period == 'year':
            date_format = '%Y'
            group_by = extract('year', Booking.fecha)
        else:  # month
            date_format = '%Y-%m'
            group_by = func.strftime('%Y-%m', Booking.fecha)
        
        timeline_stats = db.session.query(
            group_by.label('period'),
            func.count(Booking.id).label('count'),
            func.sum(Booking.total).label('revenue')
        ).filter(
            Booking.estado.in_(['confirmed', 'completed'])
        ).group_by('period').order_by('period').all()
        
        # Reservas por hora del día
        hour_stats = db.session.query(
            func.substr(Booking.hora, 1, 2).label('hour'),
            func.count(Booking.id).label('count')
        ).group_by('hour').order_by('hour').all()
        
        return jsonify({
            'success': True,
            'stats': {
                'period': period,
                'total_bookings': total_bookings,
                'total_revenue': float(total_revenue),
                'avg_booking_value': float(total_revenue / total_bookings) if total_bookings > 0 else 0,
                'by_status': status_dict,
                'top_tours': [
                    {
                        'tour_id': tour_id,
                        'count': count,
                        'revenue': float(revenue) if revenue else 0
                    }
                    for tour_id, count, revenue in tour_stats
                ],
                'timeline': [
                    {
                        'period': str(period),
                        'count': count,
                        'revenue': float(revenue) if revenue else 0
                    }
                    for period, count, revenue in timeline_stats
                ],
                'by_hour': [
                    {
                        'hour': hour,
                        'count': count
                    }
                    for hour, count in hour_stats
                ],
                'date_range': {
                    'from': from_date_str or 'all',
                    'to': to_date_str or 'all'
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

@booking_bp.route('/<booking_code>/confirm', methods=['POST'])
@jwt_required()
def confirm_booking(booking_code):
    """
    Confirmar reserva (solo administradores)
    POST /api/bookings/<booking_code>/confirm
    """
    try:
        current_user = get_jwt_identity()
        
        # Verificar permisos de administrador
        if current_user.get('rol') != 'admin':
            return jsonify({
                'success': False,
                'error': 'Se requieren permisos de administrador'
            }), 403
        
        from models.booking import Booking
        from models import db
        
        booking = Booking.find_by_code(booking_code)
        
        if not booking:
            return jsonify({
                'success': False,
                'error': 'Reserva no encontrada'
            }), 404
        
        if booking.estado == 'confirmed':
            return jsonify({
                'success': False,
                'error': 'La reserva ya está confirmada'
            }), 400
        
        if booking.estado == 'cancelled':
            return jsonify({
                'success': False,
                'error': 'No se puede confirmar una reserva cancelada'
            }), 400
        
        # Confirmar reserva
        booking.estado = 'confirmed'
        db.session.commit()
        
        logger.info(f"Reserva {booking_code} confirmada por admin {current_user.get('email')}")
        
        return jsonify({
            'success': True,
            'message': 'Reserva confirmada exitosamente',
            'booking': booking.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error confirmando reserva: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': 'Error al confirmar reserva'
        }), 500

@booking_bp.route('/<booking_code>/complete', methods=['POST'])
@jwt_required()
def complete_booking(booking_code):
    """
    Marcar reserva como completada (solo administradores)
    POST /api/bookings/<booking_code>/complete
    """
    try:
        current_user = get_jwt_identity()
        
        # Verificar permisos de administrador
        if current_user.get('rol') != 'admin':
            return jsonify({
                'success': False,
                'error': 'Se requieren permisos de administrador'
            }), 403
        
        from models.booking import Booking
        from models import db
        
        booking = Booking.find_by_code(booking_code)
        
        if not booking:
            return jsonify({
                'success': False,
                'error': 'Reserva no encontrada'
            }), 404
        
        if booking.estado == 'completed':
            return jsonify({
                'success': False,
                'error': 'La reserva ya está marcada como completada'
            }), 400
        
        if booking.estado != 'confirmed':
            return jsonify({
                'success': False,
                'error': 'Solo se pueden completar reservas confirmadas'
            }), 400
        
        # Verificar que la fecha de la reserva haya pasado
        fecha_reserva = datetime.combine(booking.fecha, datetime.strptime(booking.hora, '%H:%M').time())
        if fecha_reserva > datetime.now():
            return jsonify({
                'success': False,
                'error': 'No se puede completar una reserva futura'
            }), 400
        
        # Marcar como completada
        booking.estado = 'completed'
        db.session.commit()
        
        logger.info(f"Reserva {booking_code} marcada como completada por admin {current_user.get('email')}")
        
        return jsonify({
            'success': True,
            'message': 'Reserva marcada como completada exitosamente',
            'booking': booking.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error completando reserva: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': 'Error al completar reserva'
        }), 500

@booking_bp.route('/check-availability', methods=['POST'])
@jwt_required()
def check_availability():
    """
    Verificar disponibilidad específica
    POST /api/bookings/check-availability
    Body: {
        "tour_id": 1,
        "fecha": "2024-01-15",
        "personas": 4
    }
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'error': 'Se requiere datos en formato JSON'
            }), 400
        
        tour_id = data.get('tour_id')
        fecha_str = data.get('fecha')
        personas = data.get('personas', 1)
        
        if not tour_id or not fecha_str:
            return jsonify({
                'success': False,
                'error': 'tour_id y fecha son requeridos'
            }), 400
        
        from models.tour import Tour
        from models.booking import Booking
        
        tour = Tour.find_by_id(tour_id)
        
        if not tour:
            return jsonify({
                'success': False,
                'error': 'Tour no encontrado'
            }), 404
        
        if not tour.disponible:
            return jsonify({
                'success': False,
                'available': False,
                'message': 'Este tour no está disponible actualmente'
            }), 200
        
        try:
            fecha = datetime.strptime(fecha_str, '%Y-%m-%d').date()
        except ValueError:
            return jsonify({
                'success': False,
                'error': 'Formato de fecha inválido. Use YYYY-MM-DD'
            }), 400
        
        # Verificar que no sea una fecha pasada
        if fecha < datetime.now().date():
            return jsonify({
                'success': True,
                'available': False,
                'message': 'No se pueden hacer reservas para fechas pasadas'
            }), 200
        
        # Calcular disponibilidad
        existing_bookings = Booking.query.filter(
            Booking.tour_id == tour_id,
            Booking.fecha == fecha,
            Booking.estado.in_(['confirmed', 'pending'])
        ).all()
        
        booked_people = sum(booking.personas for booking in existing_bookings)
        available_spots = tour.capacidad_maxima - booked_people
        
        is_available = personas <= available_spots
        
        return jsonify({
            'success': True,
            'available': is_available,
            'details': {
                'tour': {
                    'id': tour.id,
                    'nombre': tour.nombre,
                    'capacidad_maxima': tour.capacidad_maxima,
                    'precio': float(tour.precio) if tour.precio else 0
                },
                'date': fecha_str,
                'requested_people': personas,
                'available_spots': available_spots,
                'already_booked': booked_people,
                'can_accommodate': is_available
            },
            'message': f'{"Hay disponibilidad" if is_available else f"No hay disponibilidad. Quedan {available_spots} espacios disponibles"}'
        }), 200
        
    except Exception as e:
        logger.error(f"Error verificando disponibilidad: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': 'Error al verificar disponibilidad'
        }), 500