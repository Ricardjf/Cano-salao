# Backend/models/booking.py - MODELO DE RESERVAS CORREGIDO
from datetime import datetime, date, timedelta
from enum import Enum
from . import db
import secrets
import string

class BookingStatus(Enum):
    """Estados posibles de una reserva"""
    PENDING = 'pending'      # Pendiente de confirmación
    CONFIRMED = 'confirmed'  # Confirmada
    CANCELLED = 'cancelled'  # Cancelada
    COMPLETED = 'completed'  # Completada
    NO_SHOW = 'no_show'      # No se presentó
    
    @classmethod
    def get_all(cls):
        """Retorna todos los estados posibles"""
        return [status.value for status in cls]

class Booking(db.Model):
    """Modelo de Reserva para Tours"""
    __tablename__ = 'bookings'
    
    # ========== IDENTIFICACIÓN ==========
    id = db.Column(db.Integer, primary_key=True)
    codigo = db.Column(db.String(20), unique=True, nullable=False, index=True)  # RES-2024-001
    referencia_pago = db.Column(db.String(50), unique=True, nullable=True, index=True)  # Referencia de pago
    
    # ========== RELACIONES ==========
    usuario_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    tour_id = db.Column(db.Integer, db.ForeignKey('tours.id', ondelete='CASCADE'), nullable=False)
    
    # ========== FECHAS Y HORARIOS ==========
    fecha_reserva = db.Column(db.Date, nullable=False, index=True)  # Fecha del tour
    hora_reserva = db.Column(db.String(10), nullable=False)  # Hora del tour: "08:00", "14:00", etc.
    fecha_creacion = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)  # Cuándo se hizo la reserva
    fecha_confirmacion = db.Column(db.DateTime)  # Cuándo se confirmó
    fecha_cancelacion = db.Column(db.DateTime)  # Cuándo se canceló
    fecha_completacion = db.Column(db.DateTime)  # Cuándo se completó
    
    # ========== PARTICIPANTES ==========
    adultos = db.Column(db.Integer, nullable=False, default=1)
    ninos = db.Column(db.Integer, default=0)  # 0-12 años
    estudiantes = db.Column(db.Integer, default=0)  # Con carnet estudiantil
    personas_totales = db.Column(db.Integer, nullable=False)  # adultos + ninos + estudiantes
    
    # ========== PRECIOS Y PAGOS ==========
    precio_adulto = db.Column(db.Float, nullable=False)  # Precio por adulto en el momento de la reserva
    precio_nino = db.Column(db.Float, default=0.0)
    precio_estudiante = db.Column(db.Float, default=0.0)
    subtotal = db.Column(db.Float, nullable=False)
    descuento = db.Column(db.Float, default=0.0)  # Descuento aplicado
    impuestos = db.Column(db.Float, default=0.0)  # Impuestos
    total = db.Column(db.Float, nullable=False)
    moneda = db.Column(db.String(3), default='USD')
    
    # ========== ESTADO Y SEGUIMIENTO ==========
    estado = db.Column(db.String(20), default=BookingStatus.PENDING.value, nullable=False, index=True)
    metodo_pago = db.Column(db.String(50))  # efectivo, transferencia, tarjeta, pago_movil
    estado_pago = db.Column(db.String(20), default='pending')  # pending, paid, failed, refunded
    fecha_pago = db.Column(db.DateTime)
    
    # ========== INFORMACIÓN ADICIONAL ==========
    notas = db.Column(db.Text)  # Notas especiales del cliente
    notas_internas = db.Column(db.Text)  # Notas internas del administrador
    requerimientos_especiales = db.Column(db.Text)  # Requerimientos especiales del cliente
    punto_encuentro = db.Column(db.String(200))  # Punto de encuentro específico
    
    # ========== METADATOS ==========
    ip_cliente = db.Column(db.String(45))  # IP del cliente al hacer la reserva
    user_agent = db.Column(db.Text)  # User agent del navegador
    fuente_reserva = db.Column(db.String(50), default='web')  # web, movil, admin, telefono
    
    # ========== RELACIONES (backrefs) ==========
    usuario = db.relationship('User', backref=db.backref('reservas', lazy='dynamic'))
    tour = db.relationship('Tour', backref=db.backref('reservas', lazy='dynamic'))
    
    # ========== ÍNDICES COMPUESTOS ==========
    __table_args__ = (
        db.Index('idx_booking_user_date', 'usuario_id', 'fecha_reserva'),
        db.Index('idx_booking_tour_date', 'tour_id', 'fecha_reserva'),
        db.Index('idx_booking_status_date', 'estado', 'fecha_reserva'),
    )
    
    # ========== MÉTODOS DE INICIALIZACIÓN ==========
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        
        # Generar código único si no se proporciona
        if not self.codigo:
            self.codigo = self.generar_codigo()
        
        # Calcular total de personas si no se proporciona
        if self.personas_totales is None:
            self.personas_totales = (self.adultos or 0) + (self.ninos or 0) + (self.estudiantes or 0)
        
        # Calcular total si no se proporciona
        if self.total is None and self.subtotal is not None:
            self.total = round(self.subtotal - self.descuento + self.impuestos, 2)
    
    # ========== MÉTODOS DE UTILIDAD ==========
    def generar_codigo(self):
        """Genera un código único para la reserva"""
        from . import db
        from sqlalchemy import func
        
        # Formato: RES-YYYY-XXX (XXX = número secuencial)
        year = datetime.now().year
        count = db.session.query(func.count(Booking.id)).filter(
            db.extract('year', Booking.fecha_creacion) == year
        ).scalar() or 0
        
        return f'RES-{year}-{str(count + 1).zfill(3)}'
    
    def generar_referencia_pago(self):
        """Genera una referencia de pago única"""
        alphabet = string.ascii_uppercase + string.digits
        referencia = ''.join(secrets.choice(alphabet) for _ in range(10))
        self.referencia_pago = f'PAGO-{referencia}'
        return self.referencia_pago
    
    # ========== MÉTODOS DE ESTADO ==========
    def is_pending(self):
        """Verifica si la reserva está pendiente"""
        return self.estado == BookingStatus.PENDING.value
    
    def is_confirmed(self):
        """Verifica si la reserva está confirmada"""
        return self.estado == BookingStatus.CONFIRMED.value
    
    def is_cancelled(self):
        """Verifica si la reserva está cancelada"""
        return self.estado == BookingStatus.CANCELLED.value
    
    def is_completed(self):
        """Verifica si la reserva está completada"""
        return self.estado == BookingStatus.COMPLETED.value
    
    def is_active(self):
        """Verifica si la reserva está activa (confirmada o pendiente)"""
        return self.estado in [BookingStatus.PENDING.value, BookingStatus.CONFIRMED.value]
    
    def can_be_cancelled(self):
        """Verifica si la reserva puede ser cancelada"""
        if self.is_cancelled() or self.is_completed():
            return False
        
        # No cancelar si es para hoy o ya pasó
        hoy = date.today()
        if self.fecha_reserva <= hoy:
            return False
        
        return True
    
    def can_be_confirmed(self):
        """Verifica si la reserva puede ser confirmada"""
        return self.is_pending() and not self.is_cancelled()
    
    # ========== MÉTODOS DE TRANSICIÓN DE ESTADO ==========
    def confirmar(self, notas_internas=None, usuario_confirmador_id=None):
        """Confirma la reserva"""
        if not self.can_be_confirmed():
            return False
        
        self.estado = BookingStatus.CONFIRMED.value
        self.estado_pago = 'paid'  # Asumimos pago completado al confirmar
        self.fecha_confirmacion = datetime.utcnow()
        
        if notas_internas:
            if self.notas_internas:
                self.notas_internas += f"\n[{datetime.utcnow().strftime('%Y-%m-%d %H:%M')}] {notas_internas}"
            else:
                self.notas_internas = f"[{datetime.utcnow().strftime('%Y-%m-%d %H:%M')}] {notas_internas}"
        
        return True
    
    def cancelar(self, motivo=None, usuario_cancelador_id=None):
        """Cancela la reserva"""
        if not self.can_be_cancelled():
            return False
        
        self.estado = BookingStatus.CANCELLED.value
        self.fecha_cancelacion = datetime.utcnow()
        
        if motivo:
            if self.notas_internas:
                self.notas_internas += f"\n[{datetime.utcnow().strftime('%Y-%m-%d %H:%M')}] Cancelado: {motivo}"
            else:
                self.notas_internas = f"[{datetime.utcnow().strftime('%Y-%m-%d %H:%M')}] Cancelado: {motivo}"
        
        # Liberar cupos en el tour
        if self.tour:
            try:
                self.tour.liberar_cupos(self.personas_totales)
            except:
                pass  # Ignorar errores al liberar cupos
        
        return True
    
    def completar(self, notas_internas=None):
        """Marca la reserva como completada"""
        if not self.is_confirmed():
            return False
        
        self.estado = BookingStatus.COMPLETED.value
        self.fecha_completacion = datetime.utcnow()
        
        if notas_internas:
            if self.notas_internas:
                self.notas_internas += f"\n[{datetime.utcnow().strftime('%Y-%m-%d %H:%M')}] Completada: {notas_internas}"
            else:
                self.notas_internas = f"[{datetime.utcnow().strftime('%Y-%m-%d %H:%M')}] Completada: {notas_internas}"
        
        return True
    
    def marcar_como_no_show(self, notas_internas=None):
        """Marca la reserva como no show"""
        if not self.is_confirmed():
            return False
        
        self.estado = BookingStatus.NO_SHOW.value
        
        if notas_internas:
            if self.notas_internas:
                self.notas_internas += f"\n[{datetime.utcnow().strftime('%Y-%m-%d %H:%M')}] No Show: {notas_internas}"
            else:
                self.notas_internas = f"[{datetime.utcnow().strftime('%Y-%m-%d %H:%M')}] No Show: {notas_internas}"
        
        return True
    
    # ========== MÉTODOS DE PAGO ==========
    def marcar_como_pagada(self, metodo_pago=None, referencia=None, fecha_pago=None):
        """Marca la reserva como pagada"""
        self.estado_pago = 'paid'
        self.metodo_pago = metodo_pago or self.metodo_pago
        self.referencia_pago = referencia or self.referencia_pago
        self.fecha_pago = fecha_pago or datetime.utcnow()
        
        # Si estaba pendiente y se paga, confirmar automáticamente
        if self.is_pending():
            self.confirmar(notas_internas="Pago confirmado automáticamente")
        
        return True
    
    def marcar_como_fallida(self, motivo=None):
        """Marca el pago como fallido"""
        self.estado_pago = 'failed'
        
        if motivo:
            if self.notas_internas:
                self.notas_internas += f"\n[{datetime.utcnow().strftime('%Y-%m-%d %H:%M')}] Pago fallido: {motivo}"
            else:
                self.notas_internas = f"[{datetime.utcnow().strftime('%Y-%m-%d %H:%M')}] Pago fallido: {motivo}"
        
        return True
    
    # ========== MÉTODOS DE CÁLCULO ==========
    def calcular_totales(self):
        """Calcula los totales de la reserva"""
        from .tour import Tour
        
        # Obtener tour actualizado
        tour = Tour.query.get(self.tour_id) if not self.tour else self.tour
        
        if not tour:
            return False
        
        # Usar precios del tour
        self.precio_adulto = tour.precio_adulto
        self.precio_nino = tour.precio_nino
        self.precio_estudiante = tour.precio_estudiante
        self.moneda = tour.moneda
        
        # Calcular subtotal
        self.subtotal = (
            (self.adultos * self.precio_adulto) +
            (self.ninos * self.precio_nino) +
            (self.estudiantes * self.precio_estudiante)
        )
        
        # Calcular total (subtotal - descuento + impuestos)
        self.total = round(self.subtotal - self.descuento + self.impuestos, 2)
        
        return True
    
    def aplicar_descuento(self, monto, tipo='fijo', codigo=None):
        """Aplica un descuento a la reserva"""
        if tipo == 'porcentaje':
            # monto es porcentaje (ej: 10 para 10%)
            descuento = self.subtotal * (monto / 100)
        else:
            # monto es cantidad fija
            descuento = monto
        
        # Limitar descuento al subtotal
        descuento = min(descuento, self.subtotal)
        
        self.descuento = round(descuento, 2)
        self.total = round(self.subtotal - self.descuento + self.impuestos, 2)
        
        if codigo:
            if self.notas_internas:
                self.notas_internas += f"\nDescuento aplicado: {codigo} (${descuento:.2f})"
            else:
                self.notas_internas = f"Descuento aplicado: {codigo} (${descuento:.2f})"
        
        return True
    
    # ========== MÉTODOS DE VALIDACIÓN ==========
    def validar_fecha(self):
        """Valida que la fecha de reserva sea válida"""
        hoy = date.today()
        
        # No permitir reservas en el pasado
        if self.fecha_reserva < hoy:
            return False, "No se pueden hacer reservas para fechas pasadas"
        
        # Limitar reservas a 90 días en el futuro
        max_fecha = hoy + timedelta(days=90)
        if self.fecha_reserva > max_fecha:
            return False, "Solo se pueden hacer reservas hasta 90 días en el futuro"
        
        return True, "Fecha válida"
    
    def validar_cupos(self):
        """Valida que haya cupos disponibles"""
        from .tour import Tour
        
        tour = Tour.query.get(self.tour_id) if not self.tour else self.tour
        
        if not tour:
            return False, "Tour no encontrado"
        
        if not tour.hay_cupos_disponibles(self.personas_totales):
            return False, f"No hay cupos disponibles. Cupos restantes: {tour.cupos_disponibles}"
        
        return True, "Cupos disponibles"
    
    def validar_reserva(self):
        """Valida toda la reserva"""
        # Validar fecha
        fecha_valida, fecha_msg = self.validar_fecha()
        if not fecha_valida:
            return False, fecha_msg
        
        # Validar cupos
        cupos_validos, cupos_msg = self.validar_cupos()
        if not cupos_validos:
            return False, cupos_msg
        
        # Validar número de personas
        if self.personas_totales < 1:
            return False, "Debe haber al menos una persona"
        
        if self.personas_totales > 20:  # Límite arbitrario
            return False, "Máximo 20 personas por reserva"
        
        # Validar tour disponible
        if not self.tour or not self.tour.disponible or not self.tour.activo:
            return False, "El tour no está disponible"
        
        return True, "Reserva válida"
    
    # ========== MÉTODOS DE SERIALIZACIÓN ==========
    def to_dict(self, include_details=False):
        """Convierte la reserva a diccionario"""
        data = {
            'id': self.id,
            'codigo': self.codigo,
            'usuario_id': self.usuario_id,
            'tour_id': self.tour_id,
            'fecha_reserva': self.fecha_reserva.isoformat() if self.fecha_reserva else None,
            'hora_reserva': self.hora_reserva,
            'fecha_creacion': self.fecha_creacion.isoformat() if self.fecha_creacion else None,
            'adultos': self.adultos,
            'ninos': self.ninos,
            'estudiantes': self.estudiantes,
            'personas_totales': self.personas_totales,
            'subtotal': self.subtotal,
            'descuento': self.descuento,
            'impuestos': self.impuestos,
            'total': self.total,
            'moneda': self.moneda,
            'estado': self.estado,
            'estado_pago': self.estado_pago,
            'metodo_pago': self.metodo_pago,
        }
        
        if include_details:
            data.update({
                'referencia_pago': self.referencia_pago,
                'fecha_confirmacion': self.fecha_confirmacion.isoformat() if self.fecha_confirmacion else None,
                'fecha_cancelacion': self.fecha_cancelacion.isoformat() if self.fecha_cancelacion else None,
                'fecha_completacion': self.fecha_completacion.isoformat() if self.fecha_completacion else None,
                'precio_adulto': self.precio_adulto,
                'precio_nino': self.precio_nino,
                'precio_estudiante': self.precio_estudiante,
                'notas': self.notas,
                'notas_internas': self.notas_internas,
                'requerimientos_especiales': self.requerimientos_especiales,
                'punto_encuentro': self.punto_encuentro,
                'fecha_pago': self.fecha_pago.isoformat() if self.fecha_pago else None,
                'ip_cliente': self.ip_cliente,
                'user_agent': self.user_agent,
                'fuente_reserva': self.fuente_reserva,
            })
        
        return data
    
    def to_detailed_dict(self):
        """Diccionario detallado para administración"""
        data = self.to_dict(include_details=True)
        
        # Agregar información del usuario
        if self.usuario:
            data['usuario'] = {
                'id': self.usuario.id,
                'nombre': self.usuario.nombre,
                'email': self.usuario.email,
                'telefono': self.usuario.telefono
            }
        
        # Agregar información del tour
        if self.tour:
            data['tour'] = {
                'id': self.tour.id,
                'codigo': self.tour.codigo,
                'nombre': self.tour.nombre,
                'duracion_texto': self.tour.duracion_texto,
                'imagen_principal': self.tour.imagen_principal
            }
        
        return data
    
    def to_public_dict(self):
        """Diccionario para vista pública del cliente"""
        return {
            'codigo': self.codigo,
            'fecha_reserva': self.fecha_reserva.strftime('%d/%m/%Y') if self.fecha_reserva else None,
            'hora_reserva': self.hora_reserva,
            'personas_totales': self.personas_totales,
            'total': self.total,
            'moneda': self.moneda,
            'estado': self.estado,
            'estado_pago': self.estado_pago,
            'tour_nombre': self.tour.nombre if self.tour else None,
            'fecha_creacion': self.fecha_creacion.strftime('%d/%m/%Y %H:%M') if self.fecha_creacion else None,
        }
    
    # ========== MÉTODOS DE CLASE (QUERIES) ==========
    @classmethod
    def find_by_code(cls, code):
        """Busca reserva por código"""
        return cls.query.filter_by(codigo=code).first()
    
    @classmethod
    def find_by_user(cls, user_id, limit=None):
        """Busca reservas de un usuario"""
        query = cls.query.filter_by(usuario_id=user_id).order_by(cls.fecha_reserva.desc())
        if limit:
            query = query.limit(limit)
        return query.all()
    
    @classmethod
    def find_by_tour_and_date(cls, tour_id, fecha):
        """Busca reservas para un tour en una fecha específica"""
        return cls.query.filter_by(tour_id=tour_id, fecha_reserva=fecha).all()
    
    @classmethod
    def find_pending_bookings(cls):
        """Busca reservas pendientes"""
        return cls.query.filter_by(estado=BookingStatus.PENDING.value).order_by(cls.fecha_creacion).all()
    
    @classmethod
    def find_upcoming_bookings(cls, days=7):
        """Busca reservas próximas (próximos X días)"""
        hoy = date.today()
        fecha_limite = hoy + timedelta(days=days)
        
        return cls.query.filter(
            cls.estado.in_([BookingStatus.PENDING.value, BookingStatus.CONFIRMED.value]),
            cls.fecha_reserva >= hoy,
            cls.fecha_reserva <= fecha_limite
        ).order_by(cls.fecha_reserva, cls.hora_reserva).all()
    
    @classmethod
    def find_todays_bookings(cls):
        """Busca reservas para hoy"""
        hoy = date.today()
        return cls.query.filter_by(fecha_reserva=hoy).order_by(cls.hora_reserva).all()
    
    @classmethod
    def get_booking_stats(cls, start_date=None, end_date=None):
        """Obtiene estadísticas de reservas"""
        from sqlalchemy import func
        
        query = cls.query
        
        if start_date:
            query = query.filter(cls.fecha_creacion >= start_date)
        if end_date:
            query = query.filter(cls.fecha_creacion <= end_date)
        
        total = query.count()
        total_revenue = query.with_entities(func.sum(cls.total)).scalar() or 0
        
        # Por estado
        status_stats = query.with_entities(
            cls.estado,
            func.count(cls.id).label('count')
        ).group_by(cls.estado).all()
        
        # Por día (últimos 30 días)
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        daily_stats = query.filter(
            cls.fecha_creacion >= thirty_days_ago
        ).with_entities(
            func.date(cls.fecha_creacion).label('date'),
            func.count(cls.id).label('count'),
            func.sum(cls.total).label('revenue')
        ).group_by('date').order_by('date').all()
        
        return {
            'total': total,
            'total_revenue': round(total_revenue, 2),
            'by_status': {status: count for status, count in status_stats},
            'daily_stats': [
                {
                    'date': date.strftime('%Y-%m-%d') if hasattr(date, 'strftime') else date,
                    'count': count,
                    'revenue': round(revenue or 0, 2)
                }
                for date, count, revenue in daily_stats
            ]
        }
    
    # ========== REPRESENTACIÓN ==========
    def __repr__(self):
        return f'<Booking {self.codigo}: {self.estado}>'
    
    def __str__(self):
        return f'{self.codigo} - {self.tour.nombre if self.tour else "Tour"} - {self.fecha_reserva}'


# Modelo para códigos de descuento (opcional)
class DiscountCode(db.Model):
    """Códigos de descuento para reservas"""
    __tablename__ = 'discount_codes'
    
    id = db.Column(db.Integer, primary_key=True)
    codigo = db.Column(db.String(50), unique=True, nullable=False, index=True)
    tipo = db.Column(db.String(20), default='porcentaje')  # porcentaje, fijo
    valor = db.Column(db.Float, nullable=False)  # 10 para 10% o monto fijo
    uso_maximo = db.Column(db.Integer)  # Usos máximos (null = ilimitado)
    usos_actual = db.Column(db.Integer, default=0)
    valido_desde = db.Column(db.DateTime, default=datetime.utcnow)
    valido_hasta = db.Column(db.DateTime)
    activo = db.Column(db.Boolean, default=True)
    creado_por = db.Column(db.Integer, db.ForeignKey('users.id'))
    fecha_creacion = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Restricciones
    solo_para_tours = db.Column(db.Text)  # IDs de tours separados por coma
    solo_para_usuarios = db.Column(db.Text)  # IDs de usuarios separados por coma
    orden_minima = db.Column(db.Float, default=0.0)  # Orden mínima para aplicar
    
    def is_valid(self, booking=None, user_id=None):
        """Verifica si el código es válido"""
        ahora = datetime.utcnow()
        
        # Validaciones básicas
        if not self.activo:
            return False, "Código inactivo"
        
        if self.valido_desde and ahora < self.valido_desde:
            return False, "Código no válido aún"
        
        if self.valido_hasta and ahora > self.valido_hasta:
            return False, "Código expirado"
        
        if self.uso_maximo and self.usos_actual >= self.uso_maximo:
            return False, "Código ya no disponible"
        
        # Validaciones específicas si hay booking
        if booking:
            if self.orden_minima and booking.subtotal < self.orden_minima:
                return False, f"Orden mínima: {self.orden_minima} {booking.moneda}"
            
            if self.solo_para_tours:
                tours_permitidos = [int(tid) for tid in self.solo_para_tours.split(',')]
                if booking.tour_id not in tours_permitidos:
                    return False, "Código no válido para este tour"
        
        # Validaciones de usuario
        if user_id and self.solo_para_usuarios:
            usuarios_permitidos = [int(uid) for uid in self.solo_para_usuarios.split(',')]
            if user_id not in usuarios_permitidos:
                return False, "Código no válido para este usuario"
        
        return True, "Código válido"
    
    def aplicar(self, booking):
        """Aplica el código a una reserva"""
        es_valido, mensaje = self.is_valid(booking, booking.usuario_id)
        
        if not es_valido:
            return False, mensaje
        
        # Aplicar descuento
        booking.aplicar_descuento(self.valor, self.tipo, self.codigo)
        
        # Incrementar contador de usos
        self.usos_actual += 1
        
        return True, "Descuento aplicado"
    
    def to_dict(self):
        return {
            'id': self.id,
            'codigo': self.codigo,
            'tipo': self.tipo,
            'valor': self.valor,
            'uso_maximo': self.uso_maximo,
            'usos_actual': self.usos_actual,
            'valido_desde': self.valido_desde.isoformat() if self.valido_desde else None,
            'valido_hasta': self.valido_hasta.isoformat() if self.valido_hasta else None,
            'activo': self.activo,
            'orden_minima': self.orden_minima,
            'fecha_creacion': self.fecha_creacion.isoformat() if self.fecha_creacion else None,
        }