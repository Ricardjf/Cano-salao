# Backend/models/tour.py - MODELO DE TOUR CORREGIDO
from datetime import datetime
from . import db

class Tour(db.Model):
    """Modelo de Tour Turístico para Caño Salao"""
    __tablename__ = 'tours'
    
    # ========== IDENTIFICACIÓN ==========
    id = db.Column(db.Integer, primary_key=True)
    codigo = db.Column(db.String(20), unique=True, nullable=False, index=True)  # Código único: TOUR-001
    nombre = db.Column(db.String(200), nullable=False)
    slug = db.Column(db.String(220), unique=True, nullable=False, index=True)  # URL amigable
    
    # ========== DESCRIPCIÓN Y CONTENIDO ==========
    descripcion_corta = db.Column(db.String(300), nullable=False)  # Para listados
    descripcion_larga = db.Column(db.Text, nullable=False)  # Para página detalle
    itinerario = db.Column(db.Text)  # Itinerario detallado
    incluye = db.Column(db.Text)  # Qué incluye el tour
    no_incluye = db.Column(db.Text)  # Qué no incluye
    recomendaciones = db.Column(db.Text)  # Recomendaciones para el tour
    
    # ========== DURACIÓN Y HORARIOS ==========
    duracion_horas = db.Column(db.Integer, nullable=False)  # Duración en horas
    duracion_texto = db.Column(db.String(50), nullable=False)  # Ej: "2 horas", "1 día completo"
    horarios_disponibles = db.Column(db.Text, default='08:00,10:00,14:00,16:00')  # Horarios separados por coma
    
    # ========== PRECIOS Y PAGOS ==========
    precio_adulto = db.Column(db.Float, nullable=False)
    precio_nino = db.Column(db.Float, default=0.0)  # Precio para niños (0-12 años)
    precio_estudiante = db.Column(db.Float, default=0.0)  # Precio para estudiantes
    precio_grupo = db.Column(db.Float)  # Precio especial para grupos
    moneda = db.Column(db.String(3), default='USD')  # USD, EUR, VES
    
    # ========== CAPACIDAD Y DISPONIBILIDAD ==========
    capacidad_maxima = db.Column(db.Integer, nullable=False)
    capacidad_minima = db.Column(db.Integer, default=1)  # Mínimo para realizar el tour
    cupos_disponibles = db.Column(db.Integer, nullable=False)  # Se actualiza con cada reserva
    disponible = db.Column(db.Boolean, default=True, nullable=False)
    
    # ========== CATEGORIZACIÓN ==========
    categoria = db.Column(db.String(50), default='aventura')  # aventura, naturaleza, cultura, educativo, fotografia
    dificultad = db.Column(db.String(20), default='media')  # baja, media, alta
    edad_minima = db.Column(db.Integer, default=5)  # Edad mínima para participar
    requiere_condicion_fisica = db.Column(db.Boolean, default=False)
    
    # ========== MEDIOS Y MULTIMEDIA ==========
    imagen_principal = db.Column(db.String(500))
    imagenes_secundarias = db.Column(db.Text)  # URLs separadas por coma
    video_url = db.Column(db.String(500))  # URL de video promocional
    mapa_url = db.Column(db.String(500))  # URL de mapa o ubicación
    
    # ========== METADATOS Y SEO ==========
    palabras_clave = db.Column(db.Text)  # Para SEO
    meta_descripcion = db.Column(db.String(300))  # Para SEO
    destacado = db.Column(db.Boolean, default=False)  # Tour destacado en portada
    orden = db.Column(db.Integer, default=0)  # Orden de visualización
    
    # ========== DATOS DE REGISTRO ==========
    fecha_creacion = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    fecha_actualizacion = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    creado_por = db.Column(db.Integer, db.ForeignKey('users.id'))  # ID del usuario que creó el tour
    activo = db.Column(db.Boolean, default=True, nullable=False)
    
    # ========== RELACIONES ==========
    # Relación con reservas (si el modelo Booking existe)
    # reservas = db.relationship('Booking', backref='tour', lazy='dynamic', cascade='all, delete-orphan')
    
    # ========== MÉTODOS DE INICIALIZACIÓN ==========
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Generar código automático si no se proporciona
        if not self.codigo:
            self.codigo = self.generar_codigo()
        # Generar slug automático si no se proporciona
        if not self.slug and self.nombre:
            self.slug = self.generar_slug()
        # Inicializar cupos disponibles si no se proporciona
        if self.cupos_disponibles is None:
            self.cupos_disponibles = self.capacidad_maxima
    
    # ========== MÉTODOS DE UTILIDAD ==========
    def generar_codigo(self):
        """Genera un código único para el tour"""
        from . import db
        from sqlalchemy import func
        
        # Contar tours existentes
        count = db.session.query(func.count(Tour.id)).scalar() or 0
        return f'TOUR-{str(count + 1).zfill(3)}'
    
    def generar_slug(self):
        """Genera un slug URL-friendly desde el nombre"""
        import re
        import unicodedata
        
        # Convertir a ASCII
        slug = unicodedata.normalize('NFKD', self.nombre).encode('ascii', 'ignore').decode('utf-8')
        
        # Convertir a minúsculas y reemplazar caracteres especiales
        slug = re.sub(r'[^\w\s-]', '', slug.lower())
        slug = re.sub(r'[-\s]+', '-', slug).strip('-_')
        
        return slug
    
    # ========== MÉTODOS DE DISPONIBILIDAD ==========
    def hay_cupos_disponibles(self, cantidad=1):
        """Verifica si hay cupos disponibles"""
        return self.disponible and self.activo and self.cupos_disponibles >= cantidad
    
    def reservar_cupos(self, cantidad=1):
        """Reserva cupos del tour"""
        if not self.hay_cupos_disponibles(cantidad):
            return False
        
        self.cupos_disponibles -= cantidad
        return True
    
    def liberar_cupos(self, cantidad=1):
        """Libera cupos del tour"""
        if self.cupos_disponibles + cantidad <= self.capacidad_maxima:
            self.cupos_disponibles += cantidad
            return True
        return False
    
    def actualizar_disponibilidad(self):
        """Actualiza el estado de disponibilidad basado en cupos"""
        self.disponible = self.cupos_disponibles > 0 and self.activo
    
    # ========== MÉTODOS DE PRECIO ==========
    def calcular_precio(self, adultos=1, ninos=0, estudiantes=0, es_grupo=False):
        """Calcula el precio total para un grupo"""
        if es_grupo and self.precio_grupo:
            total = self.precio_grupo * (adultos + ninos + estudiantes)
        else:
            total = (self.precio_adulto * adultos) + \
                   (self.precio_nino * ninos) + \
                   (self.precio_estudiante * estudiantes)
        
        return round(total, 2)
    
    def get_precio_formateado(self):
        """Retorna el precio formateado con moneda"""
        return f"{self.moneda} {self.precio_adulto:.2f}"
    
    # ========== MÉTODOS DE SERIALIZACIÓN ==========
    def to_dict(self, include_details=False):
        """Convierte el tour a diccionario"""
        data = {
            'id': self.id,
            'codigo': self.codigo,
            'nombre': self.nombre,
            'slug': self.slug,
            'descripcion_corta': self.descripcion_corta,
            'duracion_texto': self.duracion_texto,
            'duracion_horas': self.duracion_horas,
            'precio_adulto': self.precio_adulto,
            'precio_formateado': self.get_precio_formateado(),
            'capacidad_maxima': self.capacidad_maxima,
            'cupos_disponibles': self.cupos_disponibles,
            'disponible': self.disponible and self.activo,
            'categoria': self.categoria,
            'dificultad': self.dificultad,
            'edad_minima': self.edad_minima,
            'imagen_principal': self.imagen_principal,
            'destacado': self.destacado,
            'orden': self.orden,
            'fecha_creacion': self.fecha_creacion.isoformat() if self.fecha_creacion else None,
        }
        
        if include_details:
            data.update({
                'descripcion_larga': self.descripcion_larga,
                'itinerario': self.itinerario,
                'incluye': self.incluye.split(',') if self.incluye else [],
                'no_incluye': self.no_incluye.split(',') if self.no_incluye else [],
                'recomendaciones': self.recomendaciones,
                'horarios_disponibles': self.horarios_disponibles.split(',') if self.horarios_disponibles else [],
                'precio_nino': self.precio_nino,
                'precio_estudiante': self.precio_estudiante,
                'precio_grupo': self.precio_grupo,
                'moneda': self.moneda,
                'capacidad_minima': self.capacidad_minima,
                'requiere_condicion_fisica': self.requiere_condicion_fisica,
                'imagenes_secundarias': self.imagenes_secundarias.split(',') if self.imagenes_secundarias else [],
                'video_url': self.video_url,
                'mapa_url': self.mapa_url,
                'palabras_clave': self.palabras_clave.split(',') if self.palabras_clave else [],
                'meta_descripcion': self.meta_descripcion,
                'fecha_actualizacion': self.fecha_actualizacion.isoformat() if self.fecha_actualizacion else None,
                'creado_por': self.creado_por,
                'activo': self.activo,
            })
        
        return data
    
    def to_public_dict(self):
        """Diccionario para vista pública"""
        return {
            'id': self.id,
            'codigo': self.codigo,
            'nombre': self.nombre,
            'slug': self.slug,
            'descripcion_corta': self.descripcion_corta,
            'duracion_texto': self.duracion_texto,
            'precio_formateado': self.get_precio_formateado(),
            'capacidad_maxima': self.capacidad_maxima,
            'cupos_disponibles': self.cupos_disponibles,
            'disponible': self.disponible and self.activo,
            'categoria': self.categoria,
            'dificultad': self.dificultad,
            'edad_minima': self.edad_minima,
            'imagen_principal': self.imagen_principal,
            'destacado': self.destacado,
            'fecha_creacion': self.fecha_creacion.strftime('%d/%m/%Y') if self.fecha_creacion else None,
        }
    
    def to_admin_dict(self):
        """Diccionario para panel de administración"""
        return self.to_dict(include_details=True)
    
    # ========== MÉTODOS DE VALIDACIÓN ==========
    @staticmethod
    def validate_price(price):
        """Valida que el precio sea válido"""
        try:
            price_float = float(price)
            return price_float >= 0
        except (ValueError, TypeError):
            return False
    
    @staticmethod
    def validate_capacity(capacity):
        """Valida que la capacidad sea válida"""
        try:
            capacity_int = int(capacity)
            return capacity_int > 0
        except (ValueError, TypeError):
            return False
    
    @staticmethod
    def validate_duration(duration_hours):
        """Valida que la duración sea válida"""
        try:
            duration_int = int(duration_hours)
            return duration_int > 0 and duration_int <= 24
        except (ValueError, TypeError):
            return False
    
    # ========== MÉTODOS DE CLASE (QUERIES) ==========
    @classmethod
    def find_by_slug(cls, slug):
        """Busca tour por slug"""
        return cls.query.filter_by(slug=slug).first()
    
    @classmethod
    def find_by_code(cls, code):
        """Busca tour por código"""
        return cls.query.filter_by(codigo=code).first()
    
    @classmethod
    def find_available_tours(cls):
        """Obtiene todos los tours disponibles"""
        return cls.query.filter_by(disponible=True, activo=True).order_by(cls.orden, cls.nombre).all()
    
    @classmethod
    def find_featured_tours(cls, limit=3):
        """Obtiene tours destacados"""
        return cls.query.filter_by(destacado=True, disponible=True, activo=True)\
                       .order_by(cls.orden, cls.nombre)\
                       .limit(limit)\
                       .all()
    
    @classmethod
    def find_by_category(cls, category):
        """Obtiene tours por categoría"""
        return cls.query.filter_by(categoria=category, disponible=True, activo=True)\
                       .order_by(cls.orden, cls.nombre)\
                       .all()
    
    @classmethod
    def search_tours(cls, search_term):
        """Busca tours por término"""
        from sqlalchemy import or_
        
        return cls.query.filter(
            cls.activo == True,
            or_(
                cls.nombre.ilike(f'%{search_term}%'),
                cls.descripcion_corta.ilike(f'%{search_term}%'),
                cls.descripcion_larga.ilike(f'%{search_term}%'),
                cls.palabras_clave.ilike(f'%{search_term}%')
            )
        ).order_by(cls.orden, cls.nombre).all()
    
    # ========== MÉTODOS DE ACTUALIZACIÓN ==========
    def update_tour(self, **kwargs):
        """Actualiza los datos del tour"""
        allowed_fields = ['nombre', 'descripcion_corta', 'descripcion_larga', 'itinerario',
                         'incluye', 'no_incluye', 'recomendaciones', 'duracion_horas',
                         'duracion_texto', 'horarios_disponibles', 'precio_adulto',
                         'precio_nino', 'precio_estudiante', 'precio_grupo', 'moneda',
                         'capacidad_maxima', 'capacidad_minima', 'categoria', 'dificultad',
                         'edad_minima', 'requiere_condicion_fisica', 'imagen_principal',
                         'imagenes_secundarias', 'video_url', 'mapa_url', 'palabras_clave',
                         'meta_descripcion', 'destacado', 'orden', 'activo']
        
        for field, value in kwargs.items():
            if field in allowed_fields and value is not None:
                setattr(self, field, value)
        
        # Si cambia el nombre, actualizar slug
        if 'nombre' in kwargs and kwargs['nombre']:
            self.slug = self.generar_slug()
        
        # Si cambia la capacidad, actualizar cupos disponibles
        if 'capacidad_maxima' in kwargs and kwargs['capacidad_maxima']:
            if kwargs['capacidad_maxima'] < self.cupos_disponibles:
                self.cupos_disponibles = kwargs['capacidad_maxima']
        
        # Actualizar disponibilidad
        self.actualizar_disponibilidad()
        
        return self
    
    def activate(self):
        """Activa el tour"""
        self.activo = True
        self.actualizar_disponibilidad()
        return self
    
    def deactivate(self):
        """Desactiva el tour"""
        self.activo = False
        self.disponible = False
        return self
    
    def mark_as_featured(self):
        """Marca el tour como destacado"""
        self.destacado = True
        return self
    
    def unmark_as_featured(self):
        """Quita el tour de destacados"""
        self.destacado = False
        return self
    
    # ========== REPRESENTACIÓN ==========
    def __repr__(self):
        return f'<Tour {self.codigo}: {self.nombre}>'
    
    def __str__(self):
        return f'{self.nombre} ({self.codigo})'


# Modelo para imágenes de tours (opcional)
class TourImage(db.Model):
    """Imágenes adicionales para tours"""
    __tablename__ = 'tour_images'
    
    id = db.Column(db.Integer, primary_key=True)
    tour_id = db.Column(db.Integer, db.ForeignKey('tours.id', ondelete='CASCADE'), nullable=False)
    image_url = db.Column(db.String(500), nullable=False)
    alt_text = db.Column(db.String(200))
    orden = db.Column(db.Integer, default=0)
    fecha_creacion = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relación
    tour = db.relationship('Tour', backref=db.backref('imagenes', lazy='dynamic', cascade='all, delete-orphan'))
    
    def to_dict(self):
        return {
            'id': self.id,
            'tour_id': self.tour_id,
            'image_url': self.image_url,
            'alt_text': self.alt_text,
            'orden': self.orden,
            'fecha_creacion': self.fecha_creacion.isoformat() if self.fecha_creacion else None
        }


# Función para crear tours demo
def create_demo_tours():
    """Crea tours de demostración"""
    from app import app
    
    with app.app_context():
        from . import db
        
        demo_tours = [
            {
                'nombre': 'Tour por los Manglares',
                'descripcion_corta': 'Recorrido de 2 horas por los hermosos manglares de Caño Salao',
                'descripcion_larga': 'Descubre la belleza natural de los manglares en un recorrido guiado de 2 horas. Observa la flora y fauna única de este ecosistema.',
                'duracion_horas': 2,
                'duracion_texto': '2 horas',
                'precio_adulto': 25.00,
                'capacidad_maxima': 15,
                'categoria': 'naturaleza',
                'dificultad': 'baja',
                'edad_minima': 5,
                'imagen_principal': 'https://images.unsplash.com/photo-1559827260-dc66d52bef19',
                'destacado': True,
            },
            {
                'nombre': 'Tour Histórico Cultural',
                'descripcion_corta': 'Explora la historia y cultura de la región en un tour completo',
                'descripcion_larga': 'Conoce la rica historia y cultura de la región con visitas a sitios históricos y explicaciones de guías locales.',
                'duracion_horas': 4,
                'duracion_texto': '4 horas',
                'precio_adulto': 45.00,
                'capacidad_maxima': 12,
                'categoria': 'cultura',
                'dificultad': 'media',
                'edad_minima': 8,
                'imagen_principal': 'https://images.unsplash.com/photo-1469854523086-cc02fe5d8800',
                'destacado': True,
            },
            {
                'nombre': 'Tour Fotográfico',
                'descripcion_corta': 'Tour especial para fotógrafos con los mejores atardeceres',
                'descripcion_larga': 'Captura las mejores fotografías de los paisajes y atardeceres de Caño Salao con la guía de fotógrafos profesionales.',
                'duracion_horas': 3,
                'duracion_texto': '3 horas',
                'precio_adulto': 60.00,
                'precio_estudiante': 45.00,
                'capacidad_maxima': 8,
                'categoria': 'fotografia',
                'dificultad': 'media',
                'edad_minima': 12,
                'imagen_principal': 'https://images.unsplash.com/photo-1501555088652-021faa106b9b',
            }
        ]
        
        for tour_data in demo_tours:
            # Verificar si el tour ya existe
            existing_tour = Tour.query.filter_by(nombre=tour_data['nombre']).first()
            
            if not existing_tour:
                try:
                    tour = Tour(**tour_data)
                    db.session.add(tour)
                    db.session.commit()
                    print(f"✅ Tour demo creado: {tour_data['nombre']}")
                except Exception as e:
                    db.session.rollback()
                    print(f"⚠️ Error al crear tour demo: {e}")
            else:
                print(f"✅ Tour demo ya existe: {tour_data['nombre']}")