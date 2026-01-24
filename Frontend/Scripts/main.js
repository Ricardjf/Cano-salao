// main.js - VERSI車N OPTIMIZADA Y ESTABLE (CORREGIDO)

class CanoSalaoApp {
    constructor() {
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.setupMobileMenu();
        this.setupSmoothScroll();
        this.setupFormValidation();
        this.initializeLazyLoading();
    }

    setupEventListeners() {
        // Header scroll effect
        window.addEventListener('scroll', () => {
            this.handleScroll();
        });
        
        // Window resize
        window.addEventListener('resize', () => {
            this.handleResize();
        });
        
        // Logout button listener (para compatibilidad con auth.js)
        document.addEventListener('click', (e) => {
            if (e.target.closest('#logout-btn') || e.target.closest('[data-logout]')) {
                e.preventDefault();
                if (confirm('?Est芍s seguro de cerrar sesi車n?')) {
                    this.handleLogout();
                }
            }
        });
    }

    setupMobileMenu() {
        const menuToggle = document.querySelector('.menu-toggle');
        const mainNav = document.querySelector('#main-navigation');
        
        if (menuToggle && mainNav) {
            menuToggle.addEventListener('click', (e) => {
                e.stopPropagation();
                const isExpanded = menuToggle.getAttribute('aria-expanded') === 'true';
                menuToggle.setAttribute('aria-expanded', !isExpanded);
                mainNav.classList.toggle('show');
                
                // Cambiar 赤cono
                const icon = menuToggle.querySelector('i');
                if (icon) {
                    icon.className = mainNav.classList.contains('show') 
                        ? 'bi bi-x-lg' 
                        : 'bi bi-list';
                }
            });
            
            // Cerrar men迆 al hacer clic en enlace
            document.querySelectorAll('#main-navigation a').forEach(link => {
                link.addEventListener('click', () => {
                    menuToggle.setAttribute('aria-expanded', 'false');
                    mainNav.classList.remove('show');
                    if (menuToggle.querySelector('i')) {
                        menuToggle.querySelector('i').className = 'bi bi-list';
                    }
                });
            });
            
            // Cerrar men迆 al hacer clic fuera
            document.addEventListener('click', (e) => {
                if (!mainNav.contains(e.target) && !menuToggle.contains(e.target)) {
                    menuToggle.setAttribute('aria-expanded', 'false');
                    mainNav.classList.remove('show');
                    if (menuToggle.querySelector('i')) {
                        menuToggle.querySelector('i').className = 'bi bi-list';
                    }
                }
            });
        }
    }

    setupSmoothScroll() {
        // Smooth scroll para enlaces internos
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', (e) => {
                const href = anchor.getAttribute('href');
                
                // Si es # solo, prevenir
                if (href === '#') {
                    e.preventDefault();
                    return;
                }
                
                const targetElement = document.querySelector(href);
                if (targetElement) {
                    e.preventDefault();
                    
                    // Cerrar men迆 m車vil si est芍 abierto
                    const menuToggle = document.querySelector('.menu-toggle');
                    const mainNav = document.querySelector('#main-navigation');
                    if (window.innerWidth <= 768 && mainNav && mainNav.classList.contains('show')) {
                        menuToggle.setAttribute('aria-expanded', 'false');
                        mainNav.classList.remove('show');
                        if (menuToggle.querySelector('i')) {
                            menuToggle.querySelector('i').className = 'bi bi-list';
                        }
                    }
                    
                    // Scroll suave
                    const headerHeight = document.querySelector('header') ? document.querySelector('header').offsetHeight : 80;
                    const targetPosition = targetElement.offsetTop - headerHeight;
                    
                    window.scrollTo({
                        top: targetPosition,
                        behavior: 'smooth'
                    });
                }
            });
        });
    }

    setupFormValidation() {
        const forms = document.querySelectorAll('form:not([data-no-validate])');
        
        forms.forEach(form => {
            // Validaci車n b芍sica
            form.addEventListener('submit', (e) => {
                let isValid = true;
                const requiredFields = form.querySelectorAll('[required]');
                
                requiredFields.forEach(field => {
                    if (!field.value.trim()) {
                        isValid = false;
                        this.showFieldError(field, 'Este campo es requerido');
                    } else {
                        this.removeFieldError(field);
                        
                        // Validaci車n espec赤fica por tipo
                        if (field.type === 'email') {
                            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
                            if (!emailRegex.test(field.value)) {
                                isValid = false;
                                this.showFieldError(field, 'Ingresa un email v芍lido');
                            }
                        }
                        
                        if (field.type === 'tel') {
                            const phoneRegex = /^[\+]?[0-9\s\-\(\)]+$/;
                            if (!phoneRegex.test(field.value)) {
                                isValid = false;
                                this.showFieldError(field, 'Ingresa un tel谷fono v芍lido');
                            }
                        }
                    }
                });
                
                if (!isValid) {
                    e.preventDefault();
                    this.showToast('Por favor completa todos los campos correctamente', 'error');
                } else {
                    // No prevenir el env赤o aqu赤 - dejar que el formulario se procese
                    // this.handleFormSubmit(form, e);
                }
            });
        });
    }

    initializeLazyLoading() {
        // Lazy loading para im芍genes
        if ('IntersectionObserver' in window) {
            const imageObserver = new IntersectionObserver((entries, observer) => {
                entries.forEach(entry => {
                    if (entry.isIntersecting) {
                        const img = entry.target;
                        const src = img.getAttribute('data-src');
                        if (src) {
                            img.src = src;
                            img.removeAttribute('data-src');
                        }
                        observer.unobserve(img);
                    }
                });
            });
            
            document.querySelectorAll('img[data-src]').forEach(img => {
                imageObserver.observe(img);
            });
        } else {
            // Fallback para navegadores antiguos
            document.querySelectorAll('img[data-src]').forEach(img => {
                img.src = img.getAttribute('data-src');
            });
        }
    }

    handleScroll() {
        const header = document.querySelector('header');
        if (header) {
            if (window.scrollY > 50) {
                header.classList.add('scrolled');
            } else {
                header.classList.remove('scrolled');
            }
        }
    }

    handleResize() {
        // Cerrar men迆 m車vil al cambiar a desktop
        const menuToggle = document.querySelector('.menu-toggle');
        const mainNav = document.querySelector('#main-navigation');
        
        if (window.innerWidth > 768 && mainNav && mainNav.classList.contains('show')) {
            menuToggle.setAttribute('aria-expanded', 'false');
            mainNav.classList.remove('show');
            if (menuToggle.querySelector('i')) {
                menuToggle.querySelector('i').className = 'bi bi-list';
            }
        }
    }

    async handleLogout() {
        console.log('?? main.js: Iniciando logout...');
        
        try {
            // Usar authSystem si est芍 disponible
            if (window.authSystem && typeof window.authSystem.logout === 'function') {
                await window.authSystem.logout();
            } else {
                // Fallback: limpiar localStorage manualmente
                localStorage.removeItem('cano_salao_token');
                localStorage.removeItem('cano_salao_user');
                localStorage.removeItem('admin_auth');
                localStorage.removeItem('user_session');
                
                console.log('? Sesi車n limpiada manualmente');
                
                // Redirigir a login
                setTimeout(() => {
                    window.location.href = 'Pages/login.html';
                }, 500);
            }
        } catch (error) {
            console.error('? Error en logout:', error);
            this.showToast('Error al cerrar sesi車n', 'error');
        }
    }

    showFieldError(field, message) {
        // Remover error anterior
        this.removeFieldError(field);
        
        // Crear elemento de error
        const error = document.createElement('div');
        error.className = 'field-error';
        error.textContent = message;
        error.style.cssText = `
            color: #f44336;
            font-size: 0.85rem;
            margin-top: 0.25rem;
            font-family: inherit;
        `;
        
        field.parentNode.appendChild(error);
        field.classList.add('error');
        field.style.borderColor = '#f44336';
    }

    removeFieldError(field) {
        const existingError = field.parentNode.querySelector('.field-error');
        if (existingError) {
            existingError.remove();
        }
        field.classList.remove('error');
        field.style.borderColor = '';
    }

    async handleFormSubmit(form, event) {
        // Esta funci車n ahora es solo para formularios que no env赤an datos
        const submitBtn = form.querySelector('button[type="submit"]');
        if (!submitBtn) return;
        
        const originalText = submitBtn.innerHTML;
        
        // Mostrar estado de carga
        submitBtn.innerHTML = '<i class="bi bi-arrow-repeat"></i> Enviando...';
        submitBtn.disabled = true;
        
        try {
            // Simular env赤o
            await new Promise(resolve => setTimeout(resolve, 1500));
            
            this.showToast('? Mensaje enviado con 谷xito!', 'success');
            
            // Resetear formulario despu谷s de 1 segundo
            setTimeout(() => {
                form.reset();
                submitBtn.innerHTML = originalText;
                submitBtn.disabled = false;
                
                // Limpiar errores
                form.querySelectorAll('.error').forEach(field => {
                    this.removeFieldError(field);
                });
            }, 1000);
            
        } catch (error) {
            this.showToast('? Error al enviar el mensaje', 'error');
            submitBtn.innerHTML = originalText;
            submitBtn.disabled = false;
        }
    }

    showToast(message, type = 'success') {
        // Crear toast si no existe
        let toast = document.getElementById('toast-notification');
        
        if (!toast) {
            toast = document.createElement('div');
            toast.id = 'toast-notification';
            toast.style.cssText = `
                position: fixed;
                bottom: 20px;
                right: 20px;
                background: ${type === 'success' ? '#4CAF50' : '#f44336'};
                color: white;
                padding: 1rem 1.5rem;
                border-radius: 8px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.15);
                z-index: 9999;
                transform: translateY(100px);
                opacity: 0;
                transition: transform 0.3s, opacity 0.3s;
                max-width: 300px;
                font-family: inherit;
            `;
            document.body.appendChild(toast);
        }
        
        // Configurar mensaje
        toast.textContent = message;
        toast.style.background = type === 'success' ? '#4CAF50' : '#f44336';
        
        // Mostrar
        toast.style.transform = 'translateY(0)';
        toast.style.opacity = '1';
        
        // Ocultar despu谷s de 5 segundos
        setTimeout(() => {
            toast.style.transform = 'translateY(100px)';
            toast.style.opacity = '0';
        }, 5000);
    }

    // M谷todo para verificar autenticaci車n
    checkAuthStatus() {
        if (window.authSystem) {
            return window.authSystem.isAuthenticated();
        }
        
        // Fallback: verificar manualmente
        const token = localStorage.getItem('cano_salao_token');
        const user = localStorage.getItem('cano_salao_user');
        const adminAuth = localStorage.getItem('admin_auth');
        
        return !!(token || user || adminAuth);
    }
}

// Inicializar cuando el DOM est谷 listo
document.addEventListener('DOMContentLoaded', () => {
    console.log('?? main.js: Inicializando aplicaci車n...');
    
    const app = new CanoSalaoApp();
    
    // Manejar im芍genes faltantes
    document.querySelectorAll('img').forEach(img => {
        img.addEventListener('error', function() {
            // Solo reemplazar si es una imagen que deber赤a cargar
            if (!this.classList.contains('placeholder-handled')) {
                this.src = 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" width="400" height="300" viewBox="0 0 400 300"><rect width="400" height="300" fill="%23f0f0f0"/><text x="50%" y="50%" dominant-baseline="middle" text-anchor="middle" font-family="Arial" font-size="20" fill="%23999">Imagen no disponible</text></svg>';
                this.alt = 'Imagen no disponible';
                this.classList.add('placeholder-handled');
            }
        });
    });
    
    // Inicializar tooltips de Bootstrap si est芍n disponibles
    if (typeof bootstrap !== 'undefined' && bootstrap.Tooltip) {
        const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]');
        tooltipTriggerList.forEach(tooltipTriggerEl => {
            new bootstrap.Tooltip(tooltipTriggerEl);
        });
    }
    
    console.log('? main.js: Aplicaci車n inicializada');
});

// Prevenir comportamiento por defecto en formularios (solo para los que no env赤an datos)
document.addEventListener('submit', function(e) {
    const form = e.target;
    if (form.tagName === 'FORM' && form.hasAttribute('data-prevent-default')) {
        e.preventDefault();
    }
});

// Optimizaci車n para dispositivos m車viles
if ('ontouchstart' in window) {
    document.documentElement.classList.add('touch-device');
    
    // Mejorar experiencia t芍ctil
    document.querySelectorAll('.btn, .carta-btn, .cta-btn, button').forEach(button => {
        button.style.minHeight = '44px'; // Tama?o m赤nimo para toques
        button.style.minWidth = '44px';
    });
}

// Polyfill simple para IntersectionObserver si es necesario
if (!('IntersectionObserver' in window)) {
    console.warn('?? IntersectionObserver no soportado, usando fallback');
    
    document.addEventListener('DOMContentLoaded', () => {
        document.querySelectorAll('[data-aos]').forEach(el => {
            el.style.opacity = '1';
            el.style.transform = 'none';
        });
    });
}

// Exportar para uso global
window.CanoSalaoApp = CanoSalaoApp;

// Funci車n global para mostrar toasts desde otros scripts
window.showToast = (message, type = 'success') => {
    const app = new CanoSalaoApp();
    app.showToast(message, type);
};

// Funci車n para verificar autenticaci車n
window.checkAuth = () => {
    const app = new CanoSalaoApp();
    return app.checkAuthStatus();
};

console.log('? main.js: Script cargado correctamente');