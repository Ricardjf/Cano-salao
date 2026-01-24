// Frontend/Scripts/auth.js - VERSIÓN CORREGIDA PARA PANEL ADMIN
console.log('🔧 === AUTH.JS CARGADO - VERSIÓN PANEL ADMIN ===');

class AuthSystem {
    constructor() {
        // Claves compatibles con panel admin
        this.tokenKey = 'cano_salao_token'; // Mantenemos por compatibilidad
        this.userKey = 'cano_salao_user';   // Mantenemos por compatibilidad
        this.adminAuthKey = 'admin_auth';   // CLAVE NUEVA para panel admin
        
        console.log('🔧 Claves de autenticación:');
        console.log('  tokenKey:', this.tokenKey);
        console.log('  userKey:', this.userKey);
        console.log('  adminAuthKey:', this.adminAuthKey);
        
        this.debugStatus();
    }

    debugStatus() {
        console.log('🔍 Estado de autenticación:');
        console.log('  Token (canosalao):', this.getToken() ? '✅ Presente' : '❌ Ausente');
        console.log('  User (canosalao):', this.getUser() ? '✅ Presente' : '❌ Ausente');
        console.log('  Admin Auth (admin_auth):', this.getAdminAuth() ? '✅ Presente' : '❌ Ausente');
        console.log('  ¿Autenticado?:', this.isAuthenticated() ? '✅ SÍ' : '❌ NO');
        console.log('  ¿Es admin?:', this.isAdmin() ? '✅ SÍ' : '❌ NO');
    }

    // ========== MÉTODOS DE OBTENCIÓN ==========
    
    // Obtiene el token legacy
    getToken() {
        const token = localStorage.getItem(this.tokenKey);
        if (!token || token === 'undefined' || token === 'null' || token === '') {
            return null;
        }
        return token;
    }

    // Obtiene usuario legacy
    getUser() {
        try {
            const userData = localStorage.getItem(this.userKey);
            if (!userData || userData === 'undefined' || userData === 'null') {
                return null;
            }
            return JSON.parse(userData);
        } catch (e) {
            console.error('❌ Error parseando user legacy:', e);
            return null;
        }
    }

    // Obtiene datos de admin (nuevo formato)
    getAdminAuth() {
        try {
            const adminData = localStorage.getItem(this.adminAuthKey);
            if (!adminData || adminData === 'undefined' || adminData === 'null') {
                return null;
            }
            return JSON.parse(adminData);
        } catch (e) {
            console.error('❌ Error parseando admin auth:', e);
            return null;
        }
    }

    // ========== MÉTODOS DE VERIFICACIÓN ==========
    
    // Verifica si está autenticado (compatibilidad total)
    isAuthenticated() {
        // Primero verifica el formato admin (nuevo)
        const adminAuth = this.getAdminAuth();
        if (adminAuth) {
            console.log('🔐 Autenticación usando admin_auth:', adminAuth.email);
            return true;
        }
        
        // Luego verifica el formato legacy
        const legacyUser = this.getUser();
        const legacyToken = this.getToken();
        if (legacyUser && legacyToken) {
            console.log('🔐 Autenticación usando formato legacy');
            return true;
        }
        
        console.log('🔐 No autenticado en ningún formato');
        return false;
    }

    // Verifica si es administrador
    isAdmin() {
        // Primero verifica formato admin
        const adminAuth = this.getAdminAuth();
        if (adminAuth) {
            const isAdmin = adminAuth.rol === 'admin';
            console.log('👑 Verificación admin (formato admin_auth):', isAdmin ? '✅ SÍ' : '❌ NO');
            return isAdmin;
        }
        
        // Luego verifica formato legacy
        const legacyUser = this.getUser();
        if (legacyUser) {
            const isAdmin = legacyUser.rol === 'admin';
            console.log('👑 Verificación admin (formato legacy):', isAdmin ? '✅ SÍ' : '❌ NO');
            return isAdmin;
        }
        
        console.log('👑 No es admin (sin datos)');
        return false;
    }

    // ========== MÉTODOS DE SESIÓN ==========
    
    // Obtiene usuario actual (compatibilidad total)
    getCurrentUser() {
        // Priorizar formato admin
        const adminAuth = this.getAdminAuth();
        if (adminAuth) {
            console.log('👤 Usuario actual (formato admin):', adminAuth);
            return adminAuth;
        }
        
        // Fallback a formato legacy
        const legacyUser = this.getUser();
        if (legacyUser) {
            console.log('👤 Usuario actual (formato legacy):', legacyUser);
            return legacyUser;
        }
        
        return null;
    }

    // Login (para mantener compatibilidad)
    async login(email, password) {
        console.log('⚠️  login() llamado - Usando autenticación local');
        
        // Aquí normalmente se conectaría al backend
        // Por ahora simulamos login local
        const users = JSON.parse(localStorage.getItem('cano_salao_users') || '[]');
        const user = users.find(u => u.email === email.toLowerCase());
        
        if (!user) {
            return { success: false, error: 'Usuario no encontrado' };
        }
        
        // Verificar contraseña (en base64)
        const encryptedPassword = btoa(password);
        if (user.password !== encryptedPassword) {
            return { success: false, error: 'Contraseña incorrecta' };
        }
        
        // Crear sesión en formato admin
        const authData = {
            id: user.id,
            nombre: user.nombre,
            email: user.email,
            rol: user.rol || 'user',
            activo: true,
            fecha_creacion: user.fecha_registro || new Date().toISOString()
        };
        
        // Guardar en ambos formatos para compatibilidad
        localStorage.setItem(this.adminAuthKey, JSON.stringify(authData));
        localStorage.setItem(this.userKey, JSON.stringify(authData)); // Compatibilidad
        localStorage.setItem(this.tokenKey, 'simulated_token_' + Date.now()); // Compatibilidad
        
        console.log('✅ Login exitoso (simulado)');
        console.log('  Datos guardados en:', this.adminAuthKey);
        
        // Disparar evento
        const event = new CustomEvent('authLogin', { 
            detail: { user: authData } 
        });
        window.dispatchEvent(event);
        
        return { 
            success: true, 
            user: authData 
        };
    }

    // Logout (limpia todas las sesiones)
    logout() {
        console.log('🚪 LOGOUT ejecutando...');
        
        // Eliminar todas las claves relacionadas con autenticación
        localStorage.removeItem(this.tokenKey);
        localStorage.removeItem(this.userKey);
        localStorage.removeItem(this.adminAuthKey);
        
        // También limpiar otras posibles claves
        localStorage.removeItem('user_session');
        localStorage.removeItem('admin_session_start');
        
        console.log('✅ Todas las sesiones eliminadas');
        
        // Disparar evento
        window.dispatchEvent(new CustomEvent('authLogout'));
        
        // Redirigir a login
        setTimeout(() => {
            console.log('🔄 Redirigiendo a login...');
            window.location.href = 'Pages/login.html';
        }, 500);
    }

    // Método auxiliar para migrar datos legacy a nuevo formato
    migrateToNewFormat() {
        const legacyUser = this.getUser();
        if (legacyUser && !this.getAdminAuth()) {
            console.log('🔄 Migrando datos legacy a nuevo formato...');
            
            const authData = {
                id: legacyUser.id || Date.now(),
                nombre: legacyUser.nombre || legacyUser.name || 'Usuario',
                email: legacyUser.email,
                rol: legacyUser.rol || 'user',
                activo: true,
                fecha_creacion: legacyUser.fecha_registro || new Date().toISOString()
            };
            
            localStorage.setItem(this.adminAuthKey, JSON.stringify(authData));
            console.log('✅ Migración completada');
        }
    }

    // Validar y corregir sesiones
    validateSession() {
        console.log('🔍 Validando sesión...');
        
        const adminAuth = this.getAdminAuth();
        const legacyUser = this.getUser();
        
        // Si hay datos inconsistentes, sincronizar
        if (adminAuth && !legacyUser) {
            // Copiar admin auth a formato legacy
            localStorage.setItem(this.userKey, JSON.stringify(adminAuth));
            console.log('🔄 Sincronizado: admin_auth → user');
        } else if (!adminAuth && legacyUser) {
            // Migrar legacy a admin
            this.migrateToNewFormat();
        }
        
        return this.isAuthenticated();
    }
}

// ========== INSTANCIA GLOBAL ==========
const authSystem = new AuthSystem();
window.authSystem = authSystem;

// ========== FUNCIONES AUXILIARES GLOBALES ==========
function updateAuthUI() {
    console.log('🎨 Actualizando UI de autenticación...');
    
    const authMenu = document.getElementById('auth-menu');
    const loginMenu = document.getElementById('login-menu');
    const userAvatar = document.getElementById('user-avatar');
    const userName = document.getElementById('user-name');
    const adminLink = document.getElementById('admin-link');

    if (authSystem.isAuthenticated()) {
        const user = authSystem.getCurrentUser();
        console.log('👤 Usuario encontrado para UI:', user);
        
        // Mostrar menú de usuario
        if (authMenu) {
            authMenu.style.display = 'block';
            authMenu.style.opacity = '1';
            console.log('  ✅ auth-menu: MOSTRADO');
        }
        if (loginMenu) {
            loginMenu.style.display = 'none';
            console.log('  ✅ login-menu: OCULTO');
        }
        
        // Actualizar avatar y nombre
        if (userAvatar && user) {
            userAvatar.textContent = user.nombre ? user.nombre.charAt(0).toUpperCase() : 'U';
            console.log('  👤 Avatar actualizado:', userAvatar.textContent);
        }
        if (userName && user) {
            userName.textContent = user.nombre || user.name || 'Usuario';
            console.log('  👤 Nombre actualizado:', userName.textContent);
        }
        
        // Mostrar enlace admin si corresponde
        if (adminLink) {
            if (authSystem.isAdmin()) {
                adminLink.style.display = 'block';
                adminLink.href = 'Pages/admin.html'; // Ruta corregida
                console.log('  👑 Admin link: VISIBLE');
            } else {
                adminLink.style.display = 'none';
                console.log('  👑 Admin link: OCULTO (no es admin)');
            }
        }
    } else {
        console.log('🔓 Usuario NO autenticado');
        
        // Mostrar menú de login
        if (authMenu) {
            authMenu.style.display = 'none';
            console.log('  ❌ auth-menu: OCULTO');
        }
        if (loginMenu) {
            loginMenu.style.display = 'block';
            loginMenu.style.opacity = '1';
            console.log('  ✅ login-menu: MOSTRADO');
        }
        
        // Limpiar datos de usuario si existen
        if (userAvatar) userAvatar.textContent = '';
        if (userName) userName.textContent = '';
        if (adminLink) adminLink.style.display = 'none';
    }
}

// ========== PROTECCIÓN DE RUTAS ==========
function protectAdminRoute() {
    console.log('🛡️  Verificando acceso a ruta admin...');
    
    if (!authSystem.isAuthenticated()) {
        console.log('❌ No autenticado - Redirigiendo a login');
        window.location.href = 'login.html';
        return false;
    }
    
    if (!authSystem.isAdmin()) {
        console.log('❌ No es admin - Redirigiendo a inicio');
        alert('Acceso denegado. Se requieren permisos de administrador.');
        window.location.href = '../index.html';
        return false;
    }
    
    console.log('✅ Acceso autorizado');
    return true;
}

function protectUserRoute() {
    console.log('🛡️  Verificando acceso a ruta protegida...');
    
    if (!authSystem.isAuthenticated()) {
        console.log('❌ No autenticado - Redirigiendo a login');
        window.location.href = 'login.html';
        return false;
    }
    
    console.log('✅ Acceso autorizado');
    return true;
}

// ========== INICIALIZACIÓN ==========
document.addEventListener('DOMContentLoaded', function() {
    console.log('🚀 DOM cargado - Inicializando sistema de autenticación...');
    
    // 1. Validar y corregir sesión si es necesario
    authSystem.validateSession();
    
    // 2. Actualizar UI inicial
    updateAuthUI();
    
    // 3. Configurar menú de usuario
    const userMenuToggle = document.getElementById('user-menu-toggle');
    const userDropdown = document.getElementById('user-dropdown');
    const logoutBtn = document.getElementById('logout-btn');

    if (userMenuToggle && userDropdown) {
        userMenuToggle.addEventListener('click', function(e) {
            e.stopPropagation();
            console.log('📋 Menú de usuario clickeado');
            userDropdown.classList.toggle('show');
        });

        document.addEventListener('click', function(e) {
            if (!userMenuToggle.contains(e.target) && !userDropdown.contains(e.target)) {
                userDropdown.classList.remove('show');
            }
        });
    }

    if (logoutBtn) {
        logoutBtn.addEventListener('click', function(e) {
            e.preventDefault();
            console.log('🚪 Botón logout clickeado');
            if (confirm('¿Estás seguro de cerrar sesión?')) {
                authSystem.logout();
            }
        });
    }
    
    // 4. Escuchar eventos de autenticación
    window.addEventListener('authLogin', function(e) {
        console.log('🎉 EVENTO authLogin recibido!');
        console.log('  Usuario:', e.detail?.user);
        
        // Actualizar UI
        updateAuthUI();
        
        // Redirigir si estamos en login page
        if (window.location.pathname.includes('login.html')) {
            console.log('🔄 Redirigiendo desde login page...');
            setTimeout(() => {
                const user = e.detail?.user;
                if (user && user.rol === 'admin') {
                    window.location.href = 'admin.html';
                } else {
                    window.location.href = '../index.html';
                }
            }, 1000);
        }
    });
    
    window.addEventListener('authLogout', function() {
        console.log('👋 EVENTO authLogout recibido!');
        updateAuthUI();
    });
    
    // 5. Proteger rutas si es necesario
    if (window.location.pathname.includes('admin.html')) {
        protectAdminRoute();
    }
    
    console.log('✅ Sistema de autenticación inicializado correctamente');
    
    // Log final de estado
    setTimeout(() => {
        authSystem.debugStatus();
    }, 1000);
});

// Exportar para uso global
window.auth = {
    system: authSystem,
    updateUI: updateAuthUI,
    protectAdmin: protectAdminRoute,
    protectUser: protectUserRoute
};

console.log('🔧 === AUTH.JS LISTO - COMPATIBLE CON PANEL ADMIN ===');