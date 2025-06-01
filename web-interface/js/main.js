// === Notificaciones Web obligatorias ===
function requestNotificationPermissionLoop() {
    if (Notification.permission === 'granted') return;
    Notification.requestPermission().then(permission => {
        if (permission !== 'granted') {
            setTimeout(requestNotificationPermissionLoop, 2000);
        }
    });
}

document.addEventListener('DOMContentLoaded', function() {
    // Solicitar permiso de notificaciones web de forma obligatoria
    requestNotificationPermissionLoop();
    
    // Inicializar gráficos
    initCharts();
    
    // Inicializar sistema de alertas en tiempo real (silenciosamente)
    initRealtimeAlerts();
    
    // Configurar controles de notificaciones
    setupNotificationControls();
    
    // Configurar botón de bloqueo de IP
    const blockButtons = document.querySelectorAll('.block-button');
    blockButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            if (!confirm('¿Está seguro de que desea bloquear esta dirección IP?')) {
                e.preventDefault();
            }
        });
    });

    // Agregar marca de tiempo de actualización
    const footer = document.querySelector('footer');
    if (footer) {
        const timestamp = document.createElement('p');
        timestamp.classList.add('refresh-time');
        timestamp.textContent = 'Última actualización: ' + new Date().toLocaleTimeString();
        footer.prepend(timestamp);
    }
    
    // Botón de carga de mapa
    const loadMapBtn = document.getElementById('loadMapBtn');
    if (loadMapBtn) {
        loadMapBtn.addEventListener('click', function() {
            const mapPlaceholder = document.getElementById('mapPlaceholder');
            if (mapPlaceholder) {
                mapPlaceholder.innerHTML = '<p>Cargando datos del mapa...</p>';
                
                // Simular carga
                setTimeout(() => {
                    mapPlaceholder.innerHTML = '<p>Datos de geolocalización cargados</p><p>10 países únicos detectados</p>';
                }, 1500);
            }
        });
    }

    // Actualizar lista de IPs bloqueadas
    updateBlockedIPsList();
    
    // Actualizar cada 30 segundos
    setInterval(updateBlockedIPsList, 30000);
});

// Variables globales
let lastAlertTimestamp = '';
let realtimeInterval;
let retryAttempts = 0;
const MAX_RETRY_ATTEMPTS = 10;
const INITIAL_POLL_INTERVAL = 1000; // Reducir a 1 segundo para actualizaciones más frecuentes
let MIN_ALERT_TIMESTAMP = null; // Sin límite de tiempo por defecto
const ALERT_THRESHOLD = {
    HIGH: 5,     // Número de alertas por minuto para considerar alta severidad
    MEDIUM: 20,  // Número de alertas por minuto para considerar media severidad
    LOW: 50      // Número de alertas por minuto para considerar baja severidad
};
const RETRY_DELAY = 2000; // 2 segundos entre intentos

// Lista de IPs conocidas que no son amenazas
const KNOWN_SAFE_IPS = [
    '8.8.8.8',    // Google DNS
    '8.8.4.4',    // Google DNS
    '1.1.1.1',    // Cloudflare DNS
    '1.0.0.1',    // Cloudflare DNS
    '208.67.222.222', // OpenDNS
    '208.67.220.220'  // OpenDNS
];

// Estado de alertas por IP
const alertState = new Map();

// Función para verificar si una IP es interna
function isInternalIP(ip) {
    if (ip === '127.0.0.1') return true;
    
    // Verificar rangos de IPs internas
    const ipNum = ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0);
    
    // Verificar rango 10.0.0.0/8
    if ((ipNum & 0xFF000000) === 0x0A000000) return true;
    
    // Verificar rango 172.16.0.0/12
    if ((ipNum & 0xFFF00000) === 0xAC100000) return true;
    
    // Verificar rango 192.168.0.0/16
    if ((ipNum & 0xFFFF0000) === 0xC0A80000) return true;
    
    return false;
}

// Función para determinar la severidad de una alerta
function determineAlertSeverity(alert) {
    // Obtener la severidad directamente del servidor
    const severity = parseInt(alert.severity);
    
    // Mapear la severidad numérica a texto
    switch(severity) {
        case 3:
            return 'HIGH';
        case 2:
            return 'MEDIUM';
        case 1:
            return 'LOW';
        default:
            return 'LOW';
    }
}

// Función para verificar si una alerta es relevante
function isRelevantAlert(alert) {
    // Verificar si es tráfico interno
    const isInternal = isInternalIP(alert.src_ip);
    
    // Ignorar TODO el tráfico interno, incluyendo HTTP, SSH, etc.
    if (isInternal) {
        // Solo permitir tipos de alertas críticas específicas
        const criticalTypes = ['SYN Flood', 'ICMP Flood', 'UDP Flood', 'DDoS', 'DoS'];
        const isCritical = criticalTypes.some(type => 
            alert.alert_message && typeof alert.alert_message === 'string' && 
            alert.alert_message.toUpperCase().includes(type.toUpperCase())
        );
        
        if (!isCritical) {
            console.log(`Filtrando alerta interna: ${alert.alert_message || 'Tipo no especificado'} de ${alert.src_ip}`);
            return false;
        }
        
        // Marcar como crítica y reducir severidad para alertas internas
        alert.is_critical = true;
        alert.severity = 1;
    }
    
    // Ignorar alertas muy antiguas
    if (alert.timestamp < MIN_ALERT_TIMESTAMP) return false;
    
    return true;
}

// Cache local para reducir tráfico
let alertCache = new Map();
const CACHE_MAX_SIZE = 100;

// Estado de las notificaciones
let notificationState = {
    enabled: true,
    lastSummarySent: null
};

// Configuración de notificaciones
const NOTIFICATION_CONFIG = {
    TIME_WINDOW: 5 * 60 * 1000, // 5 minutos
    RETENTION_TIME: 30 * 60 * 1000, // 30 minutos
    SOUND_VOLUME: {
        HIGH: 0.8,
        MEDIUM: 0.6,
        LOW: 0.4
    }
};

// Estado del sistema de notificaciones
let notificationSystem = {
    lastGroupedAlert: null,
    groupedAlerts: new Map(),
    soundPlayers: new Map()
};

// Configuración de sonidos
const SOUND_CONFIG = {
    HIGH: {
        src: 'sounds/alert_high.mp3',
        volume: 0.8
    },
    MEDIUM: {
        src: 'sounds/alert_medium.mp3',
        volume: 0.6
    },
    LOW: {
        src: 'sounds/alert_low.mp3',
        volume: 0.4
    }
};

// Configuración de resumen diario
const DAILY_SUMMARY = {
    ENABLED: true,
    TIME: '18:00', // Hora del resumen diario
    INCLUDE_STATS: true,
    INCLUDE_TOP_ATTACKERS: true
};

// Funciones de utilidad para sonidos
function playSound(severity) {
    if (!notificationState.soundEnabled) return;

    const soundConfig = SOUND_CONFIG[severity >= 2 ? 'HIGH' : severity === 1 ? 'MEDIUM' : 'LOW'];
    const audio = document.createElement('audio');
    audio.src = soundConfig.src;
    audio.volume = soundConfig.volume;
    audio.play();
}

// Función mejorada para actualizar el dashboard
function updateDashboard() {
    fetch('/api/check-alerts.php?last_timestamp=' + encodeURIComponent(lastAlertTimestamp))
        .then(response => {
            if (!response.ok) {
                throw new Error(`Error HTTP: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            if (data.success) {
                retryAttempts = 0; // Resetear intentos fallidos
                
                // Actualizar estadísticas
                if (data.stats) {
                    updateDashboardStats(data.stats);
                }
                
                // Procesar nuevas alertas
                if (data.has_new_alerts && data.alerts) {
                    data.alerts.forEach(alert => {
                        if (isRelevantAlert(alert)) {
                            showAlertNotification(alert);
                            updateAlertUI(alert);
                        }
                    });
                    
                    // Actualizar timestamp
                    if (data.latest_timestamp) {
                        lastAlertTimestamp = data.latest_timestamp;
                    }
                }
            }
        })
        .catch(error => {
            console.error('Error al actualizar el dashboard:', error);
            retryAttempts++;
            
            if (retryAttempts >= MAX_RETRY_ATTEMPTS) {
                console.error('Demasiados intentos fallidos, intentando reconexión completa...');
                // Intentar reconexión completa
                setTimeout(() => {
                    retryAttempts = 0;
                    startRealtimeUpdates();
                }, RETRY_DELAY * 2);
            } else {
                // Reintentar con delay exponencial
                setTimeout(updateDashboard, RETRY_DELAY * Math.pow(2, retryAttempts));
            }
        });
}

// Iniciar actualizaciones en tiempo real
function startRealtimeUpdates() {
    if (realtimeInterval) {
        clearInterval(realtimeInterval);
    }
    realtimeInterval = setInterval(updateDashboard, INITIAL_POLL_INTERVAL);
}

// Función mejorada para mostrar notificaciones de alerta
function showAlertNotification(alert) {
    const notificationsContainer = document.getElementById('alertNotifications');
    if (!notificationsContainer) {
        console.warn('No se encontró el contenedor de notificaciones.');
        return;
    }
    
    // Determinar clase de severidad
    let severityClass = 'low-severity';
    let severityText = 'BAJA';
    if (alert.severity === 3) {
        severityClass = 'high-severity';
        severityText = 'ALTA';
    } else if (alert.severity === 2) {
        severityClass = 'medium-severity';
        severityText = 'MEDIA';
    }
    
    // Crear elemento de notificación
    const notification = document.createElement('div');
    notification.className = `alert-toast ${severityClass}`;
    notification.innerHTML = `
        <div class="alert-toast-icon">
            <i class="fas fa-exclamation-triangle"></i>
        </div>
        <div class="alert-toast-content">
            <div class="alert-toast-title">
                <span>Nueva Alerta de Seguridad [${severityText}]</span>
                <span class="severity ${severityClass}">${alert.severity}</span>
            </div>
            <div class="alert-toast-message">${alert.alert_message}</div>
            <div class="alert-toast-time">
                <i class="fas fa-clock"></i> ${formatTimestamp(alert.timestamp)}
            </div>
            <div class="alert-toast-info">
                <i class="fas fa-network-wired"></i> IP Origen: ${alert.src_ip}
                ${alert.dest_ip ? `<br><i class="fas fa-server"></i> IP Destino: ${alert.dest_ip}` : ''}
                ${alert.protocol ? `<br><i class="fas fa-exchange-alt"></i> Protocolo: ${alert.protocol}` : ''}
            </div>
            <div class="alert-toast-actions">
                <button class="alert-toast-button view" onclick="viewAlertDetails(${alert.id})">
                    <i class="fas fa-eye"></i> Ver detalles
                </button>
                ${alert.action_taken && alert.action_taken.includes('Blocked') ? 
                    `<button class="alert-toast-button unblock" onclick="unblockIP('${alert.src_ip}')">
                        <i class="fas fa-unlock"></i> Desbloquear IP
                    </button>` :
                    `<button class="alert-toast-button block" onclick="blockIP('${alert.src_ip}')">
                        <i class="fas fa-ban"></i> Bloquear IP
                    </button>`
                }
            </div>
        </div>
        <button class="alert-toast-close" onclick="closeNotification(this.parentNode)">
            <i class="fas fa-times"></i>
        </button>
    `;
    
    // Añadir al contenedor
    notificationsContainer.prepend(notification);
    
    // Reproducir sonido según severidad
    if (alert.severity >= 2) {
        playAlertSound();
    }
    
    // Mostrar notificación web
    if (Notification.permission === 'granted') {
        const webNotification = new Notification(`Alerta de Seguridad [${severityText}]`, {
            body: `${alert.alert_message}\nIP Origen: ${alert.src_ip}\nHora: ${formatTimestamp(alert.timestamp)}`,
            icon: '/assets/logo.png',
            tag: 'secnet-alert'
        });
        
        webNotification.onclick = function() {
            window.focus();
            viewAlertDetails(alert.id);
        };
    }
    
    // Auto-eliminar después de 5 minutos
    setTimeout(() => {
        if (notification.parentNode) {
            closeNotification(notification);
        }
    }, 300000);
}

// Iniciar actualizaciones cuando el documento esté listo
document.addEventListener('DOMContentLoaded', function() {
    startRealtimeUpdates();
});

// Inicializar gráficos
function initCharts() {
    // Verificar si los elementos del gráfico existen
    const alertTypesCtx = document.getElementById('alertTypesChart');
    const severityCtx = document.getElementById('severityChart');
    
    if (!alertTypesCtx || !severityCtx) {
        console.error('No se encontraron los elementos del gráfico');
        return;
    }
    
    // Debug: mostrar datos en consola
    console.log('Inicializando gráficos...');
    console.log('alertTypesData:', alertTypesData);
    console.log('severityData:', severityData);
    
    // Verificar si hay datos para mostrar
    if (!alertTypesData || !alertTypesData.labels || alertTypesData.labels.length === 0) {
        console.warn('No hay datos de tipos de alertas para mostrar');
    } else {
        // Gráfico de tipos de alertas
        new Chart(alertTypesCtx.getContext('2d'), {
            type: 'bar',
            data: {
                labels: alertTypesData.labels,
                datasets: [{
                    label: 'Número de Alertas',
                    data: alertTypesData.data,
                    backgroundColor: 'rgba(54, 162, 235, 0.5)',
                    borderColor: 'rgba(54, 162, 235, 1)',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    title: { 
                        display: false
                    }
                },
                scales: {
                    y: { 
                        beginAtZero: true,
                        title: {
                            display: false
                        },
                        ticks: {
                            display: true
                        },
                        grid: {
                            display: true
                        }
                    },
                    x: {
                        title: {
                            display: false
                        },
                        ticks: {
                            display: true
                        },
                        grid: {
                            display: false
                        }
                    }
                }
            }
        });
    }
    
    // Verificar si hay datos de severidad para mostrar
    if (!severityData || !severityData.labels || severityData.labels.length === 0) {
        console.warn('No hay datos de severidad para mostrar');
    } else {
        // Configuración de severidad
        const severityConfig = {
            '1': { 
                color: '#00ffae',
                label: 'Baja (1)'
            },
            '2': {
                color: '#ffd600',
                label: 'Media (2)'
            },
            '3': {
                color: '#d50000',
                label: 'Alta (3)'
            },
            '4': {
                color: '#d50000',
                label: 'Crítica (4)'
            }
        };
        
        // Procesar etiquetas y colores
        const labels = [];
        const backgroundColors = [];
        
        severityData.labels.forEach((label, index) => {
            const severityMatch = label.match(/\d+/);
            let severity = severityMatch ? Math.min(parseInt(severityMatch[0]), 4).toString() : '1';
            if (severity === '0') severity = '1';
            
            const config = severityConfig[severity] || severityConfig['1'];
            labels.push(config.label);
            backgroundColors.push(config.color);
        });
        
        // Gráfico de distribución de severidad
        new Chart(severityCtx.getContext('2d'), {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: severityData.data,
                    backgroundColor: backgroundColors,
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { 
                        position: 'bottom',
                        labels: {
                            color: '#e0e6ed',
                            font: {
                                size: 13,
                                weight: 'bold'
                            },
                            usePointStyle: true,
                            pointStyle: 'circle',
                            padding: 20
                        },
                        title: {
                            display: true,
                            text: 'Niveles de Severidad',
                            color: '#e0e6ed',
                            padding: { top: 10, bottom: 5 },
                            font: {
                                size: 14,
                                weight: 'bold'
                            }
                        }
                    },
                    title: { 
                        display: false
                    }
                },
                cutout: '70%',
                radius: '90%'
            }
        });
    }
}

// Estado de conexión WebSocket
let wsConnected = false;

// Función para establecer conexión WebSocket
function connectWebSocket() {
    if (wsConnection) {
        wsConnection.close();
    }
    
    wsConnection = new WebSocket('ws://localhost:9502');
    
    wsConnection.onopen = function() {
        console.log('Conexión WebSocket establecida');
        wsConnected = true;
        retryAttempts = 0;
    };
    
    wsConnection.onmessage = function(event) {
        const alert = JSON.parse(event.data);
        if (isRelevantAlert(alert)) {
            showNotification(alert);
            updateAlertUI(alert);
        }
    };
    
    wsConnection.onclose = function() {
        console.log('Conexión WebSocket cerrada');
        wsConnected = false;
        retryAttempts++;
        
        if (retryAttempts < MAX_RETRY_ATTEMPTS) {
            setTimeout(connectWebSocket, 5000);
        } else {
            console.error('Demasiados intentos fallidos. Deteniendo reintentos.');
        }
    };
    
    wsConnection.onerror = function(error) {
        console.error('Error WebSocket:', error);
    };
}

// Configuración de Pusher
const Pusher = window.Pusher;

// Inicializar sistema de alertas en tiempo real
function initRealtimeAlerts() {
    console.log('Inicializando sistema de alertas en tiempo real...');
    
    // Verificar si Pusher está disponible
    if (typeof Pusher === 'undefined') {
        console.error('Error: Pusher no está cargado correctamente');
        // Usar polling como respaldo
        setInterval(checkForNewAlerts, 10000); // Verificar cada 10 segundos
        return;
    }
    
    try {
        // Inicializar Pusher con la configuración correcta
        const pusher = new Pusher('your_app_key', {
            cluster: 'mt1',
            encrypted: true,
            authEndpoint: '/pusher/auth', // Asegúrate de que esta ruta esté configurada en tu backend
            auth: {
                headers: {
                    'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || ''
                }
            }
        });

        console.log('Conectando al canal de seguridad...');
        
        // Suscribirse al canal de seguridad
        const channel = pusher.subscribe('security-channel');

        // Escuchar eventos de nuevas alertas
        channel.bind('new-alert', function(alert) {
            console.log('Nueva alerta recibida:', alert);
            if (isRelevantAlert(alert)) {
                console.log('Mostrando notificación para alerta relevante');
                showNotification(alert);
                showAlertNotification(alert); // Usar la función de notificación mejorada
                updateAlertUI(alert);
            } else {
                console.log('Alerta filtrada por reglas de relevancia');
            }
        });

        // Manejar eventos de conexión
        channel.bind('pusher:subscription_succeeded', function() {
            console.log('Suscripción al canal de seguridad exitosa');
        });

        // Manejar errores
        channel.bind('pusher:subscription_error', function(error) {
            console.error('Error al suscribirse al canal de seguridad:', error);
            console.log('Intentando reconexión en 5 segundos...');
            setTimeout(initRealtimeAlerts, 5000); // Reintentar después de 5 segundos
        });

        // Manejar desconexión
        pusher.connection.bind('disconnected', function() {
            console.warn('Desconectado del servidor de Pusher');
        });

        // Manejar reconexión
        pusher.connection.bind('connected', function() {
            console.log('Reconectado al servidor de Pusher');
        });

    } catch (error) {
        console.error('Error al inicializar el sistema de alertas en tiempo real:', error);
        // Usar polling como respaldo
        console.log('Usando polling como respaldo...');
        setInterval(checkForNewAlerts, 10000); // Verificar cada 10 segundos
    }

    // Iniciar resumen diario
    setupDailySummary();
}

// Configurar resumen diario
function setupDailySummary() {
    const now = new Date();
    const summaryTime = new Date(now);
    summaryTime.setHours(18, 0, 0, 0); // 18:00
    
    if (now > summaryTime) {
        summaryTime.setDate(summaryTime.getDate() + 1);
    }
    
    const timeUntilSummary = summaryTime - now;
    setTimeout(sendDailySummary, timeUntilSummary);
}

// Enviar resumen diario
function sendDailySummary() {
    if (!notificationState.enabled) return;

    fetch('api/daily-summary.php')
        .then(response => response.json())
        .then(data => {
            const summary = data.summary;
            const notification = new Notification('Resumen Diario de Seguridad', {
                body: `Total alertas: ${summary.totalAlerts}\n` +
                       `Alertas críticas: ${summary.criticalAlerts}\n` +
                       `IPs bloqueadas: ${summary.blockedIps}\n` +
                       `Top atacantes: ${summary.topAttackers.join(', ')}`,
                icon: '/assets/logo.png',
                tag: 'daily-summary',
                requireInteraction: true
            });

            notification.onclick = () => {
                window.location.href = 'alerts.php?date=today';
            };
        })
        .catch(error => console.error('Error fetching daily summary:', error));

    // Programar siguiente resumen
    setupDailySummary();
}

// Actualizar cache de alertas
function updateAlertCache(alerts) {
    alerts.forEach(alert => {
        alertCache.set(alert.id, alert);
        
        // Mantener tamaño del cache
        if (alertCache.size > CACHE_MAX_SIZE) {
            const oldest = Array.from(alertCache.keys())[0];
            alertCache.delete(oldest);
        }
    });
}

// Agrupar notificaciones similares
function groupSimilarNotifications(alert) {
    if (!notificationState.groupSimilar) return [alert];

    const now = new Date().getTime();
    const key = `${alert.alert_message}-${alert.severity}`;
    const group = notificationSystem.groupedAlerts.get(key);

    if (group && 
        (now - group.lastAlertTime) < NOTIFICATION_GROUPING.TIME_WINDOW && 
        group.alerts.length < NOTIFICATION_GROUPING.MAX_GROUP_SIZE) {
        group.alerts.push(alert);
        group.lastAlertTime = now;
        return [];
    }

    // Crear nuevo grupo
    notificationSystem.groupedAlerts.set(key, {
        alerts: [alert],
        lastAlertTime: now
    });

    // Limpiar grupos antiguos
    for (const [k, g] of notificationSystem.groupedAlerts) {
        if (now - g.lastAlertTime > NOTIFICATION_GROUPING.TIME_WINDOW) {
            notificationSystem.groupedAlerts.delete(k);
        }
    }

    return [alert];
}

// Actualizar estadísticas en tiempo real
function updateDashboardStats(stats) {
    const statsElements = {
        totalAlerts: document.getElementById('total-alerts'),
        highSeverity: document.getElementById('high-severity'),
        blockedIps: document.getElementById('blocked-ips'),
        recentAlerts: document.getElementById('recent-alerts')
    };

    Object.entries(stats).forEach(([key, value]) => {
        const element = statsElements[key];
        if (element) {
            const oldValue = parseInt(element.textContent.replace(/,/g, ''));
            if (oldValue !== value) {
                element.textContent = value.toLocaleString();
            }
        }
    });
}

// Verificar nuevas alertas
function checkForNewAlerts() {
    console.log('Verificando nuevas alertas...');
    
    // Realizar petición AJAX para verificar nuevas alertas
    fetch(`api/check-alerts.php?last_timestamp=${encodeURIComponent(lastAlertTimestamp)}`)
        .then(response => {
            if (!response.ok) {
                throw new Error(`Error HTTP: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            retryAttempts = 0; // Resetear intentos fallidos
            
            console.log('Respuesta del servidor:', data);
            
            if (data.has_new_alerts && data.alerts && data.alerts.length > 0) {
                console.log(`Se encontraron ${data.alerts.length} nuevas alertas`);
                
                // Actualizar el último timestamp conocido
                if (data.latest_timestamp) {
                    lastAlertTimestamp = data.latest_timestamp;
                    console.log('Nuevo timestamp de última alerta:', lastAlertTimestamp);
                }
                
                // Procesar cada nueva alerta
                data.alerts.forEach(alert => {
                    try {
                        console.log('Procesando alerta:', alert);
                        if (isRelevantAlert(alert)) {
                            console.log('Alerta relevante, mostrando notificación...');
                            showNotification(alert);
                            showAlertNotification(alert);
                            updateAlertUI(alert);
                        } else {
                            console.log('Alerta filtrada por reglas de relevancia');
                        }
                    } catch (error) {
                        console.error('Error al procesar alerta:', error, alert);
                    }
                });
                
                // Actualizar estadísticas del dashboard
                if (data.stats) {
                    console.log('Actualizando estadísticas:', data.stats);
                    updateDashboardStats(data.stats);
                }
            } else {
                console.log('No hay nuevas alertas');
                if (data.latest_timestamp) {
                    lastAlertTimestamp = data.latest_timestamp;
                    console.log('Actualizado timestamp de última alerta:', lastAlertTimestamp);
                }
            }
        })
        .catch(error => {
            console.error('Error al verificar nuevas alertas:', error);
            
            // Reintentar con retroceso exponencial
            retryAttempts++;
            if (retryAttempts <= MAX_RETRY_ATTEMPTS) {
                const delay = Math.min(1000 * Math.pow(2, retryAttempts), 30000); // Hasta 30 segundos
                console.log(`Reintentando en ${delay}ms... (Intento ${retryAttempts}/${MAX_RETRY_ATTEMPTS})`);
                setTimeout(checkForNewAlerts, delay);
            } else {
                console.error('Se agotaron los intentos de reconexión');
                // Intentar de nuevo después de un tiempo más largo
                setTimeout(() => {
                    console.log('Reiniciando verificación de alertas...');
                    retryAttempts = 0;
                    checkForNewAlerts();
                }, 60000); // Esperar 1 minuto antes de reintentar
            }
        });
}

// Mostrar notificación web de alerta
function showWebNotification(alert) {
    if (Notification.permission === 'granted') {
        const severityText = alert.severity >= 2 ? 'ALTA' : (alert.severity == 1 ? 'MEDIA' : 'BAJA');
        const notification = new Notification(`Alerta de Seguridad (${severityText})`, {
            body: `${alert.alert_message}\nIP: ${alert.src_ip}\nHora: ${new Date(alert.timestamp).toLocaleTimeString()}`,
            icon: '/images/notification-icon.png',
            tag: 'security-alert'
        });

        notification.onclick = function() {
            window.focus();
            // Aquí podrías redirigir a una página de detalles de la alerta
            // window.location.href = `/alert-details.php?id=${alert.id}`;
        };
    }
}

// Mostrar notificación visual en el dashboard
function showDashboardNotification(alert) {
    const notificationsDiv = document.getElementById('alertNotifications');
    if (!notificationsDiv) return;

    const notification = document.createElement('div');
    notification.className = `dashboard-notification severity-${alert.severity}`;
    notification.innerHTML = `
        <div class="notification-content">
            <div class="notification-icon">
                <i class="fas ${alert.severity >= 2 ? 'fa-exclamation-circle' : 'fa-info-circle'}"></i>
            </div>
            <div class="notification-details">
                <div class="notification-severity">${alert.severity >= 2 ? '¡ALERTA!' : 'INFORMACIÓN'}</div>
                <div class="notification-message">${alert.alert_message}</div>
                <div class="notification-source">Origen: ${alert.src_ip}</div>
                <div class="notification-timestamp">${new Date(alert.timestamp).toLocaleTimeString()}</div>
            </div>
        </div>
    `;

    notificationsDiv.insertBefore(notification, notificationsDiv.firstChild);

    // Eliminar notificaciones antiguas después de 5 minutos
    setTimeout(() => {
        notification.remove();
    }, 300000);
}

// Mostrar notificación web de alerta
function showWebNotification(alert) {
    if (Notification.permission === 'granted') {
        const severityText = alert.severity >= 2 ? 'ALTA' : (alert.severity == 1 ? 'MEDIA' : 'BAJA');
        const notif = new Notification('Nueva alerta de seguridad', {
            body: `[${severityText}] ${alert.alert_message}\nOrigen: ${alert.src_ip}`,
            icon: '/assets/logo.png',
            tag: 'secnet-alert',
        });
        notif.onclick = function() {
            window.focus();
        };
    }
}

// Reproducir sonido de alerta
function playAlertSound() {
    const sound = document.getElementById('alertSound');
    if (sound) {
        sound.currentTime = 0;
        sound.play().catch(e => {
            console.log('Error playing alert sound:', e);
        });
    }
}

// Cerrar notificación con animación
function closeNotification(notification) {
    notification.classList.add('removing');
    setTimeout(() => {
        if (notification.parentNode) {
            notification.parentNode.removeChild(notification);
        }
    }, 300);
}

// Formatear timestamp para mostrar
function formatTimestamp(timestamp) {
    // Espera formato ISO o Y-m-d H:i:s
    const date = new Date(timestamp.replace(' ', 'T'));
    if (isNaN(date)) return timestamp;
    const dd = String(date.getDate()).padStart(2, '0');
    const mm = String(date.getMonth() + 1).padStart(2, '0');
    const aaaa = date.getFullYear();
    const hh = String(date.getHours()).padStart(2, '0');
    const min = String(date.getMinutes()).padStart(2, '0');
    return `${dd}-${mm}-${aaaa} ${hh}:${min}`;
}

// Ver detalles de alerta (redirigir a la página de detalles)
function viewAlertDetails(alertId) {
    window.location.href = `alert-details.php?id=${alertId}`;
}

// Bloquear IP (enviar solicitud al backend)
function blockIP(ip) {
    if (!ip || typeof ip !== 'string' || !/^\d{1,3}(?:\.\d{1,3}){3}$|^([a-fA-F0-9:]+)$/.test(ip)) {
        alert('IP inválida. No se puede bloquear.');
        return;
    }
    if (confirm(`¿Estás seguro de que deseas bloquear la IP ${ip}?`)) {
        fetch('api/block-ip.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `ip=${encodeURIComponent(ip)}&reason=${encodeURIComponent('Bloqueo manual desde alertas')}`
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert(`IP ${ip} bloqueada exitosamente`);
                window.location.reload();
            } else {
                alert(`Error al bloquear IP: ${data.message || 'Desconocido'}`);
                if (data.details) console.error(data.details);
            }
        })
        .catch(error => {
            console.error('Error blocking IP:', error);
            alert('Error al bloquear IP. Consulta la consola para más detalles.');
        });
    }
}

// Actualizar estadísticas del dashboard
function updateDashboardStats(stats) {
    // Actualizar contadores de estadísticas si existen en la página
    const elements = {
        'total_alerts': document.querySelector('.stat-card:nth-child(1) .stat-number'),
        'high_severity': document.querySelector('.stat-card:nth-child(2) .stat-number'),
        'blocked_ips': document.querySelector('.stat-card:nth-child(3) .stat-number'),
    };
    
    // Actualizar cada elemento si existe
    for (const [key, element] of Object.entries(elements)) {
        if (element && stats[key] !== undefined) {
            element.textContent = stats[key];
        }
    }
    
    // Actualizar tendencias
    const recentTrend = document.querySelector('.stat-card:nth-child(1) .stat-trend');
    if (recentTrend && stats.recent_alerts !== undefined) {
        recentTrend.innerHTML = `
            <i class="fas fa-${stats.recent_alerts > 0 ? 'arrow-up' : 'arrow-down'}"></i>
            ${stats.recent_alerts} in last 24h
        `;
        recentTrend.className = `stat-trend ${stats.recent_alerts > 0 ? 'up' : 'down'}`;
    }
}

// Function to update dashboard based on time range
function updateDashboard() {
    const timeRange = document.getElementById('timeRange').value;
    // In a real implementation, this would make an AJAX call to get new data
    // For now, we'll just reload the page with a query parameter
    window.location.href = 'index.php?timeRange=' + timeRange;
}

// Función mejorada para actualizar la UI de alertas
function updateAlertUI(alert) {
    const alertsTable = document.querySelector('.alerts-table tbody');
    if (!alertsTable) return;
    
    const row = document.createElement('tr');
    const severity = determineAlertSeverity(alert);
    row.innerHTML = `
        <td>${alert.id}</td>
        <td>${formatTimestamp(alert.timestamp)}</td>
        <td>${alert.src_ip}</td>
        <td>${alert.dest_ip || ''}</td>
        <td>${alert.alert_message}</td>
        <td>${alert.protocol || 'unknown'}</td>
        <td class="severity ${severity.toLowerCase()}">${alert.severity}</td>
        <td>${alert.action_taken || 'none'}</td>
        <td>
            <button class="action-btn alerta details-button" onclick="viewAlertDetails(${alert.id})">
                <i class="fas fa-eye"></i>
            </button>
            ${alert.action_taken && alert.action_taken.includes('Blocked') ? 
                `<button class="action-btn alerta unblock-button" onclick="unblockIP('${alert.src_ip}')">
                    <i class="fas fa-unlock"></i>
                </button>` :
                `<button class="action-btn alerta block-button" onclick="blockIP('${alert.src_ip}')">
                    <i class="fas fa-ban"></i>
                </button>`
            }
        </td>
    `;
    
    alertsTable.insertBefore(row, alertsTable.firstChild);
    
    // Actualizar contadores
    updateAlertCounters(alert);
}

// Función para actualizar contadores de alertas
function updateAlertCounters(alert) {
    const counters = {
        'total-alerts': document.getElementById('total-alerts'),
        'high-severity': document.getElementById('high-severity'),
        'blocked-ips': document.getElementById('blocked-ips'),
        'recent-alerts': document.getElementById('recent-alerts')
    };
    
    if (counters['total-alerts']) {
        counters['total-alerts'].textContent = 
            (parseInt(counters['total-alerts'].textContent) || 0) + 1;
    }
    
    if (alert.severity === 3 && counters['high-severity']) {
        counters['high-severity'].textContent = 
            (parseInt(counters['high-severity'].textContent) || 0) + 1;
    }
    
    if (alert.action_taken && alert.action_taken.includes('Blocked') && counters['blocked-ips']) {
        counters['blocked-ips'].textContent = 
            (parseInt(counters['blocked-ips'].textContent) || 0) + 1;
    }
    
    if (counters['recent-alerts']) {
        counters['recent-alerts'].textContent = 
            (parseInt(counters['recent-alerts'].textContent) || 0) + 1;
    }
}

// Función para desbloquear IP
function unblockIP(ip) {
    if (!ip || typeof ip !== 'string' || !/^\d{1,3}(?:\.\d{1,3}){3}$|^([a-fA-F0-9:]+)$/.test(ip)) {
        alert('IP inválida. No se puede desbloquear.');
        return;
    }
    
    if (confirm(`¿Estás seguro de que deseas desbloquear la IP ${ip}?`)) {
        fetch('api/unblock-ip.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ ip_address: ip })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert(`IP ${ip} desbloqueada exitosamente`);
                // Actualizar la interfaz
                updateBlockedIPsList();
                // Actualizar contadores
                const blockedIpsCounter = document.getElementById('blocked-ips');
                if (blockedIpsCounter) {
                    blockedIpsCounter.textContent = 
                        Math.max(0, (parseInt(blockedIpsCounter.textContent) || 0) - 1);
                }
            } else {
                alert(`Error al desbloquear IP: ${data.message || 'Desconocido'}`);
                if (data.details) console.error(data.details);
            }
        })
        .catch(error => {
            console.error('Error unblocking IP:', error);
            alert('Error al desbloquear IP. Consulta la consola para más detalles.');
        });
    }
}

// Función para actualizar la lista de IPs bloqueadas
function updateBlockedIPsList() {
    fetch('api/blocked-ips.php')
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                const blockedIPsTable = document.querySelector('.blocked-ips-table tbody');
                if (blockedIPsTable) {
                    blockedIPsTable.innerHTML = '';
                    data.blocked_ips.forEach(ip => {
                        const row = document.createElement('tr');
                        row.innerHTML = `
                            <td>${ip.ip_address}</td>
                            <td>${formatTimestamp(ip.timestamp)}</td>
                            <td>${ip.reason}</td>
                            <td>
                                <button class="action-btn unblock-button" onclick="unblockIP('${ip.ip_address}')">
                                    <i class="fas fa-unlock"></i> Desbloquear
                                </button>
                            </td>
                        `;
                        blockedIPsTable.appendChild(row);
                    });
                }
            }
        })
        .catch(error => {
            console.error('Error al obtener lista de IPs bloqueadas:', error);
        });
}
