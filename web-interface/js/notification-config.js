// Configuración de notificaciones
const NOTIFICATION_CONFIG = {
    // Configuración de prioridad
    PRIORITY_LEVELS: {
        HIGH: 'high',
        MEDIUM: 'medium',
        LOW: 'low'
    },

    // Umbral de agrupamiento de notificaciones
    GROUPING_THRESHOLD: 3,

    // Tiempo máximo para agrupar notificaciones similares (en minutos)
    GROUPING_TIME_WINDOW: 5,

    // Configuración de sonidos
    SOUND_CONFIG: {
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
    },

    // Tiempo de retención de notificaciones (en minutos)
    RETENTION_TIME: 30,

    // Configuración de resumen diario
    DAILY_SUMMARY: {
        ENABLED: true,
        TIME: '18:00', // Hora del resumen diario
        INCLUDE_STATS: true,
        INCLUDE_TOP_ATTACKERS: true
    }
};

// Exportar configuración
export { NOTIFICATION_CONFIG };
