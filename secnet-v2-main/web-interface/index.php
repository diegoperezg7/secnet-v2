<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="icon" type="image/png" href="assets/logo.png">
    <title>Sistema de Respuesta a Incidentes de Seguridad</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link rel="stylesheet" href="css/style.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <!-- Añadir audio para alertas -->
    <audio id="alertSound" preload="auto">
        <source src="sounds/alert.mp3" type="audio/mpeg">
    </audio>
    <!-- Tipografía tecnológica para títulos -->
    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@700;900&display=swap" rel="stylesheet">
</head>
<body>
    <div class="container">
        <!-- Componente de notificación de alertas en tiempo real -->
        <div id="alertNotifications" class="alert-notifications"></div>
        
        <header>
            <div class="logo-container">
                <a href="index.php" style="display:flex;align-items:center;text-decoration:none;">
                    <img src="assets/logo.png" alt="Logo">
                    <h1 style="font-family: 'Orbitron', sans-serif;">SecNet</h1>
                </a>
            </div>
            <nav>
                <ul>
                    <li><a href="index.php" class="active"><i class="fas fa-tachometer-alt"></i> Panel</a></li>
                    <li><a href="alerts.php"><i class="fas fa-exclamation-triangle"></i> Alertas</a></li>
                </ul>
            </nav>
        </header>
        
        <main>
            <div class="dashboard-header">
                <h2><i class="fas fa-chart-line"></i> Resumen de Seguridad</h2>
            </div>
            <section class="dashboard">
                <div class="stats-container">
                    <?php
                    // Connect to SQLite database
                    $db = new SQLite3('/var/www/html/database/alerts.db');
                    
                    // Obtener IPs bloqueadas
                    $blocked_ip_list = [];
                    $blocked_result = $db->query("SELECT DISTINCT ip_address FROM blocked_ips");
                    while ($row = $blocked_result->fetchArray(SQLITE3_ASSOC)) {
                        $blocked_ip_list[] = $row['ip_address'];
                    }
                    $has_blocked = count($blocked_ip_list) > 0;
                    $blocked_ips_placeholder = $has_blocked ? "'" . implode("','", $blocked_ip_list) . "'" : '';

                    // Generar condiciones dinámicamente
                    // DESACTIVAMOS EL FILTRO PARA MOSTRAR TODA LA INFORMACIÓN
                    $where_not_blocked = "1=1";

                    // Obtener el rango de tiempo seleccionado
                    $timeRange = isset($_GET['timeRange']) ? $_GET['timeRange'] : '';
                    $useTimeFilter = ($timeRange !== '' && is_numeric($timeRange));
                    $timeFilter = $useTimeFilter ? "timestamp > datetime('now', '-$timeRange hours')" : '1=1';

                    // Get alert statistics
                    $total_alerts = $db->querySingle("SELECT COUNT(*) FROM alerts WHERE $where_not_blocked AND $timeFilter");
                    $high_severity = $db->querySingle("SELECT COUNT(*) FROM alerts WHERE severity >= 2 AND ($where_not_blocked) AND $timeFilter");
                    $blocked_ips = $db->querySingle("SELECT COUNT(DISTINCT ip_address) FROM blocked_ips");
                    $recent_alerts = $db->querySingle("SELECT COUNT(*) FROM alerts WHERE $timeFilter AND ($where_not_blocked)");

                    // Get alert types for chart data
                    $alert_types = [];
                    $query = "SELECT alert_message, COUNT(*) as count FROM alerts WHERE $where_not_blocked AND $timeFilter GROUP BY alert_message ORDER BY count DESC LIMIT 5";
                    $alert_types_result = $db->query($query);
                    while ($row = $alert_types_result->fetchArray(SQLITE3_ASSOC)) {
                        $alert_types[$row['alert_message']] = $row['count'];
                    }

                    // Get alerts by hour for timeline chart
                    $alerts_by_hour = [];
                    $timeline_query = "SELECT strftime('%Y-%m-%d %H:00:00', timestamp) as hour, COUNT(*) as count FROM alerts WHERE $timeFilter AND ($where_not_blocked) GROUP BY hour ORDER BY hour";
                    $timeline_result = $db->query($timeline_query);
                    while ($row = $timeline_result->fetchArray(SQLITE3_ASSOC)) {
                        $alerts_by_hour[$row['hour']] = $row['count'];
                    }

                    // Get severity distribution
                    $severity_dist = [];
                    $severity_query = "SELECT severity, COUNT(*) as count FROM alerts WHERE $where_not_blocked AND $timeFilter GROUP BY severity ORDER BY severity";
                    $severity_result = $db->query($severity_query);
                    while ($row = $severity_result->fetchArray(SQLITE3_ASSOC)) {
                        $severity_dist[$row['severity']] = $row['count'];
                    }

                    // Get top attackers data
                    $top_attackers = [];
                    $top_attackers_query = "SELECT src_ip, COUNT(*) as count, MAX(severity) as max_severity FROM alerts WHERE $where_not_blocked AND $timeFilter GROUP BY src_ip ORDER BY count DESC LIMIT 10";
                    $top_attackers_result = $db->query($top_attackers_query);
                    while ($row = $top_attackers_result->fetchArray(SQLITE3_ASSOC)) {
                        $top_attackers[$row['src_ip']] = [
                            'count' => $row['count'],
                            'severity' => $row['max_severity']
                        ];
                    }
                    ?>
                    
                    <div class="stat-card">
                        <div class="stat-icon"><i class="fas fa-exclamation-circle"></i></div>
                        <div class="stat-content">
                            <div class="stat-title">Alertas Totales</div>
                            <div class="stat-value"><?php echo $total_alerts; ?></div>
                        </div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-icon danger"><i class="fas fa-bolt"></i></div>
                        <div class="stat-content">
                            <div class="stat-title">Alta Severidad</div>
                            <div class="stat-value"><?php echo $high_severity; ?></div>
                        </div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-icon"><i class="fas fa-ban"></i></div>
                        <div class="stat-content">
                            <div class="stat-title">IPs Bloqueadas</div>
                            <div class="stat-value"><?php echo $blocked_ips; ?></div>
                        </div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-icon"><i class="fas fa-clock"></i></div>
                        <div class="stat-content">
                            <div class="stat-title">Alertas últimas 24h</div>
                            <div class="stat-value"><?php echo $recent_alerts; ?></div>
                        </div>
                    </div>
                </div>
                <div class="charts-container">
<?php
// Preparar datos para gráficos
function prepareChartDatasets() {
    $db = new SQLite3('/var/www/html/database/alerts.db');
    
    // Obtener tipos de alertas
    $alert_types = [];
    $query = "SELECT alert_message, COUNT(*) as count FROM alerts GROUP BY alert_message ORDER BY count DESC LIMIT 5";
    $alert_types_result = $db->query($query);
    while ($row = $alert_types_result->fetchArray(SQLITE3_ASSOC)) {
        $alert_types[$row['alert_message']] = $row['count'];
    }
    
    // Obtener distribución de severidad
    $severity_dist = [];
    $severity_query = "SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity ORDER BY severity";
    $severity_result = $db->query($severity_query);
    while ($row = $severity_result->fetchArray(SQLITE3_ASSOC)) {
        $severity_dist[$row['severity']] = $row['count'];
    }
    
    // Obtener alertas por hora
    $alerts_by_hour = [];
    $timeline_query = "SELECT strftime('%Y-%m-%d %H:00:00', timestamp) as hour, COUNT(*) as count FROM alerts GROUP BY hour ORDER BY hour";
    $timeline_result = $db->query($timeline_query);
    while ($row = $timeline_result->fetchArray(SQLITE3_ASSOC)) {
        $alerts_by_hour[$row['hour']] = $row['count'];
    }
    
    return [
        'alert_types' => $alert_types,
        'severity_dist' => $severity_dist,
        'alerts_by_hour' => $alerts_by_hour
    ];
}

$chartData = prepareChartDatasets();
?>

                    <div class="chart-card">
                        <h3><i class="fas fa-chart-pie"></i> Tipos de Alertas</h3>
                        <div class="chart-container" style="min-height: 300px;">
                            <canvas id="alertTypesChart"></canvas>
                        </div>
                    </div>
                    <div class="chart-card">
                        <h3><i class="fas fa-chart-bar"></i> Distribución de severidad</h3>
                        <div class="chart-container" style="min-height: 300px;">
                            <canvas id="severityChart" style="width: 100%; height: 100%;"></canvas>
                        </div>
                    </div>
                </div>
                <div class="top-attackers-section">
                    <h3><i class="fas fa-user-secret"></i> Principales atacantes</h3>
                    <table class="top-attackers-table">
                        <thead>
                            <tr>
                                <th>IP origen</th>
                                <th>Alertas</th>
                                <th>Severidad máx.</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($top_attackers as $ip => $info): ?>
                                <tr>
                                    <td><?php echo htmlspecialchars($ip); ?></td>
                                    <td><?php echo $info['count']; ?></td>
                                    <td><?php echo $info['severity']; ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
                <div class="recent-alerts">
                    <div class="section-header">
                        <h3><i class="fas fa-bell"></i> Alertas recientes</h3>
                        <a href="alerts.php" class="view-all">Ver todas <i class="fas fa-arrow-right"></i></a>
                    </div>
                    <div class="table-container">
                        <table>
                            <thead>
                                <tr>
                                    <th>Hora</th>
                                    <th>IP origen</th>
                                    <th>Alerta</th>
                                    <th>Severidad</th>
                                    <th>Acción</th>
                                    <th>Detalles</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php
                                // Get recent alerts
                                $results = $db->query("SELECT * FROM alerts WHERE $where_not_blocked AND $timeFilter ORDER BY timestamp DESC LIMIT 5");
                                
                                while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
                                    $severity_class = ($row['severity'] >= 2) ? 'high' : 'low';
                                    echo '<tr>';
                                    echo '<td>' . date('d-m-Y H:i', strtotime($row['timestamp'])) . '</td>';
                                    echo '<td>' . htmlspecialchars($row['src_ip']) . '</td>';
                                    echo '<td>' . htmlspecialchars($row['alert_message']) . '</td>';
                                    echo '<td><span class="severity ' . $severity_class . '">' . htmlspecialchars($row['severity']) . '</span></td>';
                                    echo '<td>' . htmlspecialchars($row['action_taken']) . '</td>';
                                    echo '<td><a href="alert-details.php?id=' . urlencode($row['id']) . '" class="btn btn-icon" title="Ver detalles"><i class="fas fa-eye"></i></a></td>';
                                    echo '</tr>';
                                }
                                
                                $db->close();
                                ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            </section>
        </main>
        
        <footer class="footer-container">
            <p>&copy; <?php echo date('Y'); ?> Sistema Automatizado de Respuesta a Incidentes</p>
        </footer>
    </div>
    
    <script>
    // Datos para los gráficos - Hacerlos globales
    window.alertTypesData = {
        labels: <?php echo json_encode(array_keys($alert_types)); ?>,
        data: <?php echo json_encode(array_values($alert_types)); ?>
    };
    
    window.timelineData = {
        labels: <?php echo json_encode(array_keys($alerts_by_hour)); ?>,
        data: <?php echo json_encode(array_values($alerts_by_hour)); ?>
    };
    
    // Preparar etiquetas de severidad
    window.severityLabels = <?php 
        $severityNames = ['Baja', 'Media', 'Alta'];
        $formattedLabels = [];
        foreach ($severity_dist as $key => $value) {
            $sevNum = intval($key);
            $formattedLabels[] = 'Severidad ' . ($severityNames[$sevNum] ?? $key);
        }
        echo json_encode($formattedLabels);
    ?>;
    
    window.severityData = {
        labels: window.severityLabels,
        data: <?php echo json_encode(array_values($severity_dist)); ?>
    };
    
    // Debug: mostrar datos en consola
    console.log('alertTypesData:', window.alertTypesData);
    console.log('severityData:', window.severityData);
    
    <?php
    $last_alert_row = $db = new SQLite3('/var/www/html/database/alerts.db');
    $last_alert_row = $last_alert_row->querySingle("SELECT timestamp FROM alerts ORDER BY timestamp DESC LIMIT 1");
    if ($last_alert_row) {
        echo "let lastAlertTimestamp = '" . $last_alert_row . "';\n";
    } else {
        echo "let lastAlertTimestamp = '2000-01-01 00:00:00';\n";
    }
    ?>
    </script>
    <script src="/js/main.clean.js"></script>
    <script>
        // Inicializar los gráficos cuando el DOM esté completamente cargado
        document.addEventListener('DOMContentLoaded', function() {
            console.log('DOM completamente cargado, inicializando gráficos...');
            // Verificar si Chart.js está cargado
            if (typeof Chart === 'undefined') {
                console.error('Chart.js no se ha cargado correctamente');
                return;
            }
            // Verificar si la función initCharts existe
            if (typeof initCharts === 'function') {
                console.log('Inicializando gráficos...');
                initCharts();
            } else {
                console.error('La función initCharts no está definida');
            }
        });
    </script>
</body>
</html>
