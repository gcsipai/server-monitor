<?php
// Naplózási függvény (Audit Log)
function log_audit($pdo, $action, $description = null, $user_id = null) {
    if (!isset($pdo)) {
        error_log("Hiba: A log_audit funkció PDO kapcsolat nélkül lett hívva.");
        return;
    }
    
    // IP cím lekérdezése biztonságosabban
    $ip_address = $_SERVER['HTTP_CLIENT_IP'] ?? $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? 'unknown';

    try {
        $stmt = $pdo->prepare("INSERT INTO audit_log (user_id, action, description, ip_address) VALUES (?, ?, ?, ?)");
        $stmt->execute([$user_id, $action, $description, $ip_address]);
    } catch (PDOException $e) {
        error_log("Audit logolási hiba: " . $e->getMessage());
    }
}

// A monitorozás futtatása
function run_monitoring($pdo) {
    try {
        // Lekérdezzük az összes hosztot
        $stmt = $pdo->query("SELECT id, ip_address, name, port, description FROM hosts ORDER BY ip_address, port");
        $db_hosts = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        if (empty($db_hosts)) {
            return ['error' => 'Nincsenek hosztok konfigurálva'];
        }
        
        $hosts_grouped = [];
        foreach ($db_hosts as $row) {
            $ip = $row['ip_address'];
            // A hosztot IP cím alapján csoportosítjuk (minden szolgáltatás Ping állapotot kap)
            if (!isset($hosts_grouped[$ip])) {
                $hosts_grouped[$ip] = [
                    'ip' => $ip,
                    'services' => [],
                    'ping_status' => null // Ezt a check_status fogja beállítani
                ];
            }
            // Hozzáadjuk a szolgáltatást
            $service_name = $row['port'] === null ? 
                'Ping Only' : 
                $row['name'] . " (Port " . $row['port'] . ")";
            
            $hosts_grouped[$ip]['services'][] = [
                'id' => $row['id'],
                'name' => $row['name'],
                'ip_address' => $ip,
                'service_name' => $service_name,
                'port' => $row['port'],
                'description' => $row['description'],
                'status' => null // Ezt is a check_status fogja beállítani
            ];
        }

        $results = [];
        foreach ($hosts_grouped as $ip => $data) {
            $check_results = check_status($data['ip'], $data['services']);
            
            // Ping állapot beállítása a fő csoporthoz
            $data['ping_status'] = $check_results['ping'];
            
            // Szolgáltatás állapotok visszaállítása a grouped services-be
            foreach ($data['services'] as $index => $service) {
                $service_key = $service['port'] === null ? 'ping_only' : $service['port'];
                $data['services'][$index]['status'] = $check_results['services'][$service_key] ?? ['status' => 'N/A', 'badge' => 'secondary', 'icon' => 'fa-question'];
            }
            
            $results[$ip] = $data;
        }
        
        return $results;
        
    } catch (PDOException $e) {
        error_log("Monitoring hiba: " . $e->getMessage());
        return ['error' => 'Adatbázis hiba a monitorozás során'];
    }
}

// Nagios-szerű Ping és Port ellenőrzés
function check_status($ip, $services) {
    $host_status = ['ping' => ['status' => 'N/A', 'badge' => 'secondary', 'icon' => 'fa-question'], 'services' => []];

    // IP cím validáció
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        $host_status['ping'] = ['status' => 'INVALID IP', 'badge' => 'warning', 'icon' => 'fa-exclamation-triangle'];
        return $host_status;
    }

    // PING ELLENŐRZÉS (ICMP) - platformfüggetlen
    $is_windows = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
    
    // Részletesebb ping kimenet kezelés
    $ping_command = $is_windows ? 
        'ping -n 1 -w 1000 ' . escapeshellarg($ip) : // 1 csomag, 1000ms timeout
        'ping -c 1 -W 1 ' . escapeshellarg($ip);    // 1 csomag, 1s timeout
    
    $ping_output = shell_exec($ping_command . ' 2>&1'); 

    if (strpos($ping_output, '1 received') !== false || 
        strpos($ping_output, 'bytes from') !== false ||
        ($is_windows && strpos($ping_output, 'TTL=') !== false)) {
        $host_status['ping'] = ['status' => 'UP', 'badge' => 'success', 'icon' => 'fa-arrow-up'];
    } else {
        $host_status['ping'] = ['status' => 'DOWN', 'badge' => 'danger', 'icon' => 'fa-arrow-down'];
    }
    
    // Ha a ping nem megy át, a port ellenőrzéseket nem is érdemes futtatni,
    // de az "ÁLLAPOT" mezőket kitöltjük az olvashatóság miatt.

    // SZOLGÁLTATÁS ELLENŐRZÉS (TCP Port)
    foreach ($services as $service_data) {
        $port = $service_data['port'];
        $key = $port === null ? 'ping_only' : $port;
        
        if ($port === null) {
            // Ping only bejegyzés: az állapot megegyezik a Ping eredménnyel
            $host_status['services'][$key] = $host_status['ping'];
            continue; 
        }
        
        // Port validáció
        if (!is_numeric($port) || $port < 1 || $port > 65535) {
            $host_status['services'][$key] = ['status' => 'INVALID PORT', 'badge' => 'warning', 'icon' => 'fa-exclamation-triangle'];
            continue;
        }
        
        // TCP kapcsolat tesztelése
        $timeout = 2; // 2 másodperc timeout
        $fp = @fsockopen($ip, $port, $errno, $errstr, $timeout);
        
        if ($fp) {
            $host_status['services'][$key] = ['status' => 'OK', 'badge' => 'success', 'icon' => 'fa-check'];
            fclose($fp);
        } else {
            // Ha a ping DOWN, a port is CRITICAL
            if ($host_status['ping']['status'] === 'DOWN') {
                $host_status['services'][$key] = ['status' => 'CRITICAL (Ping DOWN)', 'badge' => 'danger', 'icon' => 'fa-times-circle'];
            } else {
                $host_status['services'][$key] = ['status' => 'CRITICAL (Port Zárva)', 'badge' => 'danger', 'icon' => 'fa-times'];
            }
        }
    }

    return $host_status;
}
?>
