#!/bin/bash
# Server-Monitor Teljes Telepítő Szkript (Linux/Unix)
# Telepítési hely: /var/www/html/server-monitor
# Nem hozza létre a .env fájlt, biztosítva, hogy az install.php induljon.

TARGET_DIR="/var/www/html/server-monitor"

# ----------------------------------------------
# 1. ELŐKÉSZÜLETEK ÉS ELLENŐRZÉS
# ----------------------------------------------

echo "🚀 Server-Monitor telepítése a '$TARGET_DIR' könyvtárba..."

# Ellenőrizzük, hogy létezik-e már a könyvtár
if [ -d "$TARGET_DIR" ]; then
    read -r -p "A '$TARGET_DIR' könyvtár már létezik. Töröljük és telepítsük újra? (i/n): " confirm
    if [[ ! "$confirm" =~ ^[iI]$ ]]; then
        echo "A telepítés megszakítva."
        exit 1
    fi
    echo "Törlés..."
    sudo rm -rf "$TARGET_DIR"
fi

# Mappák létrehozása
sudo mkdir -p "$TARGET_DIR"
echo "📂 Könyvtárstruktúra létrehozása..."
sudo mkdir -p "$TARGET_DIR/assets/css"
sudo mkdir -p "$TARGET_DIR/src/Cache"
sudo mkdir -p "$TARGET_DIR/src/Config"
sudo mkdir -p "$TARGET_DIR/src/Repository"
sudo mkdir -p "$TARGET_DIR/src/Security"
sudo mkdir -p "$TARGET_DIR/src/Service"
sudo mkdir -p "$TARGET_DIR/cache" 
sudo mkdir -p "$TARGET_DIR/log"   

# ----------------------------------------------
# 2. PHP FÁJLOK LÉTREHOZÁSA (cat + sudo tee)
# ----------------------------------------------

echo "📝 PHP fájlok generálása..."

# -- Fájltartalom: autoload.php (Javítva: feltételes inicializálás) --
cat << 'EOF' | sudo tee "$TARGET_DIR/autoload.php" > /dev/null
<?php
// Minimal Autoloader
spl_autoload_register(function ($class) {
    if (strpos($class, 'App\\') !== 0) {
        return;
    }
    $base_dir = __DIR__ . '/src/';
    $relative_class = substr($class, 4); 
    $file = $base_dir . str_replace('\\', '/', $relative_class) . '.php';

    if (file_exists($file)) {
        require $file;
    }
});

use App\Config\Config;
use App\Repository\UserRepository;
use App\Repository\HostRepository;
use App\Service\MonitoringService;
use App\Cache\CacheManager;

$config = $pdo = $userRepository = $hostRepository = $cacheManager = $monitoringService = null;

// 1. Ha a .env NEM létezik, és NEM az install.php fut, akkor átirányítunk.
if (!file_exists(__DIR__ . '/.env')) {
    if (basename($_SERVER['PHP_SELF']) !== 'install.php') {
        header("Location: install.php");
        exit();
    }
    // Az install.php itt folytatja a futást, a globális változók nullák.
    return;
}

// 2. Ha a .env létezik, próbáljuk inicializálni a rendszert.
try {
    $config = Config::getInstance();
    
    // Hibakezelés beállítása
    $config->isProduction() ? (ini_set("display_errors", 0) && error_reporting(0)) : (ini_set("display_errors", 1) && error_reporting(E_ALL));

    // Adatbázis kapcsolat
    $pdo = new PDO(
        "mysql:host=" . $config->get('DB_HOST') . ";dbname=" . $config->get('DB_NAME') . ";charset=utf8mb4", 
        $config->get('DB_USER'), 
        $config->get('DB_PASS')
    );
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    $pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES, false); 
    
    // Service-ek inicializálása
    $userRepository = new UserRepository($pdo);
    $hostRepository = new HostRepository($pdo);
    $cacheManager = new CacheManager();
    $monitoringService = new MonitoringService($hostRepository, $cacheManager);

} catch (\Exception $e) {
    // Ha a .env létezik, de a DB kapcsolat hibás, átirányítunk az install.php-ra (hibajelzéssel)
    if (basename($_SERVER['PHP_SELF']) !== 'install.php') {
        error_log("Kritikus indítási hiba: " . $e->getMessage());
        header("Location: install.php"); // Az install.php innen tudja, hogy a DB hibás
        exit();
    }
    // Az install.php itt folytatja a futást, a $pdo NULL lesz.
}
EOF

# -- Fájltartalom: install.php (Javítva: logikusan kezeli a .env hiányát) --
cat << 'EOF' | sudo tee "$TARGET_DIR/install.php" > /dev/null
<?php
// install.php - Server-Monitor Telepítő
if (session_status() === PHP_SESSION_NONE) { session_start(); }
ini_set("display_errors", 1); error_reporting(E_ALL);

// Csak a szükséges fájlok betöltése az AUTOLOAD előtt
if (!file_exists("src/Security/SecurityHelper.php")) { die("Hiba: Nem találom a src/Security/SecurityHelper.php fájlt."); }
require_once "src/Security/SecurityHelper.php";
use App\Security\SecurityHelper;

$error = $message = "";
$step = 1;

// Ha a .env létezik, megpróbáljuk betölteni a teljes autoloader-t.
if (file_exists(".env")) {
    require_once "autoload.php";
    global $pdo;
    
    // Ha az autoload.php lefutott és a $pdo létrejött, akkor a rendszer konfigurálva van.
    if (isset($pdo)) {
        try {
            $pdo->query("SELECT 1"); // Kapcsolat ellenőrzése
            $step = 2; // Sikeres kapcsolat, átléphetünk a befejezéshez.
        } catch (Exception $e) {
            $error = "A .env létezik, de az adatbázis hibás: " . htmlspecialchars($e->getMessage());
        }
    } else {
        // A $pdo nem jött létre az autoload.php-ban (pl. config hiba, de nem a fájl hiánya)
        $error = "A .env létezik, de az inicializáció hibás. Kérjük, ellenőrizze a .env tartalmát, vagy törölje a fájlt a kezdéshez.";
    }
}

// FÜGGVÉNY: Létrehozza a .env fájlt
function generate_env_and_config($host, $user, $pass, $name) {
    $env_content = <<<ENV
APP_ENV=development
APP_NAME="Server-Monitor"
APP_VERSION="2.0.0"

DB_HOST={$host}
DB_NAME={$name}
DB_USER={$user}
DB_PASS={$pass}

DEFAULT_ADMIN_USER=admin
DEFAULT_ADMIN_PASS=admin

SESSION_TIMEOUT=3600
CACHE_DURATION=300
ENV;
    
    if (!file_put_contents(".env", $env_content)) { return "Hiba: Nem sikerült létrehozni a .env fájlt. (Jogosultságok?)"; }
    $cache_dir = __DIR__ . '/cache/';
    if (!is_dir($cache_dir) && !mkdir($cache_dir, 0777, true)) { return "Hiba: Nem sikerült létrehozni a cache/ mappát."; }
    return "success";
}

// SQL SÉMA
$sql_schema = [
    "CREATE TABLE IF NOT EXISTS users ( id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(50) NOT NULL UNIQUE, password_hash VARCHAR(255) NOT NULL, is_admin BOOLEAN DEFAULT FALSE, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP );",
    "CREATE TABLE IF NOT EXISTS hosts ( id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(100) NOT NULL, ip_address VARCHAR(45) NOT NULL, port INT NULL, description VARCHAR(255) NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP );",
    "CREATE TABLE IF NOT EXISTS audit_log ( id INT AUTO_INCREMENT PRIMARY KEY, user_id INT NULL, action VARCHAR(100) NOT NULL, description TEXT, ip_address VARCHAR(45), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP );"
];

// ŰRLAP KEZELÉSE
if ($_SERVER["REQUEST_METHOD"] === "POST" && $step === 1) { 
    if (!isset($_POST['csrf_token']) || !SecurityHelper::verifyCsrfToken($_POST['csrf_token'])) { $error = "CSRF hiba."; goto end_post_processing; }
    
    $db_host = SecurityHelper::sanitizeInput($_POST["db_host"] ?? "");
    $db_user = SecurityHelper::sanitizeInput($_POST["db_user"] ?? "");
    $db_pass = $_POST["db_pass"] ?? ""; 
    $db_name = SecurityHelper::sanitizeInput($_POST["db_name"] ?? "");

    if (empty($db_host) || empty($db_user) || empty($db_name)) { $error = "Minden mező kötelező!"; } else {
        try {
            $pdo_conn = new PDO("mysql:host={$db_host}", $db_user, $db_pass);
            $pdo_conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $pdo_conn->exec("CREATE DATABASE IF NOT EXISTS `{$db_name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;");
            
            $pdo_db = new PDO("mysql:host={$db_host};dbname={$db_name}", $db_user, $db_pass);
            $pdo_db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

            foreach ($sql_schema as $sql) { $pdo_db->exec($sql); }

            $result = generate_env_and_config($db_host, $db_user, $db_pass, $db_name);

            if ($result === "success") {
                require_once "src/Repository/UserRepository.php"; // Kell az osztály
                $userRepo = new \App\Repository\UserRepository($pdo_db); 
                if (!$userRepo->userExists("admin")) {
                    $userRepo->createUser("admin", "admin", true);
                    $message = "success|Telepítés sikeres. Admin: **admin/admin** (azonnal változtassa meg!).<br>";
                } else { $message = "success|Telepítés sikeres. A felhasználók már léteztek.<br>"; }

                $message .= "A beállítások sikeresen létrehozva.";
                $step = 2;
            } else { $error = $result; }

        } catch (\PDOException $e) { $error = "Adatbázis hiba: " . htmlspecialchars($e->getMessage()); }
    }
    
    end_post_processing:
}

if (isset($_GET["delete_installer"]) && $step == 2) {
    header("Content-Type: application/json");
    echo json_encode(["success" => unlink(__FILE__)]);
    exit;
}
?>
<!DOCTYPE html><html lang="hu"><head><meta charset="UTF-8"><title>Server-Monitor Telepítés</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet"><link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css"></head><body class="bg-dark text-light"><div class="container py-5"><div class="card p-5 shadow-lg bg-light text-dark"><h1 class="card-title text-center mb-4"><i class="fas fa-tools me-2"></i> Server-Monitor Telepítés</h1><?php if ($error): ?><div class="alert alert-danger"><i class="fas fa-exclamation-triangle me-2"></i> <?= $error; ?></div><?php endif; ?><?php if ($message): list($type, $msg) = explode("|", $message); ?><div class="alert alert-<?= $type; ?>"><?= $msg; ?></div><?php endif; ?><?php if ($step == 1): ?><p class="lead">Kérjük, adja meg a MySQL/MariaDB adatbázis adatait. Ez létrehozza az adatbázist és a **.env** konfigurációs fájlt.</p><form method="POST"><input type="hidden" name="csrf_token" value="<?= SecurityHelper::generateCsrfToken(); ?>"><div class="mb-3"><label class="form-label">Adatbázis Szerver (Host)</label><input type="text" name="db_host" class="form-control" value="<?= SecurityHelper::sanitizeInput($_POST["db_host"] ?? "localhost"); ?>" required></div><div class="mb-3"><label class="form-label">Adatbázis Neve</label><input type="text" name="db_name" class="form-control" value="<?= SecurityHelper::sanitizeInput($_POST["db_name"] ?? "server_monitor_db"); ?>" required></div><div class="mb-3"><label class="form-label">Adatbázis Felhasználó</label><input type="text" name="db_user" class="form-control" value="<?= SecurityHelper::sanitizeInput($_POST["db_user"] ?? ""); ?>" required></div><div class="mb-3"><label class="form-label">Adatbázis Jelszó</label><input type="password" name="db_pass" class="form-control"></div><button type="submit" class="btn btn-primary w-100"><i class="fas fa-cogs me-2"></i> Telepítés indítása</button></form><?php elseif ($step == 2): ?><div class="alert alert-success"><h4 class="alert-heading">Telepítés sikeresen befejeződött!</h4><p class="mb-0 text-danger">⚠️ **BIZTONSÁGI FIGYELMEZTETÉS:** Erősen ajánlott az **`install.php`** fájl azonnali **törlése** a szerverről!</p></div><a href="index.php" class="btn btn-success w-100"><i class="fas fa-sign-in-alt me-2"></i> Tovább a Server-Monitorhoz</a><script>document.addEventListener('DOMContentLoaded', function() {setTimeout(function() {if(confirm("Ajánlott a telepítő fájl törlése a biztonság érdekében. Szeretné most törölni?")) {fetch("?delete_installer=1").then(response => response.json()).then(data => {if(data.success) {alert("Telepítő sikeresen törölve!");window.location.href = "index.php";} else {alert("Törlés sikertelen. Kérjük, manuálisan törölje az install.php fájlt!");}}).catch(e => alert("Törlési hiba. Kérjük, manuálisan törölje az install.php fájlt!"));}}, 3000);});</script><?php endif; ?></div></div></body></html>
EOF

# -- A többi PHP fájl tartalmát változatlanul be kell illeszteni --
# Csak az index.php-t, auth.php-t és a többi src/* fájlt illesztem be
# az áttekinthetőség kedvéért.
# (A szkriptben teljes tartalommal szerepelnek a következő fájlok:
# index.php, auth.php, admin_hosts.php, admin_users.php, 
# assets/css/themes.php, src/Cache/CacheManager.php, src/Config/Config.php,
# src/Repository/HostRepository.php, src/Repository/UserRepository.php, 
# src/Security/SecurityHelper.php, src/Service/MonitoringService.php)

# -- Fájltartalom: index.php --
cat << 'EOF' | sudo tee "$TARGET_DIR/index.php" > /dev/null
<?php
require_once "auth.php"; 
require_auth(); 

global $pdo, $monitoringService; 
use App\Security\SecurityHelper;

$monitoring_results = $monitoringService->getMonitoringResults();

$last_checked = null;
foreach ($monitoring_results as $ip => $data) {
    if (isset($data['last_checked'])) {
        $last_checked = $data['last_checked'];
        break;
    }
}
$cacheDuration = $monitoringService->getCacheDuration();

show_header("Állapot Áttekintés");
?>

<div class="row mb-4">
    <div class="col-12">
        <h1><i class="fas fa-tachometer-alt me-2"></i> Server-Monitor Állapot</h1>
        <p class="lead">Utolsó frissítés: <?= date("Y. m. d. H:i:s", $last_checked ?? time()); ?> (Cache TTL: <?= round($cacheDuration/60, 0); ?> perc)</p>
    </div>
</div>

<div class="row mt-4">
    <?php if (empty($monitoring_results)): ?>
         <div class="col-12"><div class="alert alert-info"><i class="fas fa-info-circle me-2"></i> Nincsenek hosztok konfigurálva. Kérjük, adja hozzá az első hosztot az **Adminisztráció** menüben.</div></div>
    <?php else:
    
    foreach ($monitoring_results as $ip => $data): ?>
    <div class="col-md-6 col-lg-4 mb-4">
        <div class="card card-host shadow-sm border-<?= $data["ping_status"]["badge"]; ?>">
            <div class="card-header bg-<?= $data["ping_status"]["badge"]; ?> text-white">
                <h5 class="mb-0"><i class="fas fa-server me-2"></i> Hoszt: <?= SecurityHelper::sanitizeInput($data["ip"]); ?></h5>
            </div>
            <div class="card-body">
                <p class="mb-3">
                    <strong><i class="fas fa-plug me-2"></i> Alapvető elérhetőség (PING):</strong> 
                    <span class="status-badge badge bg-<?= $data["ping_status"]["badge"]; ?>">
                        <i class="fas <?= $data["ping_status"]["icon"]; ?> me-1"></i> <?= $data["ping_status"]["status"]; ?>
                    </span>
                </p>
                
                <h6><i class="fas fa-cogs me-2"></i> Szolgáltatások Ellenőrzése:</h6>
                <ul class="service-list">
                    <?php 
                    foreach ($data["services"] as $service): 
                        $status = $service["status"];
                    ?>
                        <li>
                            <strong><?= SecurityHelper::sanitizeInput($service["service_name"]); ?>:</strong> 
                            <span class="status-badge badge bg-<?= $status["badge"]; ?>">
                                <i class="fas <?= $status["icon"]; ?> me-1"></i> <?= $status["status"]; ?>
                            </span>
                        </li>
                    <?php endforeach; ?>
                </ul>
            </div>
        </div>
    </div>
    <?php endforeach; endif; ?>
</div>

<?php show_footer(); ?>
EOF

# -- Fájltartalom: auth.php --
cat << 'EOF' | sudo tee "$TARGET_DIR/auth.php" > /dev/null
<?php
// auth.php - A rendszer hitelesítési és menükezelő fájl

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Ha a .env nem létezik, átirányít az install.php-ra (az autoload.php kezeli)
require_once "autoload.php"; 

use App\Security\SecurityHelper;

global $pdo, $userRepository; 

function log_audit($pdo, $action, $description = null, $user_id = null) {
    if (!isset($pdo)) { return; } // Nincs DB kapcsolat, nincs log
    $ip_address = $_SERVER["HTTP_CLIENT_IP"] ?? $_SERVER["HTTP_X_FORWARDED_FOR"] ?? $_SERVER["REMOTE_ADDR"] ?? "unknown";

    try {
        $stmt = $pdo->prepare("INSERT INTO audit_log (user_id, action, description, ip_address) VALUES (?, ?, ?, ?)");
        $stmt->execute([$user_id, $action, SecurityHelper::sanitizeInput($description), $ip_address]);
    } catch (\PDOException $e) {
        error_log("Audit logolási hiba: " . $e->getMessage());
    }
}

$available_themes = [
    "light" => "Világos (Light)", "dark" => "Sötét (Dark)", "primary" => "Kék (Primary)", "success" => "Zöld (Success)",
    "info" => "Ciánkék (Info)", "warning" => "Sárga (Warning)", "danger" => "Piros (Danger)"
];

if (isset($_POST["set_theme"]) && array_key_exists($_POST["set_theme"], $available_themes)) {
    $_SESSION["theme"] = $_POST["set_theme"];
    header("Location: " . $_SERVER["PHP_SELF"]); exit();
}

if (isset($_GET["logout"])) {
    log_audit($pdo, "LOGOUT", "Felhasználó kijelentkezett", $_SESSION["user_id"] ?? null);
    session_destroy();
    if (session_status() === PHP_SESSION_NONE) { session_start(); }
    header("Location: index.php"); exit();
}

if (isset($_POST["login"])) {
    if (!isset($userRepository)) { $login_error = "Rendszerhiba: Nem elérhető az adatbázis."; goto end_login; }
    if (!isset($_POST['csrf_token']) || !SecurityHelper::verifyCsrfToken($_POST['csrf_token'])) {
        $login_error = "CSRF hiba. Kérjük, próbálja újra.";
        goto end_login;
    }

    $username = SecurityHelper::sanitizeInput($_POST["username"]);
    $password = $_POST["password"];
    $user = $userRepository->findByUsername($username);

    if ($user && password_verify($password, $user["password_hash"])) {
        $_SESSION["user_id"] = $user["id"];
        $_SESSION["username"] = $user["username"];
        $_SESSION["is_admin"] = $user["is_admin"];
        $_SESSION["theme"] = $_SESSION["theme"] ?? "light"; 
        log_audit($pdo, "LOGIN_SUCCESS", "Sikeres bejelentkezés", $user["id"]);
        unset($_SESSION['csrf_token']);
        header("Location: index.php"); exit();
    } else {
        $login_error = "Hibás felhasználónév vagy jelszó.";
        log_audit($pdo, "LOGIN_FAILURE", "Sikertelen bejelentkezési kísérlet: " . $username, null);
    }
    end_login:
}

function require_auth() {
    if (!isset($_SESSION["user_id"])) {
        show_login_form();
        exit();
    }
}

function show_login_form($error = null) {
    global $login_error;
    $error = $error ?? $login_error;
    $csrf_token = SecurityHelper::generateCsrfToken();
    ?>
    <!DOCTYPE html><html lang="hu"><head><meta charset="UTF-8"><title>Server-Monitor Belépés</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet"><link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css"></head><body class="bg-light"><div class="container d-flex justify-content-center align-items-center" style="min-height: 100vh;"><div class="card p-4 shadow-lg" style="width: 380px;"><h3 class="card-title text-center mb-4"><i class="fas fa-lock me-2"></i> Server-Monitor Belépés</h3><form method="POST"><input type="hidden" name="login" value="1"><input type="hidden" name="csrf_token" value="<?= $csrf_token; ?>"><div class="mb-3"><label for="username" class="form-label">Felhasználónév</label><input type="text" class="form-control" id="username" name="username" required></div><div class="mb-3"><label for="password" class="form-label">Jelszó</label><input type="password" class="form-control" id="password" name="password" required></div><?php if ($error): ?><div class="alert alert-danger"><?= $error; ?></div><?php endif; ?><button type="submit" class="btn btn-primary w-100">Belépés</button></form></div></div></body></html>
    <?php
}

function show_header($page_title) {
    global $available_themes;
    $current_theme = $_SESSION["theme"] ?? "light"; 

    ?>
    <!DOCTYPE html><html lang="hu" data-bs-theme="<?= $current_theme === 'dark' ? 'dark' : 'light'; ?>"><head><meta charset="UTF-8"><title>Server-Monitor | <?= SecurityHelper::sanitizeInput($page_title); ?></title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet"><link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css"><link rel="stylesheet" href="assets/css/themes.php"><style>.service-list { list-style: none; padding-left: 0; }.status-badge { font-size: 0.875em; padding: 0.35em 0.65em; }.card-host { transition: transform 0.2s ease-in-out; }.card-host:hover { transform: translateY(-2px); }</style></head><body class="bg-body-tertiary"><nav class="navbar navbar-expand-lg bg-body-tertiary shadow-sm sticky-top"><div class="container-fluid"><a class="navbar-brand" href="index.php"><i class="fas fa-chart-line me-2"></i> SERVER-MONITOR</a><button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation"><span class="navbar-toggler-icon"></span></button><div class="collapse navbar-collapse" id="navbarNav"><ul class="navbar-nav me-auto"><li class="nav-item"><a class="nav-link <?= strpos($_SERVER["REQUEST_URI"], "index.php") !== false && strpos($_SERVER["REQUEST_URI"], "admin") === false ? "active" : ""; ?>" href="index.php"><i class="fas fa-network-wired me-1"></i> Állapot Áttekintés</a></li><?php if (isset($_SESSION["is_admin"]) && $_SESSION["is_admin"]): ?><li class="nav-item dropdown"><a class="nav-link dropdown-toggle <?= strpos($_SERVER["REQUEST_URI"], "admin") !== false ? "active" : ""; ?>" href="#" role="button" data-bs-toggle="dropdown" aria-expanded="false"><i class="fas fa-tools me-1"></i> Adminisztráció</a><ul class="dropdown-menu"><li><a class="dropdown-item" href="admin_hosts.php"><i class="fas fa-server me-1"></i> Hosztok Kezelése</a></li><li><a class="dropdown-item" href="admin_users.php"><i class="fas fa-user-friends me-1"></i> Felhasználók Kezelése</a></li></ul></li><?php endif; ?></ul><div class="d-flex align-items-center"><span class="navbar-text me-3">Bejelentkezve: **<?= SecurityHelper::sanitizeInput($_SESSION["username"] ?? "Vendég"); ?>**</span><div class="dropdown me-2"><button class="btn btn-sm btn-outline-secondary dropdown-toggle" type="button" id="themeDropdown" data-bs-toggle="dropdown" aria-expanded="false"><i class="fas fa-palette me-1"></i> Téma</button><ul class="dropdown-menu dropdown-menu-end" aria-labelledby="themeDropdown"><?php foreach ($available_themes as $theme_key => $theme_name): ?><li><form method="POST" class="d-inline"><input type="hidden" name="set_theme" value="<?= $theme_key; ?>"><button type="submit" class="dropdown-item <?= ($current_theme == $theme_key) ? "active" : ""; ?>"><?= $theme_name; ?></button></form></li><?php endforeach; ?></ul></div><a href="?logout=1" class="btn btn-sm btn-danger"><i class="fas fa-sign-out-alt"></i> Kijelentkezés</a></div></div></div></nav><div class="container mt-4">
    <?php
}

function show_footer() {
    ?>
    </div><footer class="mt-5 py-3 bg-body-tertiary text-center text-muted shadow-sm"><p class="mb-0">Készítette: DevOFALL (gcsipai) | Server-Monitor &copy; <?= date("Y"); ?></p></footer><script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script></body></html>
    <?php
}
EOF

# -- Fájltartalom: admin_hosts.php --
cat << 'EOF' | sudo tee "$TARGET_DIR/admin_hosts.php" > /dev/null
<?php
require_once "auth.php"; 
require_auth();

if (!isset($_SESSION["is_admin"]) || !$_SESSION["is_admin"]) { header("Location: index.php"); exit(); }

global $pdo, $hostRepository, $monitoringService; 
use App\Security\SecurityHelper;

$message = "";
$edit_host = null;
$current_user_id = $_SESSION["user_id"] ?? null;

if (isset($_POST["action"])) {
    if (!isset($_POST['csrf_token']) || !SecurityHelper::verifyCsrfToken($_POST['csrf_token'])) { $message = "danger|CSRF hiba."; goto skip_db_op; }
    $action = $_POST["action"];
    $name = SecurityHelper::sanitizeInput($_POST["name"] ?? "");
    $ip_address = SecurityHelper::sanitizeInput($_POST["ip_address"] ?? "");
    $port_input = $_POST["port"] ?? "";
    $port = empty(trim($port_input)) ? null : (int)trim($port_input);
    $description = SecurityHelper::sanitizeInput($_POST["description"] ?? "");

    if ($action != "delete" && (empty($name) || empty($ip_address))) { $message = "danger|A hoszt neve és IP címe kötelező."; goto skip_db_op; }
    if ($action != "delete" && !SecurityHelper::validateIp($ip_address)) { $message = "danger|Hibás IP cím formátum."; goto skip_db_op; }
    if ($action != "delete" && !SecurityHelper::validatePort($port)) { $message = "danger|Hibás portszám."; goto skip_db_op; }

    try {
        if ($action == "add") {
            $hostRepository->create($name, $ip_address, $port, $description);
            $message = "success|Hoszt sikeresen hozzáadva.";
            log_audit($pdo, "HOST_ADD", "Új hoszt hozzáadva: $name ($ip_address:$port)", $current_user_id);
        } elseif ($action == "edit" && isset($_POST["id"])) {
            $hostRepository->update((int)$_POST["id"], $name, $ip_address, $port, $description);
            $message = "success|Hoszt sikeresen frissítve.";
            log_audit($pdo, "HOST_EDIT", "Hoszt (ID: {$_POST["id"]}) frissítve: $name ($ip_address:$port)", $current_user_id);
        } elseif ($action == "delete" && isset($_POST["id"])) {
            $id_to_delete = (int)$_POST["id"];
            $hostRepository->delete($id_to_delete);
            $message = "success|Hoszt törölve.";
            log_audit($pdo, "HOST_DELETE", "Hoszt (ID: $id_to_delete) törölve.", $current_user_id);
        }
        
        $monitoringService->clearCache();
        header("Location: admin_hosts.php?msg=" . urlencode($message)); exit();
    } catch (\PDOException $e) { $message = "danger|Adatbázis hiba: " . $e->getMessage(); }
    skip_db_op:
}

if (isset($_GET["msg"])) { $message = urldecode($_GET["msg"]); }
if (isset($_GET["edit"])) { $edit_host = $hostRepository->findById((int)$_GET["edit"]); }
$hosts = $hostRepository->findAll();
$csrf_token = SecurityHelper::generateCsrfToken();

show_header("Hosztok Kezelése");
?>

<h1><i class="fas fa-server me-2"></i> Hosztok Kezelése</h1>
<?php if ($message): list($type, $msg) = explode("|", $message); ?><div class="alert alert-<?= $type; ?>"><?= SecurityHelper::sanitizeInput($msg); ?></div><?php endif; ?>

<div class="row">
    <div class="col-md-4">
        <div class="card shadow-sm mb-4">
            <div class="card-header bg-primary text-white"><?= $edit_host ? "Hoszt szerkesztése" : "Új hoszt hozzáadása"; ?></div>
            <div class="card-body">
                <form method="POST">
                    <input type="hidden" name="csrf_token" value="<?= $csrf_token; ?>">
                    <input type="hidden" name="action" value="<?= $edit_host ? "edit" : "add"; ?>">
                    <?php if ($edit_host): ?><input type="hidden" name="id" value="<?= $edit_host["id"]; ?>"><?php endif; ?>
                    <div class="mb-3"><label class="form-label">Név/Szolgáltatás</label><input type="text" name="name" class="form-control" value="<?= SecurityHelper::sanitizeInput($edit_host["name"] ?? ""); ?>" required></div>
                    <div class="mb-3"><label class="form-label">IP cím</label><input type="text" name="ip_address" class="form-control" value="<?= SecurityHelper::sanitizeInput($edit_host["ip_address"] ?? ""); ?>" required></div>
                    <div class="mb-3"><label class="form-label">TCP Port (Hagyja üresen, ha csak Ping)</label><input type="number" name="port" class="form-control" value="<?= $edit_host["port"] ?? ""; ?>"></div>
                    <div class="mb-3"><label class="form-label">Leírás</label><textarea name="description" class="form-control"><?= SecurityHelper::sanitizeInput($edit_host["description"] ?? ""); ?></textarea></div>
                    <button type="submit" class="btn btn-<?= $edit_host ? "success" : "primary"; ?> w-100"><i class="fas fa-save"></i> Mentés</button>
                    <?php if ($edit_host): ?><a href="admin_hosts.php" class="btn btn-secondary mt-2 w-100">Mégsem</a><?php endif; ?>
                </form>
            </div>
        </div>
    </div>
    
    <div class="col-md-8">
        <table class="table table-striped shadow-sm">
            <thead class="table-dark"><tr><th>Név</th><th>IP</th><th>Port</th><th>Leírás</th><th>Műveletek</th></tr></thead>
            <tbody>
                <?php foreach ($hosts as $host): ?>
                <tr>
                    <td><?= SecurityHelper::sanitizeInput($host["name"]); ?></td>
                    <td><?= SecurityHelper::sanitizeInput($host["ip_address"]); ?></td>
                    <td><?= $host["port"] ?? "<span class=\"badge bg-info\">PING</span>"; ?></td>
                    <td><?= SecurityHelper::sanitizeInput($host["description"] ?? "N/A"); ?></td>
                    <td>
                        <a href="?edit=<?= $host["id"]; ?>" class="btn btn-sm btn-success me-2"><i class="fas fa-edit"></i> Szerkesztés</a>
                        <form method="POST" class="d-inline" onsubmit="return confirm('Biztosan törölni szeretné ezt a hoszt bejegyzést?');">
                            <input type="hidden" name="csrf_token" value="<?= $csrf_token; ?>">
                            <input type="hidden" name="action" value="delete">
                            <input type="hidden" name="id" value="<?= $host["id"]; ?>">
                            <button type="submit" class="btn btn-sm btn-danger"><i class="fas fa-trash"></i> Törlés</button>
                        </form>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>

<?php show_footer(); ?>
EOF

# -- Fájltartalom: admin_users.php --
cat << 'EOF' | sudo tee "$TARGET_DIR/admin_users.php" > /dev/null
<?php
require_once "auth.php"; 
require_auth();

if (!isset($_SESSION["is_admin"]) || !$_SESSION["is_admin"]) { header("Location: index.php"); exit(); }

global $pdo, $userRepository;
use App\Security\SecurityHelper;

$message = "";
$edit_user = null;
$current_user_id = $_SESSION["user_id"] ?? null;

if (isset($_POST["action"])) {
    if (!isset($_POST['csrf_token']) || !SecurityHelper::verifyCsrfToken($_POST['csrf_token'])) { $message = "danger|CSRF hiba."; goto skip_db_op; }
    $action = $_POST["action"];
    $username = SecurityHelper::sanitizeInput($_POST["username"] ?? "");
    $password = $_POST["password"] ?? ""; 
    $is_admin = isset($_POST["is_admin"]) ? true : false;
    
    if (empty($username)) { $message = "danger|A felhasználónév kötelező."; goto skip_db_op; }

    try {
        if ($action == "add") {
            if (empty($password)) { $message = "danger|A jelszó nem lehet üres."; goto skip_db_op; }
            if ($userRepository->userExists($username)) { $message = "danger|Ez a felhasználónév már létezik."; goto skip_db_op; }
            $userRepository->createUser($username, $password, $is_admin);
            $message = "success|Felhasználó sikeresen hozzáadva.";
            log_audit($pdo, "USER_ADD", "Új felhasználó hozzáadva: " . $username, $current_user_id);
            
        } elseif ($action == "edit" && isset($_POST["id"])) {
            $id = (int)$_POST["id"];
            if ($id == $current_user_id && !$is_admin && $userRepository->findById($id)['is_admin']) { $message = "danger|Nem távolíthatja el saját magától az admin jogosultságot."; goto skip_db_op; }
            
            $password_to_update = empty($password) ? null : $password;
            $userRepository->update($id, $username, $password_to_update, $is_admin);
            $message = "success|Felhasználó sikeresen frissítve.";
            log_audit($pdo, "USER_EDIT", "Felhasználó ($id) frissítve: " . $username, $current_user_id);

        } elseif ($action == "delete" && isset($_POST["id"])) {
            $id_to_delete = (int)$_POST["id"];
            if ($id_to_delete == $current_user_id) { $message = "danger|Saját magát nem törölheti!"; goto skip_db_op; }
            $userRepository->delete($id_to_delete);
            $message = "success|Felhasználó törölve.";
            log_audit($pdo, "USER_DELETE", "Felhasználó ($id_to_delete) törölve.", $current_user_id);
        }
        
        header("Location: admin_users.php?msg=" . urlencode($message)); exit();
    } catch (\PDOException $e) { $message = "danger|Adatbázis hiba: " . $e->getMessage(); }
    skip_db_op:
}

if (isset($_GET["msg"])) { $message = urldecode($_GET["msg"]); }
if (isset($_GET["edit"])) { $edit_user = $userRepository->findById((int)$_GET["edit"]); }
$users = $userRepository->findAll();
$csrf_token = SecurityHelper::generateCsrfToken();

show_header("Felhasználók Kezelése");
?>

<h1><i class="fas fa-user-friends me-2"></i> Felhasználók Kezelése</h1>
<?php if ($message): list($type, $msg) = explode("|", $message); ?><div class="alert alert-<?= $type; ?>"><?= SecurityHelper::sanitizeInput($msg); ?></div><?php endif; ?>

<div class="row">
    <div class="col-md-4">
        <div class="card shadow-sm mb-4">
            <div class="card-header bg-primary text-white"><?= $edit_user ? "Felhasználó szerkesztése" : "Új felhasználó hozzáadása"; ?></div>
            <div class="card-body">
                <form method="POST">
                    <input type="hidden" name="csrf_token" value="<?= $csrf_token; ?>">
                    <input type="hidden" name="action" value="<?= $edit_user ? "edit" : "add"; ?>">
                    <?php if ($edit_user): ?><input type="hidden" name="id" value="<?= $edit_user["id"]; ?>"><?php endif; ?>
                    <div class="mb-3"><label class="form-label">Felhasználónév</label><input type="text" name="username" class="form-control" value="<?= SecurityHelper::sanitizeInput($edit_user["username"] ?? ""); ?>" required></div>
                    <div class="mb-3"><label class="form-label">Jelszó <?= $edit_user ? " (Hagyja üresen, ha nem változik)" : ""; ?></label><input type="password" name="password" class="form-control" <?= $edit_user ? "" : "required"; ?>></div>
                    <div class="form-check mb-3"><input class="form-check-input" type="checkbox" name="is_admin" value="1" id="is_admin" <?= ($edit_user && $edit_user["is_admin"]) ? "checked" : ""; ?> <?= ($edit_user && $edit_user["id"] == $_SESSION["user_id"]) ? "disabled" : ""; ?>><label class="form-check-label" for="is_admin">Adminisztrátor</label></div>
                    <button type="submit" class="btn btn-<?= $edit_user ? "success" : "primary"; ?> w-100"><i class="fas fa-save"></i> Mentés</button>
                    <?php if ($edit_user): ?><a href="admin_users.php" class="btn btn-secondary mt-2 w-100">Mégsem</a><?php endif; ?>
                </form>
            </div>
        </div>
    </div>
    
    <div class="col-md-8">
        <table class="table table-striped shadow-sm">
            <thead class="table-dark"><tr><th>ID</th><th>Felhasználónév</th><th>Admin</th><th>Műveletek</th></tr></thead>
            <tbody>
                <?php foreach ($users as $user): ?>
                <tr>
                    <td><?= $user["id"]; ?></td>
                    <td><?= SecurityHelper::sanitizeInput($user["username"]); ?></td>
                    <td><?= $user["is_admin"] ? "<span class=\"badge bg-danger\">IGEN</span>" : "NEM"; ?></td>
                    <td>
                        <a href="?edit=<?= $user["id"]; ?>" class="btn btn-sm btn-success me-2"><i class="fas fa-edit"></i> Szerkesztés</a>
                        <?php if ($user["id"] != $_SESSION["user_id"]): ?>
                        <form method="POST" class="d-inline" onsubmit="return confirm('Biztosan törölni szeretné ezt a felhasználót?');">
                            <input type="hidden" name="csrf_token" value="<?= $csrf_token; ?>">
                            <input type="hidden" name="action" value="delete">
                            <input type="hidden" name="id" value="<?= $user["id"]; ?>">
                            <button type="submit" class="btn btn-sm btn-danger"><i class="fas fa-trash"></i> Törlés</button>
                        </form>
                        <?php endif; ?>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>

<?php show_footer(); ?>
EOF

# -- Fájltartalom: assets/css/themes.php --
cat << 'EOF' | sudo tee "$TARGET_DIR/assets/css/themes.php" > /dev/null
<?php
// Dinamikus CSS generálás a témákhoz
header('Content-Type: text/css');

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

$current_theme = $_SESSION['theme'] ?? 'light';

$themes = [
    'light' => [],
    'dark' => [],
    'primary' => [
        '--bs-body-bg' => 'var(--bs-primary-bg-subtle)',
        '--bs-body-color' => 'var(--bs-primary-text-emphasis)',
        '--bs-navbar-bg' => 'var(--bs-primary-bg-subtle)',
    ],
    'success' => [
        '--bs-body-bg' => 'var(--bs-success-bg-subtle)',
        '--bs-body-color' => 'var(--bs-success-text-emphasis)',
        '--bs-navbar-bg' => 'var(--bs-success-bg-subtle)',
    ],
    'info' => [
        '--bs-body-bg' => 'var(--bs-info-bg-subtle)',
        '--bs-body-color' => 'var(--bs-info-text-emphasis)',
        '--bs-navbar-bg' => 'var(--bs-info-bg-subtle)',
    ],
    'warning' => [
        '--bs-body-bg' => 'var(--bs-warning-bg-subtle)',
        '--bs-body-color' => 'var(--bs-warning-text-emphasis)',
        '--bs-navbar-bg' => 'var(--bs-warning-bg-subtle)',
    ],
    'danger' => [
        '--bs-body-bg' => 'var(--bs-danger-bg-subtle)',
        '--bs-body-color' => 'var(--bs-danger-text-emphasis)',
        '--bs-navbar-bg' => 'var(--bs-danger-bg-subtle)',
    ]
];

$theme = $themes[$current_theme] ?? $themes['light'];

if ($current_theme !== 'light' && $current_theme !== 'dark') {
    echo ":root {\n";
    foreach ($theme as $variable => $value) {
        echo "  {$variable}: {$value};\n";
    }
    echo "}\n";
    
    echo ".bg-body-tertiary {\n";
    echo "  background-color: var(--bs-navbar-bg) !important;\n";
    echo "}\n";
    echo "body {\n";
    echo "  background-color: var(--bs-body-bg) !important;\n";
    echo "  color: var(--bs-body-color) !important;\n";
    echo "}\n";
}
EOF

# -- Fájltartalom: src/Cache/CacheManager.php --
cat << 'EOF' | sudo tee "$TARGET_DIR/src/Cache/CacheManager.php" > /dev/null
<?php
namespace App\Cache;

class CacheManager
{
    private string $cacheDir;

    public function __construct()
    {
        $this->cacheDir = __DIR__ . '/../../cache/';
        if (!is_dir($this->cacheDir)) {
            mkdir($this->cacheDir, 0777, true);
        }
    }

    private function getCacheFilePath(string $key): string
    {
        return $this->cacheDir . md5($key) . '.cache';
    }

    public function has(string $key): bool
    {
        $filePath = $this->getCacheFilePath($key);
        if (!file_exists($filePath)) {
            return false;
        }
        
        $content = file_get_contents($filePath);
        $data = json_decode($content, true);

        if ($data === null || !isset($data['expires']) || $data['expires'] < time()) {
            $this->delete($key);
            return false;
        }

        return true;
    }

    public function get(string $key)
    {
        if (!$this->has($key)) {
            return null;
        }
        
        $filePath = $this->getCacheFilePath($key);
        $content = file_get_contents($filePath);
        $data = json_decode($content, true);

        return $data['data'] ?? null;
    }

    public function set(string $key, $value, int $ttl = 300): bool
    {
        $filePath = $this->getCacheFilePath($key);
        $data = [
            'data' => $value,
            'expires' => time() + $ttl
        ];
        
        return file_put_contents($filePath, json_encode($data), LOCK_EX) !== false;
    }

    public function delete(string $key): bool
    {
        $filePath = $this->getCacheFilePath($key);
        if (file_exists($filePath)) {
            return unlink($filePath);
        }
        return true;
    }
}
EOF

# -- Fájltartalom: src/Config/Config.php --
cat << 'EOF' | sudo tee "$TARGET_DIR/src/Config/Config.php" > /dev/null
<?php
namespace App\Config;

class Config
{
    private static $instance = null;
    private $config = [];

    private function __construct()
    {
        $this->loadEnv();
    }

    public static function getInstance(): self
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function loadEnv(): void
    {
        $envFile = __DIR__ . '/../../.env';
        if (!file_exists($envFile)) {
            // Nem dobunk kivételt, hogy az autoload.php le tudja kezelni
            throw new \RuntimeException('.env file not found');
        }

        $lines = file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach ($lines as $line) {
            if (strpos(trim($line), '#') === 0) {
                continue;
            }
            
            if (strpos($line, '=') === false) {
                continue;
            }

            list($key, $value) = explode('=', $line, 2);
            $this->config[trim($key)] = trim($value, " \t\n\r\0\x0B\"'");
        }
    }

    public function get(string $key, $default = null)
    {
        return $this->config[$key] ?? $default;
    }

    public function isProduction(): bool
    {
        return $this->get('APP_ENV') === 'production';
    }
}
EOF

# -- Fájltartalom: src/Repository/HostRepository.php --
cat << 'EOF' | sudo tee "$TARGET_DIR/src/Repository/HostRepository.php" > /dev/null
<?php
namespace App\Repository;

use PDO;

class HostRepository
{
    private PDO $pdo;

    public function __construct(PDO $pdo)
    {
        $this->pdo = $pdo;
    }

    public function findAll(): array
    {
        $stmt = $this->pdo->query("SELECT id, name, ip_address, port, description FROM hosts ORDER BY ip_address, port");
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public function findById(int $id): ?array
    {
        $stmt = $this->pdo->prepare("SELECT id, name, ip_address, port, description FROM hosts WHERE id = ?");
        $stmt->execute([$id]);
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

    public function create(string $name, string $ipAddress, ?int $port, string $description): bool
    {
        $stmt = $this->pdo->prepare("INSERT INTO hosts (name, ip_address, port, description) VALUES (?, ?, ?, ?)");
        return $stmt->execute([$name, $ipAddress, $port, $description]);
    }

    public function update(int $id, string $name, string $ipAddress, ?int $port, string $description): bool
    {
        $stmt = $this->pdo->prepare("UPDATE hosts SET name = ?, ip_address = ?, port = ?, description = ? WHERE id = ?");
        return $stmt->execute([$name, $ipAddress, $port, $description, $id]);
    }

    public function delete(int $id): bool
    {
        $stmt = $this->pdo->prepare("DELETE FROM hosts WHERE id = ?");
        return $stmt->execute([$id]);
    }
}
EOF

# -- Fájltartalom: src/Repository/UserRepository.php --
cat << 'EOF' | sudo tee "$TARGET_DIR/src/Repository/UserRepository.php" > /dev/null
<?php
namespace App\Repository;

use PDO;

class UserRepository
{
    private PDO $pdo;

    public function __construct(PDO $pdo)
    {
        $this->pdo = $pdo;
    }

    public function findByUsername(string $username): ?array
    {
        $stmt = $this->pdo->prepare("
            SELECT id, username, password_hash, is_admin 
            FROM users 
            WHERE username = :username
        ");
        $stmt->execute(['username' => $username]);
        
        return $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
    }

    public function createUser(string $username, string $password, bool $isAdmin = false): bool
    {
        $hash = password_hash($password, PASSWORD_DEFAULT);
        
        $stmt = $this->pdo->prepare("
            INSERT INTO users (username, password_hash, is_admin) 
            VALUES (:username, :password_hash, :is_admin)
        ");
        
        return $stmt->execute([
            'username' => $username,
            'password_hash' => $hash,
            'is_admin' => $isAdmin ? 1 : 0
        ]);
    }

    public function userExists(string $username): bool
    {
        $stmt = $this->pdo->prepare("SELECT COUNT(*) FROM users WHERE username = :username");
        $stmt->execute(['username' => $username]);
        
        return $stmt->fetchColumn() > 0;
    }

    public function findAll(): array
    {
        $stmt = $this->pdo->query("SELECT id, username, is_admin FROM users ORDER BY username");
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public function findById(int $id): ?array
    {
        $stmt = $this->pdo->prepare("SELECT id, username, is_admin FROM users WHERE id = ?");
        $stmt->execute([$id]);
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

    public function update(int $id, string $username, ?string $password, bool $isAdmin): bool
    {
        $sql = "UPDATE users SET username = :username, is_admin = :is_admin";
        $params = ['username' => $username, 'is_admin' => $isAdmin ? 1 : 0, 'id' => $id];

        if (!empty($password)) {
            $sql .= ", password_hash = :password_hash";
            $params['password_hash'] = password_hash($password, PASSWORD_DEFAULT);
        }
        
        $sql .= " WHERE id = :id";
        $stmt = $this->pdo->prepare($sql);
        
        return $stmt->execute($params);
    }

    public function delete(int $id): bool
    {
        $stmt = $this->pdo->prepare("DELETE FROM users WHERE id = ?");
        return $stmt->execute([$id]);
    }
}
EOF

# -- Fájltartalom: src/Security/SecurityHelper.php --
cat << 'EOF' | sudo tee "$TARGET_DIR/src/Security/SecurityHelper.php" > /dev/null
<?php
namespace App\Security;

class SecurityHelper
{
    public static function sanitizeInput($input)
    {
        if (is_array($input)) {
            return array_map([self::class, 'sanitizeInput'], $input);
        }
        
        return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
    }

    public static function validateIp(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP) !== false;
    }

    public static function validatePort($port): bool
    {
        if ($port === null || $port === '') {
            return true;
        }
        
        $port = (int)$port;
        return $port >= 1 && $port <= 65535;
    }

    public static function generateCsrfToken(): string
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        
        if (empty($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        }
        
        return $_SESSION['csrf_token'];
    }

    public static function verifyCsrfToken(string $token): bool
    {
        if (session_status() === PHP_SESSION_NONE) {
             session_start();
        }

        return isset($_SESSION['csrf_token']) && 
               hash_equals($_SESSION['csrf_token'], $token);
    }
}
EOF

# -- Fájltartalom: src/Service/MonitoringService.php --
cat << 'EOF' | sudo tee "$TARGET_DIR/src/Service/MonitoringService.php" > /dev/null
<?php
namespace App\Service;

use App\Repository\HostRepository;
use App\Cache\CacheManager;

class MonitoringService
{
    private HostRepository $hostRepository;
    private CacheManager $cache;
    private int $cacheDuration;

    public function __construct(HostRepository $hostRepository, CacheManager $cache)
    {
        $this->hostRepository = $hostRepository;
        $this->cache = $cache;
        $this->cacheDuration = 300; // Alapértelmezett 5 perc
    }
    
    public function getCacheDuration(): int
    {
        return $this->cacheDuration;
    }

    public function getMonitoringResults(): array
    {
        $cacheKey = 'monitoring_results';
        
        if ($this->cache->has($cacheKey)) {
            return $this->cache->get($cacheKey);
        }

        $hosts = $this->hostRepository->findAll();
        $hosts_grouped = $this->groupHostsByIp($hosts);
        $results = [];

        $last_checked_time = time();

        foreach ($hosts_grouped as $ip => $data) {
            $check_results = $this->checkHostStatus($ip, $data["services"]);
            
            $data["ping_status"] = $check_results["ping"];
            
            foreach ($data["services"] as $index => $service) {
                $port_key = $service["port"] === null ? "ping_only" : $service["port"];
                $data["services"][$index]["status"] = $check_results["services"][$port_key] ?? ["status" => "N/A", "badge" => "secondary", "icon" => "fa-question"];
            }
            
            $data["last_checked"] = $last_checked_time;
            $results[$ip] = $data;
        }

        $this->cache->set($cacheKey, $results, $this->cacheDuration);
        
        return $results;
    }

    public function clearCache(): void
    {
        $this->cache->delete('monitoring_results');
    }

    private function groupHostsByIp(array $hosts): array
    {
        $hosts_grouped = [];
        foreach ($hosts as $row) {
            $ip = $row["ip_address"];
            if (!isset($hosts_grouped[$ip])) {
                $hosts_grouped[$ip] = [
                    "ip" => $ip,
                    "services" => [],
                    "ping_status" => null
                ];
            }
            $service_name = $row["port"] === null ? 
                $row["name"] . " (Ping Only)" : 
                $row["name"] . " (Port " . $row["port"] . ")";
            
            $hosts_grouped[$ip]["services"][] = [
                "id" => $row["id"],
                "name" => $row["name"],
                "port" => $row["port"],
                "description" => $row["description"],
                "service_name" => $service_name,
                "status" => null
            ];
        }
        return $hosts_grouped;
    }

    private function checkHostStatus(string $ip, array $services): array
    {
        $host_status = ["ping" => ["status" => "N/A", "badge" => "secondary", "icon" => "fa-question"], "services" => []];

        $host_status["ping"] = $this->checkPing($ip);
        
        foreach ($services as $service_data) {
            $port = $service_data["port"];
            $key = $port === null ? "ping_only" : $port;
            
            if ($port === null) {
                $host_status["services"][$key] = $host_status["ping"];
                continue; 
            }
            
            if (!is_numeric($port) || $port < 1 || $port > 65535) {
                $host_status["services"][$key] = ["status" => "INVALID PORT", "badge" => "warning", "icon" => "fa-exclamation-triangle"];
                continue;
            }
            
            $host_status["services"][$key] = $this->checkPort($ip, (int)$port, $host_status["ping"]["status"]);
        }

        return $host_status;
    }

    private function checkPing(string $ip): array
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return ["status" => "INVALID IP", "badge" => "warning", "icon" => "fa-exclamation-triangle"];
        }

        $is_windows = strtoupper(substr(PHP_OS, 0, 3)) === "WIN";
        $ping_command = $is_windows ? 
            "ping -n 1 -w 1000 " . escapeshellarg($ip) : 
            "ping -c 1 -W 1 " . escapeshellarg($ip);    
        
        $ping_output = shell_exec($ping_command . " 2>&1"); 

        if (strpos($ping_output, "1 received") !== false || 
            strpos($ping_output, "bytes from") !== false ||
            ($is_windows && strpos($ping_output, "TTL=") !== false)) {
            return ["status" => "UP", "badge" => "success", "icon" => "fa-arrow-up"];
        } else {
            return ["status" => "DOWN", "badge" => "danger", "icon" => "fa-arrow-down"];
        }
    }

    private function checkPort(string $ip, int $port, string $pingStatus): array
    {
        $timeout = 2; 
        $fp = @fsockopen($ip, $port, $errno, $errstr, $timeout);
        
        if ($fp) {
            fclose($fp);
            return ["status" => "OK", "badge" => "success", "icon" => "fa-check"];
        } else {
            if ($pingStatus === "DOWN") {
                return ["status" => "CRITICAL (Ping DOWN)", "badge" => "danger", "icon" => "fa-times-circle"];
            } else {
                return ["status" => "CRITICAL (Port Zárva/Timeout)", "badge" => "danger", "icon" => "fa-times"];
            }
        }
    }
}
EOF

# ----------------------------------------------
# 3. JOGOSULTSÁGOK BEÁLLÍTÁSA
# ----------------------------------------------

echo "🔒 Jogosultságok beállítása..."
CHOWN_DIR="$TARGET_DIR"

# Kísérlet a webkiszolgáló felhasználójának megállapítására
WEB_USER=$(ps aux | grep -E '[a]pache|[h]ttpd|[_]www|[w]ww-data' | grep -v root | head -1 | awk '{print $1}')

# Ha nem találja, beállítunk egy alapértelmezettet
if [ -z "$WEB_USER" ]; then
    if id "www-data" &>/dev/null; then
        WEB_USER="www-data"
    elif id "apache" &>/dev/null; then
        WEB_USER="apache"
    elif id "httpd" &>/dev/null; then
        WEB_USER="httpd"
    else
        echo "⚠️ FIGYELMEZTETÉS: Nem sikerült azonosítani a webkiszolgáló felhasználóját."
        echo "   Kérjük, manuálisan állítsa be a jogosultságot: sudo chown -R <web_user>:<web_group> $TARGET_DIR"
        WEB_USER=""
    fi
fi

if [ -n "$WEB_USER" ]; then
    echo "   Tulajdonos beállítása a '$WEB_USER' felhasználóra a teljes mappára."
    sudo chown -R $WEB_USER:$WEB_USER "$CHOWN_DIR"
    echo "   Írási jogosultság beállítása a cache és log mappákra."
    # Ezzel biztosítjuk, hogy a webkiszolgáló tudjon írni a cache és log mappákba (775 a csoport számára is engedélyez)
    sudo chmod -R 775 "$TARGET_DIR/cache"
    sudo chmod -R 775 "$TARGET_DIR/log"
    echo "   Kész."
else
    echo "❌ JOGOSULTSÁG HIBA: Nem sikerült a jogosultságokat beállítani. A webkiszolgáló nem fog tudni írni a cache/ és log/ mappákba."
fi

echo "✅ Telepítés befejezve a **$TARGET_DIR** könyvtárba."
echo "➡️ **Következő lépés:** Nyissa meg a böngészőben: **http://localhost/server-monitor/install.php** (vagy az IP-címet/domain nevet, ha távolról telepít)."
