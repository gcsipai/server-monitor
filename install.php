<?php
// PHP hibaüzenetek megjelenítése a hibakereséshez
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Függvény a beállítások mentésére a config.php-ba
function save_config($host, $user, $pass, $name) {
    $content = <<<PHP
<?php
// PROJECT NÉV: Server-Monitor
// Készítette: DevOFALL (gcsipai)

// ---------------------------------------------
// 1. Biztonsági és Munkamenet Beállítások
// ---------------------------------------------
ini_set('session.cookie_httponly', 1);
ini_set('session.use_strict_mode', 1);
ini_set('session.cookie_secure', (isset(\$_SERVER['HTTPS']) && \$_SERVER['HTTPS'] === 'on'));
ini_set('session.cookie_samesite', 'Lax');

// Fejlesztési vagy éles mód
define('ENVIRONMENT', 'development'); 

if (ENVIRONMENT === 'production') {
    ini_set('display_errors', 0);
    ini_set('log_errors', 1);
    error_reporting(0);
} else {
    ini_set('display_errors', 1);
    ini_set('display_startup_errors', 1);
    error_reporting(E_ALL);
}

// Alapvető konfiguráció
define('PROJECT_NAME', 'Server-Monitor');
define('VERSION', '1.0.0');

// ---------------------------------------------
// 2. Adatbázis konfiguráció
// ---------------------------------------------
define('DB_HOST', '$host');
define('DB_USER', '$user');
define('DB_PASS', '$pass'); 
define('DB_NAME', '$name');

// Kezdeti admin adatok
define('DEFAULT_ADMIN_USER', 'admin');
define('DEFAULT_ADMIN_PASS', 'admin');

// Munkamenet indítása
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// ---------------------------------------------
// 3. Adatbázis Kapcsolat és Admin Inicializálás
// ---------------------------------------------
try {
    \$pdo = new PDO("mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4", DB_USER, DB_PASS);
    \$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    \$pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    \$pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES, false); 
} catch (PDOException \$e) {
    error_log("Adatbázis kapcsolat hiba: " . \$e->getMessage());
    if (ENVIRONMENT === 'development') {
        die("Adatbázis kapcsolat hiba: " . \$e->getMessage());
    } else {
        die("Adatbázis hiba. Kérjük, próbálja később.");
    }
}

// Alapértelmezett admin felhasználó inicializálása
try {
    \$stmt = \$pdo->prepare("SELECT COUNT(*) FROM users WHERE username = :user");
    \$stmt->execute(['user' => DEFAULT_ADMIN_USER]);
    if (\$stmt->fetchColumn() == 0) {
        \$hash = password_hash(DEFAULT_ADMIN_PASS, PASSWORD_DEFAULT);
        \$stmt = \$pdo->prepare("INSERT INTO users (username, password_hash, is_admin) VALUES (:user, :hash, 1)");
        \$stmt->execute(['user' => DEFAULT_ADMIN_USER, 'hash' => \$hash]);
    }
} catch (PDOException \$e) {
    error_log("Admin felhasználó inicializálási hiba: " . \$e->getMessage());
}
?>
PHP;
    // file_put_contents használata a tényleges íráshoz
    if (file_put_contents('config.php', $content)) {
        // Sikeres írás után állítsuk be a biztonságos jogosultságot 
        chmod('config.php', 0644); 
        return true;
    }
    return false;
}

// SQL parancsok a táblák létrehozásához és a kezdeti adatokhoz
$sql_schema = [
    // 1. Felhasználói tábla
    "CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) NOT NULL UNIQUE,
        password_hash VARCHAR(255) NOT NULL,
        is_admin BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );",
    // 2. Hosztok táblája
    "CREATE TABLE IF NOT EXISTS hosts (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        ip_address VARCHAR(45) NOT NULL,
        port INT NULL, 
        description VARCHAR(255) NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );",
    // 3. Naplózási tábla (Audit Log)
    "CREATE TABLE IF NOT EXISTS audit_log (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NULL,
        action VARCHAR(100) NOT NULL,
        description TEXT,
        ip_address VARCHAR(45),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
    );"
    // Eltávolítottam a kezdeti hosztok beszúrását
];

$message = '';
$error = '';
$step = 1;

// Ellenőrizzük, hogy a config.php már létezik-e (Javított logika)
if (file_exists('config.php')) {
    try {
        // Ellenőrizzük az aktív adatbázis kapcsolatot a meglévő config.php alapján
        include 'config.php';
        $test_stmt = $pdo->query("SELECT 1"); 
        $message = "success|A **config.php** már létezik és az adatbázis kapcsolat aktív. Ha újra szeretné telepíteni, **törölje** a config.php fájlt!";
        $step = 2; 
    } catch (Exception $e) {
        $error = "A config.php fájl létezik, de az adatbázis kapcsolat hibás: " . $e->getMessage() . ". Kérjük, törölje a config.php fájlt, és próbálja újra.";
        $step = 1; 
    }
}

// POST kérés feldolgozása
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $step === 1) { 
    $db_host = $_POST['db_host'] ?? '';
    $db_user = $_POST['db_user'] ?? '';
    $db_pass = $_POST['db_pass'] ?? '';
    $db_name = $_POST['db_name'] ?? '';

    // Validáció
    if (empty($db_host) || empty($db_user) || empty($db_name)) {
        $error = "Minden mező kitöltése kötelező, kivéve a jelszót!";
    } else {
        try {
            // 1. Kapcsolódás a MySQL/MariaDB-hez az adatbázis NÉLKÜL
            $pdo_conn = new PDO("mysql:host=$db_host", $db_user, $db_pass);
            $pdo_conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

            // 2. Adatbázis létrehozása, ha nem létezik
            $pdo_conn->exec("CREATE DATABASE IF NOT EXISTS `$db_name` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;");
            $message .= "Adatbázis ($db_name) sikeresen létrehozva vagy ellenőrizve.<br>";
            
            // 3. Kapcsolódás az újonnan létrehozott/ellenőrzött adatbázishoz
            $pdo_db = new PDO("mysql:host=$db_host;dbname=$db_name", $db_user, $db_pass);
            $pdo_db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

            // 4. Táblák létrehozása
            foreach ($sql_schema as $sql) {
                $pdo_db->exec($sql);
            }
            $message .= "Táblák sikeresen létrehozva.<br>";

            // 5. Konfigurációs fájl mentése
            if (save_config($db_host, $db_user, $db_pass, $db_name)) {
                $message .= "A **config.php** sikeresen létrehozva.<br><br>";
                $message = "success|" . $message;
                $step = 2;
                // A Bash szkript fogja beállítani a végső jogosultságot.
            } else {
                // Itt van a kritikus hiba: Nem sikerült a fájlírás.
                $error = "Hiba: Nem sikerült létrehozni a config.php fájlt. Ellenőrizze a fájl írási jogosultságokat!";
            }

        } catch (PDOException $e) {
            $error = "Adatbázis hiba: " . $e->getMessage();
        }
    }
}

// Telepítő törlése kérésre (AJAX hívásból)
if (isset($_GET['delete_installer']) && $step == 2) {
    header('Content-Type: application/json');
    if (unlink(__FILE__)) {
        echo json_encode(['success' => true]);
    } else {
        echo json_encode(['success' => false, 'error' => 'Törlési hiba.']);
    }
    exit;
}
?>
<!DOCTYPE html>
<html lang="hu">
<head>
    <meta charset="UTF-8">
    <title>Server-Monitor Telepítés</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">
</head>
<body class="bg-dark text-light">
    <div class="container py-5">
        <div class="card p-5 shadow-lg bg-light text-dark">
            <h1 class="card-title text-center mb-4"><i class="fas fa-tools me-2"></i> Server-Monitor Telepítés</h1>
            
            <?php if ($error): ?>
                <div class="alert alert-danger"><i class="fas fa-exclamation-triangle me-2"></i> <?= $error; ?></div>
            <?php endif; ?>

            <?php if ($message): 
                // Csak akkor próbáljuk meg felosztani, ha tartalmazza az elválasztót
                if (strpos($message, '|') !== false) {
                    list($type, $msg) = explode('|', $message, 2);
                } else {
                    $type = 'warning'; // Ha a telepítés meghiúsul, de van üzenet
                    $msg = $message;
                }
            ?>
                <div class="alert alert-<?= $type; ?>"><?= $msg; ?></div>
            <?php endif; ?>

            <?php if ($step == 1): ?>
                <p class="lead">Kérjük, adja meg a MySQL/MariaDB adatbázis adatait. (A felhasználónak rendelkeznie kell adatbázis létrehozási joggal!)</p>
                <form method="POST">
                    <div class="mb-3">
                        <label class="form-label">Adatbázis Szerver (Host)</label>
                        <input type="text" name="db_host" class="form-control" value="<?= $_POST['db_host'] ?? 'localhost'; ?>" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Adatbázis Neve</label>
                        <input type="text" name="db_name" class="form-control" value="<?= $_POST['db_name'] ?? 'server_monitor_db'; ?>" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Adatbázis Felhasználó</label>
                        <input type="text" name="db_user" class="form-control" value="<?= $_POST['db_user'] ?? ''; ?>" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Adatbázis Jelszó</label>
                        <input type="password" name="db_pass" class="form-control">
                    </div>
                    <button type="submit" class="btn btn-primary w-100"><i class="fas fa-cogs me-2"></i> Telepítés indítása</button>
                </form>

            <?php elseif ($step == 2): ?>
                <div class="alert alert-success">
                    <h4 class="alert-heading">Telepítés sikeresen befejeződött!</h4>
                    <p>Az alapértelmezett bejelentkezési adatok:</p>
                    <ul>
                        <li>**Felhasználónév:** `admin`</li>
                        <li>**Jelszó:** `admin`</li>
                    </ul>
                    <p>A hoszt lista üres, az adminisztrációs felületen adhat hozzá hosztokat.</p>
                    <hr>
                    <p class="mb-0 text-danger">⚠️ **BIZTONSÁGI FIGYELMEZTETÉS:** Erősen ajánlott az **`install.php`** fájl azonnali **törlése** a szerverről!</p>
                </div>
                <a href="index.php" class="btn btn-success w-100"><i class="fas fa-sign-in-alt me-2"></i> Tovább a Server-Monitorhoz</a>
                
                <script>
                    setTimeout(function() {
                        if(confirm('Ajánlott a telepítő fájl törlése a biztonság érdekében. Szeretné most törölni?')) {
                            fetch('?delete_installer=1')
                                .then(response => response.json())
                                .then(data => {
                                    if(data.success) {
                                        alert('Telepítő sikeresen törölve! Kérjük, frissítsen.');
                                    } else {
                                        alert('Törlés sikertelen. Kérjük, manuálisan törölje az install.php fájlt!');
                                    }
                                });
                        }
                    }, 3000);
                </script>
            <?php endif; ?>
        </div>
    </div>
</body>
</html>
