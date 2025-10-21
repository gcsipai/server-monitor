<?php
session_start();
// Ellenőrizzük, hogy a config.php létezik-e, különben átirányítunk a telepítőre
if (!file_exists('config.php')) {
    header('Location: install.php');
    exit();
}
require_once 'config.php'; 
require_once 'monitor_logic.php'; // log_audit miatt

// Támogatott Bootstrap témák (színek)
$available_themes = [
    'light' => 'Világos (Light)',
    'dark' => 'Sötét (Dark)',
    'primary' => 'Kék (Primary)',
    'success' => 'Zöld (Success)',
    'info' => 'Ciánkék (Info)',
    'warning' => 'Sárga (Warning)',
    'danger' => 'Piros (Danger)'
];

// Témaváltás POST kéréssel
if (isset($_POST['set_theme']) && array_key_exists($_POST['set_theme'], $available_themes)) {
    $_SESSION['theme'] = $_POST['set_theme'];
    header('Location: ' . $_SERVER['PHP_SELF']); 
    exit();
}

// Kijelentkezés
if (isset($_GET['logout'])) {
    // Naplózás
    log_audit($pdo, 'LOGOUT', 'Felhasználó kijelentkezett', $_SESSION['user_id'] ?? null);
    
    session_destroy();
    header('Location: index.php');
    exit();
}

// Bejelentkezés
if (isset($_POST['login'])) {
    $username = $_POST['username'];
    $password = $_POST['password'];

    $stmt = $pdo->prepare("SELECT id, username, password_hash, is_admin FROM users WHERE username = :user");
    $stmt->execute(['user' => $username]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user && password_verify($password, $user['password_hash'])) {
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['is_admin'] = $user['is_admin'];
        $_SESSION['theme'] = $_SESSION['theme'] ?? 'light'; // Megtartjuk a témát, ha már van
        
        // Naplózás
        log_audit($pdo, 'LOGIN_SUCCESS', 'Sikeres bejelentkezés', $user['id']);
        
        header('Location: index.php');
        exit();
    } else {
        $login_error = "Hibás felhasználónév vagy jelszó.";
        // Naplózás
        log_audit($pdo, 'LOGIN_FAILURE', 'Sikertelen bejelentkezési kísérlet: ' . $username, null);
    }
}

// Hitelesítés kikényszerítése
function require_auth() {
    if (!isset($_SESSION['user_id'])) {
        show_login_form();
        exit();
    }
}

// Bejelentkező űrlap
function show_login_form($error = null) {
    global $login_error;
    $error = $error ?? $login_error;
    ?>
    <!DOCTYPE html>
    <html lang="hu">
    <head>
        <meta charset="UTF-8">
        <title>Server-Monitor Belépés</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">
    </head>
    <body class="bg-light">
        <div class="container d-flex justify-content-center align-items-center" style="min-height: 100vh;">
            <div class="card p-4 shadow-lg" style="width: 380px;">
                <h3 class="card-title text-center mb-4"><i class="fas fa-lock me-2"></i> Server-Monitor Belépés</h3>
                <p class="text-center text-muted">Készítette: DevOFALL (gcsipai)</p>
                <form method="POST">
                    <input type="hidden" name="login" value="1">
                    <div class="mb-3">
                        <label for="username" class="form-label">Felhasználónév</label>
                        <input type="text" class="form-control" id="username" name="username" required>
                    </div>
                    <div class="mb-3">
                        <label for="password" class="form-label">Jelszó</label>
                        <input type="password" class="form-control" id="password" name="password" required>
                    </div>
                    <?php if ($error): ?>
                        <div class="alert alert-danger"><?= $error; ?></div>
                    <?php endif; ?>
                    <button type="submit" class="btn btn-primary w-100">Belépés</button>
                </form>
            </div>
        </div>
    </body>
    </html>
    <?php
}

// Fejléc és menü
function show_header($page_title) {
    global $available_themes;
    $current_theme = $_SESSION['theme'] ?? 'light'; 

    $body_data_theme = 'light';
    if ($current_theme === 'dark') {
        $body_data_theme = 'dark';
    } 

    ?>
    <!DOCTYPE html>
    <html lang="hu" data-bs-theme="<?= $body_data_theme; ?>">
    <head>
        <meta charset="UTF-8">
        <title>Server-Monitor | <?= $page_title; ?></title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">
        <style>
            .service-list { list-style: none; padding-left: 0; }
            <?php if (in_array($current_theme, ['primary', 'success', 'info', 'warning', 'danger'])): ?>
                body {
                    --bs-body-bg: var(--bs-<?= $current_theme; ?>-bg-subtle);
                    --bs-body-color: var(--bs-<?= $current_theme; ?>-text-emphasis);
                }
                .navbar-brand, .navbar-nav .nav-link, .navbar-text, .dropdown-toggle {
                     color: var(--bs-<?= $current_theme; ?>-text-emphasis) !important;
                }
                .bg-body-tertiary {
                    background-color: var(--bs-<?= $current_theme; ?>-bg-subtle) !important;
                }
                .card {
                    background-color: var(--bs-body-bg);
                }
            <?php endif; ?>
        </style>
    </head>
    <body class="bg-body-tertiary">
    <nav class="navbar navbar-expand-lg bg-body-tertiary shadow-sm sticky-top">
        <div class="container-fluid">
            <a class="navbar-brand" href="index.php"><i class="fas fa-chart-line me-2"></i> SERVER-MONITOR</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav me-auto">
                    <li class="nav-item">
                        <a class="nav-link <?= strpos($_SERVER['REQUEST_URI'], 'index.php') !== false && strpos($_SERVER['REQUEST_URI'], 'admin') === false ? 'active' : ''; ?>" href="index.php"><i class="fas fa-network-wired me-1"></i> Állapot Áttekintés</a>
                    </li>
                    <?php if ($_SESSION['is_admin']): ?>
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle <?= strpos($_SERVER['REQUEST_URI'], 'admin') !== false ? 'active' : ''; ?>" href="#" role="button" data-bs-toggle="dropdown" aria-expanded="false">
                            <i class="fas fa-tools me-1"></i> Adminisztráció
                        </a>
                        <ul class="dropdown-menu">
                            <li><a class="dropdown-item" href="admin_hosts.php"><i class="fas fa-server me-1"></i> Hosztok Kezelése</a></li>
                            <li><a class="dropdown-item" href="admin_users.php"><i class="fas fa-user-friends me-1"></i> Felhasználók Kezelése</a></li>
                        </ul>
                    </li>
                    <?php endif; ?>
                </ul>
                <div class="d-flex align-items-center">
                    <span class="navbar-text me-3">
                        Bejelentkezve: **<?= $_SESSION['username']; ?>**
                    </span>
                    
                    
<div class="dropdown me-2">
                        <button class="btn btn-sm btn-outline-secondary dropdown-toggle" type="button" id="themeDropdown" data-bs-toggle="dropdown" aria-expanded="false">
                            <i class="fas fa-palette me-1"></i> Téma
                        </button>
                        <ul class="dropdown-menu dropdown-menu-end" aria-labelledby="themeDropdown">
                            <?php foreach ($available_themes as $theme_key => $theme_name): ?>
                                <li>
                                    <form method="POST" class="d-inline">
                                        <input type="hidden" name="set_theme" value="<?= $theme_key; ?>">
                                        <button type="submit" class="dropdown-item <?= ($current_theme == $theme_key) ? 'active' : ''; ?>">
                                            <?= $theme_name; ?>
                                        </button>
                                    </form>
                                </li>
                            <?php endforeach; ?>
                        </ul>
                    </div>

                    <a href="?logout=1" class="btn btn-sm btn-danger">
                        <i class="fas fa-sign-out-alt"></i> Kijelentkezés
                    </a>
                </div>
            </div>
        </div>
    </nav>
    <div class="container mt-4">
    <?php
}

// Lábléc és JS
function show_footer() {
    ?>
    </div>
    <footer class="mt-5 py-3 bg-body-tertiary text-center text-muted shadow-sm">
        <p class="mb-0">Készítette: DevOFALL (gcsipai) | Server-Monitor &copy; <?= date('Y'); ?></p>
    </footer>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    <?php
}
?>
