<?php
session_start();
include 'config.php'; // Konfigurációs beállítások betöltése

$error = '';
$is_authenticated = false;

// Bejelentkezési logika
if (isset($_POST['password'])) {
    if ($_POST['password'] === $PASSWORD) {
        $_SESSION['authenticated'] = true;
        $is_authenticated = true;
    } else {
        $error = "Helytelen jelszó! Próbálja újra.";
    }
} elseif (isset($_SESSION['authenticated']) && $_SESSION['authenticated'] === true) {
    $is_authenticated = true;
}

// Kijelentkezési logika
if (isset($_GET['logout'])) {
    session_destroy();
    header("Location: index.php");
    exit();
}
?>
<!DOCTYPE html>
<html lang="hu">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OpenVPN Konfigurácós letöltő | v<?= $VERSION ?></title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
    <style>
        /* Sötétkék háttér gradiens */
        body { background: linear-gradient(135deg, #1A237E 0%, #0D47A1 100%); min-height: 10vh; padding: 40px 20px; color: #f8f9fa; }
        /* Kártya stílus - Világosabb kártya sötét háttéren */
        .app-card { background: #ffffff; border-radius: 12px; box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3); overflow: hidden; color: #212529; }
        /* Mély sötétkék fejléc */
        .app-header { background: #004a8f; color: white; padding: 25px 20px; text-align: center; }
        .app-header h4 { font-weight: 700; }
        .app-header small { color: #bbdefb; }
        .btn-primary { background-color: #004a8f; border-color: #004a8f; transition: background-color 0.2s; }
        .btn-primary:hover { background-color: #003366; border-color: #003366; }
        .file-item { border-left: 5px solid #004a8f; margin-bottom: 12px; transition: background-color 0.2s; }
        .file-item:hover { background-color: #f1f1f1; }
        .alert-danger { background-color: #f8d7da; color: #721c24; border-color: #f5c6cb; }
        .card-footer { background-color: #e9ecef; border-top: none; }
        .badge { font-size: 0.85em; }
    </style>
</head>
<body>
<div class="container">
    <div class="row justify-content-center">
        <div class="col-md-7 col-lg-6">
            <div class="app-card">
                <div class="app-header">
                    <i class="bi bi-cloud-arrow-down-fill" style="font-size: 2.5rem;"></i>
                    <h4 class="mt-2 mb-1">OpenVPN Konfigurácós letöltő</h4>
                    <small>Verzió: <?= $VERSION ?></small>
                </div>
                <div class="card-body p-4 p-md-5">
                    <?php if (!$is_authenticated): ?>
                        <h5 class="card-title text-center mb-4 text-muted"><i class="bi bi-lock-fill me-2"></i> Belépés szükséges</h5>
                        <?php if ($error): ?>
                            <div class="alert alert-danger" role="alert"><?= $error ?></div>
                        <?php endif; ?>
                        <form method="POST">
                            <div class="input-group mb-4">
                                <span class="input-group-text"><i class="bi bi-key-fill"></i></span>
                                <input type="password" class="form-control form-control-lg" name="password" placeholder="Jelszó" required>
                            </div>
                            <button type="submit" class="btn btn-primary btn-lg w-100"><i class="bi bi-box-arrow-in-right me-2"></i> Belépés</button>
                        </form>
                    <?php else: ?>
                        <div class="d-flex justify-content-between align-items-center mb-4 pb-3 border-bottom">
                            <h5 class="card-title mb-0 text-primary"><i class="bi bi-list-columns-reverse me-2"></i> Elérhető Kliens Fájlok</h5>
                            <a href="?logout=1" class="btn btn-outline-danger btn-sm"><i class="bi bi-box-arrow-left me-1"></i> Kilépés</a>
                        </div>
                        
                        <div class="alert alert-secondary py-2 mb-4 d-flex justify-content-between align-items-center border">
                            <strong><i class="bi bi-server me-1"></i> VPN Szerver Státusz:</strong>
                            <?php include 'vpn_status.php'; ?>
                        </div>
                        
                        <div class="list-group">
                            <?php
                            // Fájlok listázása és szűrése
                            $files = glob($DOWNLOAD_DIR . '*.ovpn');
                            if (count($files) > 0) {
                                foreach ($files as $file) {
                                    $filename = basename($file);
                                    $filesize = filesize($file);
                                    
                                    if ($filesize > $MIN_FILE_SIZE) {
                                        echo '<div class="list-group-item d-flex justify-content-between align-items-center file-item">';
                                        echo '<div>';
                                        echo '<strong><i class="bi bi-file-earmark-code me-2 text-info"></i>' . htmlspecialchars($filename) . '</strong>';
                                        echo '<br><small class="text-muted ms-4">Méret: ' . round($filesize/1024, 2) . ' KB</small>';
                                        echo '</div>';
                                        // Letöltés link
                                        echo '<a href="' . $DOWNLOAD_DIR . htmlspecialchars($filename) . '" class="btn btn-primary btn-sm" download><i class="bi bi-download me-1"></i> Letöltés</a>';
                                        echo '</div>';
                                    }
                                }
                            } else {
                                echo '<div class="alert alert-warning text-center"><i class="bi bi-exclamation-triangle-fill me-2"></i> Nincs elérhető .ovpn fájl a szerveren.</div>';
                            }
                            ?>
                        </div>
                        
                    <?php endif; ?>
                </div>
                <div class="card-footer text-center text-muted small bg-light">
                    OpenVPN Konfigurácós letöltő v<?= $VERSION ?> | Készítette: <?= $AUTHOR ?>
                </div>
            </div>
                
        </div>
    </div>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
