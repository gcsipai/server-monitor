#!/bin/bash
# --------------------------------------------------------------------------------
# OpenVPN Konfigurácós letöltő Szkript - JAVÍTOTT VERZIÓ (v6.0)
# A szkriptet kizárólag ROOT felhasználóként szabad futtatni!
# Készítette: DevOFALL
# --------------------------------------------------------------------------------

# --------------------------------------------------------------------------------
# --- KONFIGURÁCIÓS BEÁLLÍTÁSOK (V6.0) ---
# --------------------------------------------------------------------------------

DEFAULT_OVPN_SOURCE_DIR="/etc/openvpn/server/ovpn_clients" 
WWW_ROOT="/var/www/html"
DOWNLOAD_SUBDIR="ovpn_downloads"
TARGET_DIR="$WWW_ROOT/$DOWNLOAD_SUBDIR"
WWW_USER="www-data" 
VPN_SERVICE_NAME="openvpn-server@server" 
AUTHOR_NAME="DevOFALL"
VERSION_NUMBER="6.0"
OVPN_SOURCE_DIR="$DEFAULT_OVPN_SOURCE_DIR"  # ✨ JAVÍTÁS: Változó inicializálás

# --- SZÍNEK ÉS ELŐKÉSZÜLETEK ---
BLUE_BOLD='\033[1;34m'
RED_BOLD='\033[1;31m'
YELLOW_BOLD='\033[1;33m'
GREEN_BOLD='\033[1;32m'
RESET='\033[0m'

echo -e "${BLUE_BOLD}--- 🛡️ OpenVPN Konfigurációs Letöltő Telepítése (v${VERSION_NUMBER} - Root mód) ---${RESET}"

# --------------------------------------------------------------------------------
# LÉPÉS 0: Interaktív Bekérdezések és Fájltisztítás
# --------------------------------------------------------------------------------
echo -e "${YELLOW_BOLD}\n[0/6] Interaktív beállítások és fájltisztítás...${RESET}"

# 0.1 Régi index.html törlése
if [[ -f "$WWW_ROOT/index.html" ]]; then
    rm "$WWW_ROOT/index.html"
    echo -e "${GREEN_BOLD}✅ Régi index.html fájl törölve.${RESET}"
fi

# 0.2 Forráskönyvtár bekérése
read -rp "1. Adja meg az OVPN fájlok könyvtárát (Alapértelmezett: $DEFAULT_OVPN_SOURCE_DIR): " OVPN_SOURCE_DIR_INPUT
OVPN_SOURCE_DIR="${OVPN_SOURCE_DIR_INPUT:-$DEFAULT_OVPN_SOURCE_DIR}"
if [[ ! -d "$OVPN_SOURCE_DIR" ]]; then
    echo -e "${YELLOW_BOLD}ℹ️ A forrásmappa ($OVPN_SOURCE_DIR) nem létezik. Létrehozom.${RESET}"
    mkdir -p "$OVPN_SOURCE_DIR"
fi

# 0.3 Jelszó bekérése
read -rp "2. Adja meg a weboldalhoz használandó JELSZÓT: " VPN_DOWNLOAD_PASSWORD
if [[ -z "$VPN_DOWNLOAD_PASSWORD" ]]; then
    echo -e "${RED_BOLD}❌ Hiba: A jelszó nem lehet üres. Lépjen ki, és próbálja újra.${RESET}"
    exit 1
fi

# --------------------------------------------------------------------------------
# LÉPÉS 1: Jogosultságok Beállítása (ACL - Csomagtelepítéssel)
# --------------------------------------------------------------------------------
echo -e "${YELLOW_BOLD}\n[1/6] Jogosultságok beállítása (ACL)...${RESET}"

if ! command -v setfacl &> /dev/null; then
    echo -e "ℹ️ Telepítem az 'acl' csomagot."
    apt update > /dev/null 2>&1
    apt install -y acl > /dev/null 2>&1
fi

# Beállítja a www-data felhasználó olvasási jogát
setfacl -m u:$WWW_USER:rx "$OVPN_SOURCE_DIR"
setfacl -m d:u:$WWW_USER:rx "$OVPN_SOURCE_DIR"
chmod g+r "$OVPN_SOURCE_DIR/"*.ovpn 2>/dev/null  # ✨ JAVÍTÁS: Idézőjelek javítva
chown -R root:"$WWW_USER" "$OVPN_SOURCE_DIR" 2>/dev/null

echo -e "${GREEN_BOLD}✅ Jogosultságok beállítva a $WWW_USER számára.${RESET}"

# --------------------------------------------------------------------------------
# LÉPÉS 2: Webszerver (Apache2) és PHP Telepítése
# --------------------------------------------------------------------------------
echo -e "${YELLOW_BOLD}\n[2/6] Webszerver telepítése: Apache2 és PHP...${RESET}"

apt install -y apache2 php libapache2-mod-php php-cli

if [ $? -ne 0 ]; then
    echo -e "${RED_BOLD}❌ Hiba: Az Apache2/PHP telepítése sikertelen.${RESET}"
    exit 1
fi
echo -e "${GREEN_BOLD}✅ Apache2 és PHP sikeresen telepítve.${RESET}"

# --------------------------------------------------------------------------------
# LÉPÉS 3: Mappa Struktúra és Apache Konfiguráció
# --------------------------------------------------------------------------------
echo -e "${YELLOW_BOLD}\n[3/6] Mappa struktúra és Apache konfigurálása...${RESET}"
mkdir -p "$TARGET_DIR"

chown -R www-data:www-data "$WWW_ROOT"
chmod 755 "$WWW_ROOT"

# ✨ JAVÍTÁS: Megbízhatóbb Apache konfiguráció
APACHE_CONF_NEEDED="<Directory /var/www/html/ovpn_downloads>
    Options FollowSymLinks
    AllowOverride None
    Require all granted
</Directory>"

if ! grep -q "ovpn_downloads" /etc/apache2/apache2.conf; then
    echo "$APACHE_CONF_NEEDED" >> /etc/apache2/apache2.conf
    echo -e "${GREEN_BOLD}✅ Apache konfiguráció frissítve.${RESET}"
fi

systemctl restart apache2
echo -e "${GREEN_BOLD}✅ Apache2 újraindítva.${RESET}"

# --------------------------------------------------------------------------------
# LÉPÉS 4: VPN Státusz Ellenőrző Script (PHP/Bash)
# --------------------------------------------------------------------------------
echo -e "${YELLOW_BOLD}\n[4/6] VPN Státusz ellenőrző fájl generálása...${RESET}"

cat > "$WWW_ROOT/vpn_status.php" << 'EOL'
<?php
// Ellenőrzi az OpenVPN szolgáltatás állapotát a szerveren
$service_name = "openvpn-server@server";
$output = shell_exec("systemctl is-active $service_name 2>&1");
$status = trim($output);

$icon = '';
$class = 'secondary';
$text = 'ISMERETLEN';

if ($status === 'active') {
    $text = 'FUT';
    $class = 'success';
    $icon = '<i class="bi bi-shield-fill-check me-1"></i>';
} elseif ($status === 'inactive') {
    $text = 'NEM FUT';
    $class = 'warning';
    $icon = '<i class="bi bi-shield-slash-fill me-1"></i>';
} elseif ($status === 'failed') {
    $text = 'HIBA';
    $class = 'danger';
    $icon = '<i class="bi bi-x-octagon-fill me-1"></i>';
}

echo "<span class=\"badge text-bg-$class\">$icon $text</span>";
?>
EOL
chmod 755 "$WWW_ROOT/vpn_status.php"

# --------------------------------------------------------------------------------
# LÉPÉS 5: Webes Kód Generálása (Sötétkék, Modern, Ikonokkal)
# --------------------------------------------------------------------------------
echo -e "${YELLOW_BOLD}\n[5/6] Webes kód (Modern Sötétkék Design) generálása...${RESET}"

# config.php létrehozása 
cat > "$WWW_ROOT/config.php" << EOL
<?php
\$PASSWORD = "$VPN_DOWNLOAD_PASSWORD"; 
\$DOWNLOAD_DIR = "$DOWNLOAD_SUBDIR/";
\$MIN_FILE_SIZE = 1000;
\$AUTHOR = "$AUTHOR_NAME";
\$VERSION = "$VERSION_NUMBER";
?>
EOL
chmod 644 "$WWW_ROOT/config.php"

# index.php létrehozása (Sötétkék, Modern téma, Ikonokkal)
cat > "$WWW_ROOT/index.php" << 'EOL'
<?php
session_start();
include 'config.php';

$error = '';
$is_authenticated = false;

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
        body { background: linear-gradient(135deg, #1A237E 0%, #0D47A1 100%); min-height: 100vh; padding: 40px 20px; color: #f8f9fa; }
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
EOL
echo -e "${GREEN_BOLD}✅ Webes kód (Modern Sötétkék Designnal, Ikonokkal) generálva.${RESET}"

# --------------------------------------------------------------------------------
# LÉPÉS 6: Symlinkek Létrehozása és Tűzfal Konfiguráció
# --------------------------------------------------------------------------------
echo -e "${YELLOW_BOLD}\n[6/6] Symlinkek frissítése és Tűzfal ellenőrzése...${RESET}"

find "$TARGET_DIR" -type l -delete 2>/dev/null
echo "ℹ️ Meglévő symlinkek törölve."

# ✨ JAVÍTÁS: Robosztus symlink ciklus
shopt -s nullglob
ovpn_files=("$OVPN_SOURCE_DIR"/*.ovpn)
shopt -u nullglob

if [ ${#ovpn_files[@]} -eq 0 ]; then
    echo -e "${YELLOW_BOLD}⚠️  Nincsenek .ovpn fájlok a forráskönyvtárban${RESET}"
else
    for file in "${ovpn_files[@]}"; do
        if [[ -f "$file" ]]; then
            filename=$(basename "$file")
            ln -sf "$file" "$TARGET_DIR/$filename"
            echo "   ✅ Linkelve: $filename"
        fi
    done
fi

if command -v ufw &> /dev/null; then
    ufw allow 80/tcp comment 'Allow HTTP for OpenVPN Web Downloader (Internal Network)' 2>/dev/null
    ufw reload 2>/dev/null
    echo -e "${GREEN_BOLD}✅ Tűzfal (UFW) szabály frissítve a 80-as portra.${RESET}"
fi

# --------------------------------------------------------------------------------
# BEFEJEZÉS
# --------------------------------------------------------------------------------
echo -e "${BLUE_BOLD}\n🎉 TELEPÍTÉS KÉSZ! Az új, SÖTÉTKÉK, MODERN felület aktív (v${VERSION_NUMBER}).${RESET}"
echo -e "${BLUE_BOLD}================================================================${RESET}"
echo -e "🌐 **Elérési út:** http://$(hostname -I | awk '{print $1}')"
echo -e "🔑 **Jelszó:** ${RED_BOLD}$VPN_DOWNLOAD_PASSWORD${RESET}"
echo -e "📂 **Forrásmappa:** $OVPN_SOURCE_DIR"
echo -e "👤 **Készítette:** $AUTHOR_NAME"
echo -e "${BLUE_BOLD}================================================================${RESET}"
