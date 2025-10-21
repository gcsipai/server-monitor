<?php
require_once 'auth.php';
require_once 'monitor_logic.php'; 

require_auth();

if (!$_SESSION['is_admin']) {
    header('Location: index.php');
    exit();
}

global $pdo;
$message = '';
$edit_host = null;
$current_user_id = $_SESSION['user_id'];

// Kezelés: Hozzáadás/Frissítés/Törlés
if (isset($_POST['action'])) {
    $action = $_POST['action'];
    
    // BIZTONSÁGOS HOZZÁFÉRÉS ÉS TISZTÍTÁS (a hibák elkerülésére)
    $name = trim($_POST['name'] ?? '');
    $ip_address = trim($_POST['ip_address'] ?? '');
    
    // Port kezelése: biztonságos kiolvasás, majd null-ra állítás, ha üres
    $port_input = trim($_POST['port'] ?? '');
    $port = empty($port_input) ? null : (int)$port_input;
    
    $description = $_POST['description'] ?? '';

    if (empty($name) || empty($ip_address)) {
        $message = "danger|A hoszt neve és IP címe kötelező.";
        goto skip_db_op;
    }
    
    if (!filter_var($ip_address, FILTER_VALIDATE_IP)) {
        $message = "danger|Hibás IP cím formátum.";
        goto skip_db_op;
    }
    if ($port !== null && ($port < 1 || $port > 65535)) {
        $message = "danger|Hibás portszám. 1 és 65535 között kell lennie.";
        goto skip_db_op;
    }

    try {
        if ($action == 'add') {
            $stmt = $pdo->prepare("INSERT INTO hosts (name, ip_address, port, description) VALUES (?, ?, ?, ?)");
            $stmt->execute([$name, $ip_address, $port, $description]);
            $message = "success|Hoszt sikeresen hozzáadva.";
            log_audit($pdo, 'HOST_ADD', "Új hoszt hozzáadva: $name ($ip_address:$port)", $current_user_id);
            
        } elseif ($action == 'edit' && isset($_POST['id'])) {
            $stmt = $pdo->prepare("UPDATE hosts SET name = ?, ip_address = ?, port = ?, description = ? WHERE id = ?");
            $stmt->execute([$name, $ip_address, $port, $description, $_POST['id']]);
            $message = "success|Hoszt sikeresen frissítve.";
            log_audit($pdo, 'HOST_EDIT', "Hoszt (ID: {$_POST['id']}) frissítve: $name ($ip_address:$port)", $current_user_id);

        } elseif ($action == 'delete' && isset($_POST['id'])) {
            $id_to_delete = $_POST['id'];
            $stmt = $pdo->prepare("DELETE FROM hosts WHERE id = ?");
            $stmt->execute([$id_to_delete]);
            $message = "success|Hoszt törölve.";
            log_audit($pdo, 'HOST_DELETE', "Hoszt (ID: $id_to_delete) törölve.", $current_user_id);
        }

        header('Location: admin_hosts.php?msg=' . urlencode($message));
        exit();
    } catch (PDOException $e) {
        $message = "danger|Adatbázis hiba: " . $e->getMessage();
    }
    
    skip_db_op:
}

// Üzenet megjelenítése GET paraméterből
if (isset($_GET['msg'])) {
    $message = urldecode($_GET['msg']);
}

// Szerkesztési űrlap betöltése
if (isset($_GET['edit'])) {
    $stmt = $pdo->prepare("SELECT * FROM hosts WHERE id = ?");
    $stmt->execute([$_GET['edit']]);
    $edit_host = $stmt->fetch(PDO::FETCH_ASSOC);
}

// Hosztok listázása
$hosts = $pdo->query("SELECT * FROM hosts ORDER BY ip_address, port")->fetchAll(PDO::FETCH_ASSOC);

show_header("Hosztok Kezelése");
?>

<h1><i class="fas fa-server me-2"></i> Hosztok Kezelése</h1>
<?php if ($message): list($type, $msg) = explode('|', $message); ?>
    <div class="alert alert-<?= $type; ?>"><?= $msg; ?></div>
<?php endif; ?>

<div class="row">
    <div class="col-md-4">
        <div class="card shadow-sm mb-4">
            <div class="card-header bg-primary text-white"><?= $edit_host ? 'Hoszt szerkesztése' : 'Új hoszt hozzáadása'; ?></div>
            <div class="card-body">
                <form method="POST">
                    <input type="hidden" name="action" value="<?= $edit_host ? 'edit' : 'add'; ?>">
                    <?php if ($edit_host): ?><input type="hidden" name="id" value="<?= $edit_host['id']; ?>"><?php endif; ?>
                    
                    <div class="mb-3">
                        <label class="form-label">Név/Szolgáltatás</label>
                        <input type="text" name="name" class="form-control" value="<?= htmlspecialchars($edit_host['name'] ?? ''); ?>" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">IP cím</label>
                        <input type="text" name="ip_address" class="form-control" value="<?= htmlspecialchars($edit_host['ip_address'] ?? ''); ?>" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">TCP Port (Hagyja üresen, ha csak Ping)</label>
                        <input type="number" name="port" class="form-control" value="<?= $edit_host['port'] ?? ''; ?>">
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Leírás</label>
                        <textarea name="description" class="form-control"><?= htmlspecialchars($edit_host['description'] ?? ''); ?></textarea>
                    </div>
                    <button type="submit" class="btn btn-<?= $edit_host ? 'success' : 'primary'; ?> w-100"><i class="fas fa-save"></i> Mentés</button>
                    <?php if ($edit_host): ?><a href="admin_hosts.php" class="btn btn-secondary mt-2 w-100">Mégsem</a><?php endif; ?>
                </form>
            </div>
        </div>
    </div>
    
    <div class="col-md-8">
        <table class="table table-striped shadow-sm">
            <thead class="table-dark">
                <tr><th>Név</th><th>IP</th><th>Port</th><th>Leírás</th><th>Műveletek</th></tr>
            </thead>
            <tbody>
                <?php foreach ($hosts as $host): ?>
                <tr>
                    <td><?= htmlspecialchars($host['name']); ?></td>
                    <td><?= htmlspecialchars($host['ip_address']); ?></td>
                    <td><?= $host['port'] ?? '<span class="badge bg-info">PING</span>'; ?></td>
                    <td><?= htmlspecialchars($host['description'] ?? 'N/A'); ?></td>
                    <td>
                        <a href="?edit=<?= $host['id']; ?>" class="btn btn-sm btn-success me-2"><i class="fas fa-edit"></i> Szerkesztés</a>
                        <form method="POST" class="d-inline" onsubmit="return confirm('Biztosan törölni szeretné ezt a hoszt bejegyzést?');">
                            <input type="hidden" name="action" value="delete">
                            <input type="hidden" name="id" value="<?= $host['id']; ?>">
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
