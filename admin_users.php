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
$edit_user = null;
$current_user_id = $_SESSION['user_id'];

// Kezelés: Hozzáadás/Frissítés/Törlés
if (isset($_POST['action'])) {
    $action = $_POST['action'];
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $is_admin = isset($_POST['is_admin']) ? 1 : 0;
    
    try {
        if ($action == 'add') {
            if (empty($password)) { $message = "danger|A jelszó nem lehet üres."; goto skip_db_op; }
            $hash = password_hash($password, PASSWORD_DEFAULT);
            $stmt = $pdo->prepare("INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)");
            $stmt->execute([$username, $hash, $is_admin]);
            $message = "success|Felhasználó sikeresen hozzáadva.";
            log_audit($pdo, 'USER_ADD', "Új felhasználó hozzáadva: " . $username, $current_user_id);
            
        } elseif ($action == 'edit' && isset($_POST['id'])) {
            $id = $_POST['id'];
            if ($id == $current_user_id && $is_admin == 0) {
                 $message = "danger|Nem távolíthatja el saját magától az admin jogosultságot."; goto skip_db_op;
            }

            $sql = "UPDATE users SET username = ?, is_admin = ?";
            $params = [$username, $is_admin];
            
            if (!empty($password)) {
                $hash = password_hash($password, PASSWORD_DEFAULT);
                $sql .= ", password_hash = ?";
                $params[] = $hash;
            }
            $sql .= " WHERE id = ?";
            $params[] = $id;
            
            $stmt = $pdo->prepare($sql);
            $stmt->execute($params);
            $message = "success|Felhasználó sikeresen frissítve.";
            log_audit($pdo, 'USER_EDIT', "Felhasználó ($id) frissítve: " . $username, $current_user_id);
        } elseif ($action == 'delete' && isset($_POST['id'])) {
            $id_to_delete = $_POST['id'];
            if ($id_to_delete == $current_user_id) {
                $message = "danger|Saját magát nem törölheti!"; goto skip_db_op;
            }
            
            $stmt = $pdo->prepare("DELETE FROM users WHERE id = ?"); 
            $stmt->execute([$id_to_delete]);
            $message = "success|Felhasználó törölve.";
            log_audit($pdo, 'USER_DELETE', "Felhasználó ($id_to_delete) törölve.", $current_user_id);
        }
        
        header('Location: admin_users.php?msg=' . urlencode($message));
        exit();
    } catch (PDOException $e) {
        // Kezelje az adatbázis hibákat (pl. duplikált felhasználónév)
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
    $stmt = $pdo->prepare("SELECT id, username, is_admin FROM users WHERE id = ?");
    $stmt->execute([$_GET['edit']]);
    $edit_user = $stmt->fetch(PDO::FETCH_ASSOC);
}

// Felhasználók listázása
$users = $pdo->query("SELECT id, username, is_admin FROM users ORDER BY username")->fetchAll(PDO::FETCH_ASSOC);

show_header("Felhasználók Kezelése");
?>

<h1><i class="fas fa-user-friends me-2"></i> Felhasználók Kezelése</h1>
<?php if ($message): list($type, $msg) = explode('|', $message); ?>
    <div class="alert alert-<?= $type; ?>"><?= $msg; ?></div>
<?php endif; ?>

<div class="row">
    <div class="col-md-4">
        <div class="card shadow-sm mb-4">
            <div class="card-header bg-primary text-white"><?= $edit_user ? 'Felhasználó szerkesztése' : 'Új felhasználó hozzáadása'; ?></div>
            <div class="card-body">
                <form method="POST">
                    <input type="hidden" name="action" value="<?= $edit_user ? 'edit' : 'add'; ?>">
                    <?php if ($edit_user): ?><input type="hidden" name="id" value="<?= $edit_user['id']; ?>"><?php endif; ?>
                    
                    <div class="mb-3">
                        <label class="form-label">Felhasználónév</label>
                        <input type="text" name="username" class="form-control" value="<?= htmlspecialchars($edit_user['username'] ?? ''); ?>" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Jelszó <?= $edit_user ? ' (Hagyja üresen, ha nem változik)' : ''; ?></label>
                        <input type="password" name="password" class="form-control" <?= $edit_user ? '' : 'required'; ?>>
                    </div>
                    <div class="form-check mb-3">
                        <input class="form-check-input" type="checkbox" name="is_admin" value="1" id="is_admin" <?= ($edit_user && $edit_user['is_admin']) ? 'checked' : ''; ?> <?= ($edit_user && $edit_user['id'] == $_SESSION['user_id']) ? 'disabled' : ''; ?>>
                        <label class="form-check-label" for="is_admin">Adminisztrátor</label>
                    </div>
                    <button type="submit" class="btn btn-<?= $edit_user ? 'success' : 'primary'; ?> w-100"><i class="fas fa-save"></i> Mentés</button>
                    <?php if ($edit_user): ?><a href="admin_users.php" class="btn btn-secondary mt-2 w-100">Mégsem</a><?php endif; ?>
                </form>
            </div>
        </div>
    </div>
    
    <div class="col-md-8">
        <table class="table table-striped shadow-sm">
            <thead class="table-dark">
                <tr><th>ID</th><th>Felhasználónév</th><th>Admin</th><th>Műveletek</th></tr>
            </thead>
            <tbody>
                <?php foreach ($users as $user): ?>
                <tr>
                    <td><?= $user['id']; ?></td>
                    <td><?= htmlspecialchars($user['username']); ?></td>
                    <td><?= $user['is_admin'] ? '<span class="badge bg-danger">IGEN</span>' : 'NEM'; ?></td>
                    <td>
                        <a href="?edit=<?= $user['id']; ?>" class="btn btn-sm btn-success me-2"><i class="fas fa-edit"></i> Szerkesztés</a>
                        <?php if ($user['id'] != $_SESSION['user_id']): ?>
                        <form method="POST" class="d-inline" onsubmit="return confirm('Biztosan törölni szeretné ezt a felhasználót?');">
                            <input type="hidden" name="action" value="delete">
                            <input type="hidden" name="id" value="<?= $user['id']; ?>">
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
