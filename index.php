<?php
require_once 'auth.php';
require_once 'monitor_logic.php';

require_auth(); // Hitelesítés kikényszerítése

global $pdo;
$monitoring_results = run_monitoring($pdo);

show_header("Állapot Áttekintés");
?>

<div class="row mb-4">
    <div class="col-12">
        <h1><i class="fas fa-tachometer-alt me-2"></i> Server-Monitor Állapot</h1>
        <p class="lead">Utolsó frissítés: <?= date('Y. m. d. H:i:s'); ?></p>
        
        <?php if (isset($monitoring_results['error'])): ?>
            <div class="alert alert-danger"><i class="fas fa-exclamation-triangle me-2"></i> <?= $monitoring_results['error']; ?></div>
        <?php endif; ?>
    </div>
</div>

<div class="row mt-4">
    <?php 
    $hosts_to_display = array_filter($monitoring_results, function($key) {
        return $key !== 'error';
    }, ARRAY_FILTER_USE_KEY);
    
    // Csoportosítva IP cím szerint, hogy a Ping állapot egyértelmű legyen
    foreach ($hosts_to_display as $ip => $data): ?>
    <div class="col-md-6 col-lg-4 mb-4">
        <div class="card shadow-sm border-<?= $data['ping_status']['badge']; ?>">
            <div class="card-header bg-<?= $data['ping_status']['badge']; ?> text-white">
                <h5 class="mb-0"><i class="fas fa-server me-2"></i> Hoszt: <?= $data['ip']; ?></h5>
            </div>
            <div class="card-body">
                <p class="mb-3">
                    <strong><i class="fas fa-plug me-2"></i> Alapvető elérhetőség:</strong> 
                    <span class="badge bg-<?= $data['ping_status']['badge']; ?>">
                        <i class="fas <?= $data['ping_status']['icon']; ?> me-1"></i> <?= $data['ping_status']['status']; ?>
                    </span>
                </p>
                
                <h6><i class="fas fa-cogs me-2"></i> Szolgáltatások Ellenőrzése:</h6>
                <ul class="service-list">
                    <?php if (empty($data['services'])): ?>
                        <li><span class="text-muted">Nincs szolgáltatás beállítva ehhez az IP-hez.</span></li>
                    <?php endif; ?>
                    
                    <?php 
                    // Minden szolgáltatás soronkénti megjelenítése
                    foreach ($data['services'] as $service): 
                        $status = $service['status'];
                    ?>
                        <li>
                            <strong><?= htmlspecialchars($service['name']); ?> 
                            (<?= $service['port'] ?? 'Ping'; ?>):</strong> 
                            <span class="badge bg-<?= $status['badge']; ?>">
                                <i class="fas <?= $status['icon']; ?> me-1"></i> <?= $status['status']; ?>
                            </span>
                        </li>
                    <?php endforeach; ?>
                </ul>
            </div>
        </div>
    </div>
    <?php endforeach; ?>
</div>

<?php show_footer(); ?>
