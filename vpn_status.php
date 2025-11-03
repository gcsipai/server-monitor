<?php
// Ellenőrzi az OpenVPN szolgáltatás állapotát a szerveren
$service_name = "openvpn-server@server";
// A shell_exec futtatja a 'systemctl is-active' parancsot
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
