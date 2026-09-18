<?php
// ==============================================================
//  BetterForums — Database Configuration
//  AlwaysData MySQL Configuration
// ==============================================================
define('BF_DB_HOST', 'mysql-secretsqlhoster.alwaysdata.net');
define('BF_DB_PORT', 3306);
define('BF_DB_NAME', 'secretsqlhoster_betterformus');
define('BF_DB_USER', 'secretsqlhoster');
define('BF_DB_PASS', 'dhakool123');

// Generic definitions for any scripts inspecting DB_* constants
if (!defined('DB_HOST')) define('DB_HOST', BF_DB_HOST);
if (!defined('DB_PORT')) define('DB_PORT', BF_DB_PORT);
if (!defined('DB_NAME')) define('DB_NAME', BF_DB_NAME);
if (!defined('DB_USER')) define('DB_USER', BF_DB_USER);
if (!defined('DB_PASS')) define('DB_PASS', BF_DB_PASS);

$conn = @mysqli_connect(BF_DB_HOST, BF_DB_USER, BF_DB_PASS, BF_DB_NAME, BF_DB_PORT);
if (!$conn) {
    die("Connection failed: " . mysqli_connect_error());
}
mysqli_set_charset($conn, "utf8mb4");

function getBetterForumsDB() {
    global $conn;
    return $conn;
}

function sanitize($data, $c = null) {
    global $conn;
    $db = $c ? $c : $conn;
    if ($data === null) return '';
    return htmlspecialchars(mysqli_real_escape_string($db, trim((string)$data)), ENT_QUOTES, 'UTF-8');
}
