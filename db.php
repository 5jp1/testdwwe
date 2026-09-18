<?php
// ==============================================================
//  BetterChat — Database Configuration
//  Update the four lines below with your Alwaysdata credentials
// ==============================================================
define('DB_HOST', 'mysql-secretsqlhoster.alwaysdata.net');
define('DB_PORT', 3306);
define('DB_NAME', 'secretsqlhoster_betterchat');
define('DB_USER', 'secretsqlhoster');
define('DB_PASS', 'dhakool123');
// ==============================================================

function getDB(): PDO {
    static $pdo = null;
    if ($pdo === null) {
        $dsn = sprintf(
            'mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4',
            DB_HOST, DB_PORT, DB_NAME
        );
        $opts = [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ];
        $pdo = new PDO($dsn, DB_USER, DB_PASS, $opts);
    }
    return $pdo;
}
