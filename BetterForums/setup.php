<?php
require_once __DIR__ . '/db.php';

$tables = [
    "CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) NOT NULL UNIQUE,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(20) NOT NULL DEFAULT 'USER',
        ip_address VARCHAR(45) NOT NULL DEFAULT '',
        is_shadowbanned TINYINT NOT NULL DEFAULT 0,
        hide_from_search TINYINT NOT NULL DEFAULT 0,
        display_name VARCHAR(100) NOT NULL DEFAULT '',
        bio TEXT,
        avatar_type VARCHAR(20) NOT NULL DEFAULT 'url',
        avatar_data MEDIUMTEXT,
        status_flair VARCHAR(100) NOT NULL DEFAULT '',
        custom_badge VARCHAR(50) NOT NULL DEFAULT '',
        theme VARCHAR(20) NOT NULL DEFAULT 'light',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",

    "CREATE TABLE IF NOT EXISTS system_config (
        id INT AUTO_INCREMENT PRIMARY KEY,
        hit_counter BIGINT NOT NULL DEFAULT 0,
        announcement_banner TEXT
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",

    "CREATE TABLE IF NOT EXISTS motd_pool (
        id INT AUTO_INCREMENT PRIMARY KEY,
        message_text VARCHAR(255) NOT NULL,
        weight_percent DECIMAL(5,2) NOT NULL DEFAULT 0.00,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",

    "CREATE TABLE IF NOT EXISTS subbetters (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(50) NOT NULL UNIQUE,
        description VARCHAR(255) NOT NULL DEFAULT '',
        is_locked TINYINT NOT NULL DEFAULT 0,
        created_by VARCHAR(50) NOT NULL DEFAULT 'system',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",

    "CREATE TABLE IF NOT EXISTS posts (
        id INT AUTO_INCREMENT PRIMARY KEY,
        subbetter_id INT NOT NULL,
        user_id INT NOT NULL,
        title VARCHAR(250) NOT NULL,
        content TEXT NOT NULL,
        image_url MEDIUMTEXT,
        is_pinned TINYINT NOT NULL DEFAULT 0,
        is_locked TINYINT NOT NULL DEFAULT 0,
        ip_address VARCHAR(45) NOT NULL DEFAULT '',
        is_deleted TINYINT NOT NULL DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",

    "CREATE TABLE IF NOT EXISTS comments (
        id INT AUTO_INCREMENT PRIMARY KEY,
        post_id INT NOT NULL,
        parent_id INT DEFAULT NULL,
        user_id INT NOT NULL,
        content TEXT NOT NULL,
        ip_address VARCHAR(45) NOT NULL DEFAULT '',
        is_deleted TINYINT NOT NULL DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",

    "CREATE TABLE IF NOT EXISTS user_votes (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        target_type VARCHAR(10) NOT NULL,
        target_id INT NOT NULL,
        vote_type TINYINT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY unique_vote (user_id, target_type, target_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",

    "CREATE TABLE IF NOT EXISTS moderation_actions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        action_type VARCHAR(20) NOT NULL,
        target_username VARCHAR(50) NOT NULL,
        subbetter_id INT DEFAULT NULL,
        reason VARCHAR(255) NOT NULL DEFAULT '',
        status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
        reporter_username VARCHAR(50) NOT NULL DEFAULT '',
        reviewed_by VARCHAR(50) NOT NULL DEFAULT '',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",

    "CREATE TABLE IF NOT EXISTS ip_bans (
        id INT AUTO_INCREMENT PRIMARY KEY,
        ip_address VARCHAR(45) NOT NULL UNIQUE,
        reason VARCHAR(255) NOT NULL DEFAULT '',
        banned_by VARCHAR(50) NOT NULL DEFAULT '',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",

    "CREATE TABLE IF NOT EXISTS saved_posts (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        post_id INT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY user_post_save (user_id, post_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",

    "CREATE TABLE IF NOT EXISTS subscriptions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        subbetter_id INT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY user_sub (user_id, subbetter_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",

    "CREATE TABLE IF NOT EXISTS roles (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(50) NOT NULL,
        color VARCHAR(20) NOT NULL DEFAULT '#ffffff',
        permissions TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",

    "CREATE TABLE IF NOT EXISTS feedbacks (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT,
        username VARCHAR(50),
        content TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
];

foreach ($tables as $sql) {
    if (!mysqli_query($conn, $sql)) {
        die("Setup query failed: " . mysqli_error($conn));
    }
}

$user_cols = [
    'avatar_type' => "VARCHAR(20) NOT NULL DEFAULT 'url'",
    'avatar_data' => "MEDIUMTEXT",
    'status_flair' => "VARCHAR(100) NOT NULL DEFAULT ''",
    'custom_badge' => "VARCHAR(50) NOT NULL DEFAULT ''",
    'is_admin' => "TINYINT NOT NULL DEFAULT 0",
    'is_mod' => "TINYINT NOT NULL DEFAULT 0",
    'is_vip' => "TINYINT NOT NULL DEFAULT 0",
    'is_muted' => "TINYINT NOT NULL DEFAULT 0",
    'force_logout' => "TINYINT NOT NULL DEFAULT 0",
    'name_color' => "VARCHAR(20) NOT NULL DEFAULT '#94a3b8'",
    'avatar_overlay' => "TEXT",
    'last_seen' => "DATETIME DEFAULT NULL"
];
foreach ($user_cols as $col => $defn) {
    $c_chk = mysqli_query($conn, "SHOW COLUMNS FROM users LIKE '$col'");
    if (mysqli_num_rows($c_chk) === 0) {
        mysqli_query($conn, "ALTER TABLE users ADD COLUMN $col $defn");
    }
}

$post_cols = [
    'image_url' => "MEDIUMTEXT",
    'is_pinned' => "TINYINT NOT NULL DEFAULT 0",
    'is_locked' => "TINYINT NOT NULL DEFAULT 0",
    'flair' => "VARCHAR(50) NOT NULL DEFAULT ''",
    'link_url' => "VARCHAR(500) NOT NULL DEFAULT ''"
];
foreach ($post_cols as $col => $defn) {
    $c_chk = mysqli_query($conn, "SHOW COLUMNS FROM posts LIKE '$col'");
    if (mysqli_num_rows($c_chk) === 0) {
        mysqli_query($conn, "ALTER TABLE posts ADD COLUMN $col $defn");
    }
}

$sub_cols = [
    'is_locked' => "TINYINT NOT NULL DEFAULT 0"
];
foreach ($sub_cols as $col => $defn) {
    $c_chk = mysqli_query($conn, "SHOW COLUMNS FROM subbetters LIKE '$col'");
    if (mysqli_num_rows($c_chk) === 0) {
        mysqli_query($conn, "ALTER TABLE subbetters ADD COLUMN $col $defn");
    }
}

$cfg_cols = [
    'announcement_banner' => "TEXT",
    'maintenance' => "TINYINT NOT NULL DEFAULT 0",
    'maintenance_msg' => "TEXT",
    'ban_templates' => "TEXT",
    'site_settings' => "TEXT",
    'nitro_word' => "VARCHAR(100) NOT NULL DEFAULT ''"
];
foreach ($cfg_cols as $col => $defn) {
    $c_chk = mysqli_query($conn, "SHOW COLUMNS FROM system_config LIKE '$col'");
    if (mysqli_num_rows($c_chk) === 0) {
        mysqli_query($conn, "ALTER TABLE system_config ADD COLUMN $col $defn");
    }
}

$default_subbetters = ['linux', 'unblockedgames', 'webdev', 'retrodesign', 'lounge'];
foreach ($default_subbetters as $sb) {
    $sb_clean = mysqli_real_escape_string($conn, $sb);
    mysqli_query($conn, "INSERT IGNORE INTO subbetters (name, description, created_by) VALUES ('$sb_clean', 'Default subbetter community', 'system')");
}

$cfg_check = mysqli_query($conn, "SELECT id FROM system_config WHERE id = 1");
if (mysqli_num_rows($cfg_check) === 0) {
    mysqli_query($conn, "INSERT INTO system_config (id, hit_counter, announcement_banner) VALUES (1, 1, '')");
}

$motd_check = mysqli_query($conn, "SELECT id FROM motd_pool LIMIT 1");
if (mysqli_num_rows($motd_check) === 0) {
    mysqli_query($conn, "INSERT INTO motd_pool (message_text, weight_percent) VALUES ('Welcome to BetterForums - The Front Page of the Web!', 100.00)");
}

echo "<!DOCTYPE html><html><head><title>BetterForums Setup</title><style>body{font-family:Verdana,Arial,sans-serif;font-size:11px;background:#eff7ff;padding:20px;}</style></head><body><div style='background:#fff;border:1px solid #5f99cf;padding:15px;max-width:400px;'><h3>BetterForums Setup Complete</h3><p>Database tables verified and schema upgraded successfully.</p><p><a href='login.php' style='color:#0000ff;'>Proceed to Login</a></p></div></body></html>";
