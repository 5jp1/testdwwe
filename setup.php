<?php
// ==============================================================
//  BetterChat — Setup / Upgrade
//  Run this whenever you update. Safe to run multiple times.
// ==============================================================
require_once 'db.php';
$pdo = getDB();
$ok = []; $err = [];

// ── Create tables ─────────────────────────────────────────────
$tables = [
'users'=>"CREATE TABLE IF NOT EXISTS `users`(
  `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `username` VARCHAR(32) NOT NULL UNIQUE,
  `password` VARCHAR(255) NOT NULL,
  `avatar` LONGTEXT DEFAULT NULL,
  `name_color` VARCHAR(7) NOT NULL DEFAULT '#3b82f6',
  `is_banned` TINYINT(1) NOT NULL DEFAULT 0,
  `is_admin` TINYINT(1) NOT NULL DEFAULT 0,
  `last_seen` DATETIME DEFAULT NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",

'channels'=>"CREATE TABLE IF NOT EXISTS `channels`(
  `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `name` VARCHAR(64) NOT NULL,
  `type` ENUM('text','announcement') NOT NULL DEFAULT 'text',
  `position` INT NOT NULL DEFAULT 0,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",

'messages'=>"CREATE TABLE IF NOT EXISTS `messages`(
  `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `channel_id` INT UNSIGNED NOT NULL,
  `user_id` INT UNSIGNED DEFAULT NULL,
  `username` VARCHAR(32) NOT NULL,
  `msg_type` VARCHAR(20) NOT NULL DEFAULT 'text',
  `content` LONGTEXT DEFAULT NULL,
  `image_data` LONGTEXT DEFAULT NULL,
  `file_data` LONGTEXT DEFAULT NULL,
  `file_name` VARCHAR(255) DEFAULT NULL,
  `file_mime` VARCHAR(128) DEFAULT NULL,
  `is_system` TINYINT(1) NOT NULL DEFAULT 0,
  `edited_at` DATETIME DEFAULT NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (`channel_id`) REFERENCES `channels`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",

'friend_requests'=>"CREATE TABLE IF NOT EXISTS `friend_requests`(
  `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `from_id` INT UNSIGNED NOT NULL,
  `to_id` INT UNSIGNED NOT NULL,
  `status` ENUM('pending','accepted','declined') NOT NULL DEFAULT 'pending',
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (`from_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,
  FOREIGN KEY (`to_id`)   REFERENCES `users`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",

'friends'=>"CREATE TABLE IF NOT EXISTS `friends`(
  `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `user_a` INT UNSIGNED NOT NULL,
  `user_b` INT UNSIGNED NOT NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (`user_a`) REFERENCES `users`(`id`) ON DELETE CASCADE,
  FOREIGN KEY (`user_b`) REFERENCES `users`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",

'bans'=>"CREATE TABLE IF NOT EXISTS `bans`(
  `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `user_id` INT UNSIGNED NOT NULL,
  `reason` TEXT DEFAULT NULL,
  `duration` VARCHAR(64) NOT NULL DEFAULT 'permanent',
  `banned_by` INT UNSIGNED DEFAULT NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",

'inbox'=>"CREATE TABLE IF NOT EXISTS `inbox`(
  `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `to_id` INT UNSIGNED DEFAULT NULL,
  `type` ENUM('announcement','friend_accept','system') NOT NULL DEFAULT 'system',
  `content` TEXT NOT NULL,
  `is_read` TINYINT(1) NOT NULL DEFAULT 0,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",

'push_subscriptions'=>"CREATE TABLE IF NOT EXISTS `push_subscriptions`(
  `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `user_id` INT UNSIGNED NOT NULL,
  `endpoint` TEXT NOT NULL,
  `p256dh` VARCHAR(255) NOT NULL,
  `auth` VARCHAR(255) NOT NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",

'ip_bans'=>"CREATE TABLE IF NOT EXISTS `ip_bans` (
  `ip` VARCHAR(45) NOT NULL PRIMARY KEY,
  `reason` TEXT DEFAULT NULL,
  `ban_icon` VARCHAR(50) DEFAULT 'fa-gavel',
  `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",

'site_config'=>"CREATE TABLE IF NOT EXISTS `site_config`(
  `id` INT NOT NULL PRIMARY KEY DEFAULT 1,
  `maintenance` TINYINT(1) NOT NULL DEFAULT 0,
  `maintenance_msg` TEXT DEFAULT NULL,
  `allow_images` TINYINT(1) NOT NULL DEFAULT 1,
  `allow_audio` TINYINT(1) NOT NULL DEFAULT 1,
  `custom_wordle` VARCHAR(5) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",

'vapid_keys'=>"CREATE TABLE IF NOT EXISTS `vapid_keys`(
  `id` INT NOT NULL PRIMARY KEY DEFAULT 1,
  `public_key` TEXT DEFAULT NULL,
  `private_key` TEXT DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",

'feedback'=>"CREATE TABLE IF NOT EXISTS `feedback`(
  `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `user_id` INT UNSIGNED NOT NULL,
  `message` TEXT NOT NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",

'roles'=>"CREATE TABLE IF NOT EXISTS `roles`(
  `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `name` VARCHAR(64) NOT NULL,
  `color` VARCHAR(20) DEFAULT '#ffffff',
  `permissions` TEXT NOT NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",

'ban_templates'=>"CREATE TABLE IF NOT EXISTS `ban_templates`(
  `ban_type` VARCHAR(20) NOT NULL PRIMARY KEY,
  `html_content` LONGTEXT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",

'typing_status'=>"CREATE TABLE IF NOT EXISTS `typing_status`(
  `user_id` INT UNSIGNED NOT NULL PRIMARY KEY,
  `channel_id` INT UNSIGNED NOT NULL,
  `last_typed` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",

'settings'=>"CREATE TABLE IF NOT EXISTS `settings`(
  `key` VARCHAR(64) NOT NULL PRIMARY KEY,
  `value` TEXT DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
];

foreach ($tables as $name => $sql) {
    try { $pdo->exec($sql); $ok[] = "Table `$name` OK"; }
    catch (PDOException $e) { $err[] = "$name: " . $e->getMessage(); }
}

// ── ADD MISSING COLUMNS (safe for all MySQL versions) ─────────
// We check INFORMATION_SCHEMA instead of using IF NOT EXISTS
// so this works on MySQL 5.6/5.7/8 and all MariaDB versions.
function addColIfMissing(PDO $pdo, string $table, string $col, string $def, array &$ok, array &$err): void {
    $db = $pdo->query("SELECT DATABASE()")->fetchColumn();
    $exists = $pdo->prepare(
        "SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
         WHERE TABLE_SCHEMA=? AND TABLE_NAME=? AND COLUMN_NAME=?"
    );
    $exists->execute([$db, $table, $col]);
    if (!$exists->fetchColumn()) {
        try {
            $pdo->exec("ALTER TABLE `$table` ADD COLUMN `$col` $def");
            $ok[] = "Added column `$table`.`$col`";
        } catch (PDOException $e) {
            $err[] = "ALTER `$table`.`$col`: " . $e->getMessage();
        }
    }
}

addColIfMissing($pdo, 'users',    'is_admin',   "TINYINT(1) NOT NULL DEFAULT 0",   $ok, $err);
addColIfMissing($pdo, 'users',    'is_mod',     "TINYINT(1) NOT NULL DEFAULT 0",   $ok, $err);
addColIfMissing($pdo, 'users',    'last_ip',    "VARCHAR(45) DEFAULT NULL",        $ok, $err);
addColIfMissing($pdo, 'users',    'custom_tag', "VARCHAR(32) DEFAULT NULL",        $ok, $err);
addColIfMissing($pdo, 'users',    'custom_tag_color', "VARCHAR(7) DEFAULT '#ef4444'", $ok, $err);
addColIfMissing($pdo, 'users',    'is_muted',       "TINYINT(1) NOT NULL DEFAULT 0",   $ok, $err);
addColIfMissing($pdo, 'users',    'is_vip',         "TINYINT(1) NOT NULL DEFAULT 0",   $ok, $err);
addColIfMissing($pdo, 'users',    'can_img',        "TINYINT(1) NOT NULL DEFAULT 1",   $ok, $err);
addColIfMissing($pdo, 'users',    'can_audio',      "TINYINT(1) NOT NULL DEFAULT 1",   $ok, $err);
addColIfMissing($pdo, 'users',    'force_logout',   "TINYINT(1) NOT NULL DEFAULT 0",   $ok, $err);
addColIfMissing($pdo, 'users',    'shadowbanned',   "TINYINT(1) NOT NULL DEFAULT 0",   $ok, $err);
addColIfMissing($pdo, 'users',    'is_nitro',       "TINYINT(1) NOT NULL DEFAULT 0",   $ok, $err);
addColIfMissing($pdo, 'users',    'role_id',        "INT UNSIGNED DEFAULT NULL",       $ok, $err);
addColIfMissing($pdo, 'users',    'avatar_overlay', "TEXT DEFAULT NULL",               $ok, $err);
addColIfMissing($pdo, 'users',    'last_typing',    "DATETIME DEFAULT NULL",           $ok, $err);
addColIfMissing($pdo, 'bans',     'ban_type',   "VARCHAR(20) DEFAULT 'account'",   $ok, $err);
addColIfMissing($pdo, 'bans',     'ban_icon',   "VARCHAR(50) DEFAULT 'fa-gavel'",  $ok, $err);
addColIfMissing($pdo, 'bans',     'custom_html', "LONGTEXT DEFAULT NULL",          $ok, $err);
addColIfMissing($pdo, 'messages', 'msg_type',   "VARCHAR(20) NOT NULL DEFAULT 'text'", $ok, $err);
addColIfMissing($pdo, 'messages', 'reply_to',   "INT UNSIGNED DEFAULT NULL",        $ok, $err);
addColIfMissing($pdo, 'messages', 'file_data',  "LONGTEXT DEFAULT NULL",            $ok, $err);
addColIfMissing($pdo, 'site_config', 'active_challenge', "TEXT DEFAULT NULL",       $ok, $err);
addColIfMissing($pdo, 'messages', 'file_name',  "VARCHAR(255) DEFAULT NULL",        $ok, $err);
addColIfMissing($pdo, 'messages', 'file_mime',  "VARCHAR(128) DEFAULT NULL",        $ok, $err);
addColIfMissing($pdo, 'messages', 'edited_at',  "DATETIME DEFAULT NULL",            $ok, $err);

// Fix any old rows that have NULL msg_type (from before this column existed)
try {
    $pdo->exec("UPDATE `messages` SET msg_type='system' WHERE msg_type IS NULL AND is_system=1");
    $pdo->exec("UPDATE `messages` SET msg_type='text'   WHERE msg_type IS NULL AND is_system=0 AND image_data IS NULL");
    $pdo->exec("UPDATE `messages` SET msg_type='image'  WHERE msg_type IS NULL AND image_data IS NOT NULL");
    $ok[] = "Migrated legacy msg_type NULLs";
} catch (PDOException $e) { /* column may not exist yet — safe to ignore */ }

// ── Seed default data ──────────────────────────────────────────
if (!$pdo->query("SELECT COUNT(*) FROM channels")->fetchColumn()) {
    $pdo->exec("INSERT INTO channels(name,type,position) VALUES
        ('general','text',1),('media','text',2),
        ('gaming','text',3),('announcements','announcement',4)");
    $pdo->exec("INSERT INTO messages(channel_id,user_id,username,msg_type,content,is_system)
        VALUES(1,NULL,'SYSTEM','system','Welcome to BetterChat!',1)");
    $ok[] = "Default channels seeded";
}
try {
    $pdo->exec("INSERT IGNORE INTO site_config(id, maintenance, maintenance_msg) VALUES
        (1, 0, 'BetterChat is currently under maintenance. Check back soon!')");
    $ok[] = "Configuration ready";
} catch (PDOException $e) {}

// Move old settings to site_config if present
try {
    $rows = $pdo->query("SELECT `key`, value FROM settings")->fetchAll(PDO::FETCH_KEY_PAIR);
    if (!empty($rows)) {
        if (isset($rows['maintenance'])) $pdo->exec("UPDATE site_config SET maintenance=" . (int)$rows['maintenance'] . " WHERE id=1");
        if (isset($rows['maintenance_msg'])) $pdo->prepare("UPDATE site_config SET maintenance_msg=? WHERE id=1")->execute([$rows['maintenance_msg']]);
        if (isset($rows['allow_images'])) $pdo->exec("UPDATE site_config SET allow_images=" . (int)$rows['allow_images'] . " WHERE id=1");
        if (isset($rows['allow_audio'])) $pdo->exec("UPDATE site_config SET allow_audio=" . (int)$rows['allow_audio'] . " WHERE id=1");
        if (isset($rows['custom_wordle'])) $pdo->prepare("UPDATE site_config SET custom_wordle=? WHERE id=1")->execute([$rows['custom_wordle']]);

        if (!empty($rows['vapid_public']) && !empty($rows['vapid_private'])) {
            $pdo->prepare("INSERT IGNORE INTO vapid_keys(id, public_key, private_key) VALUES(1, ?, ?)")
                ->execute([$rows['vapid_public'], $rows['vapid_private']]);
        }
        
        $pdo->exec("DROP TABLE settings");
        $ok[] = "Migrated from settings table to typed configs";
    }
} catch (PDOException $e) {}
?><!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>BetterChat Setup</title>
<style>
  body{background:#0f172a;color:#e2e8f0;font-family:system-ui,sans-serif;padding:40px;max-width:640px;margin:auto}
  h1{background:linear-gradient(to right,#3b82f6,#06b6d4);-webkit-background-clip:text;-webkit-text-fill-color:transparent;font-size:1.8rem;font-weight:800;margin-bottom:20px}
  .ok{color:#34d399;margin:4px 0}.err{color:#f87171;margin:4px 0}
  a{color:#3b82f6}.done{background:#172036;border:1px solid #1e3a5f;border-radius:8px;padding:16px;margin-top:20px;color:#34d399;font-size:1rem}
</style>
</head>
<body>
<h1>BetterChat — Setup / Upgrade</h1>
<?php foreach ($ok  as $s): ?><p class="ok">✓ <?= htmlspecialchars($s) ?></p><?php endforeach; ?>
<?php foreach ($err as $e): ?><p class="err">✗ <?= htmlspecialchars($e) ?></p><?php endforeach; ?>
<?php if (empty($err)): ?>
  <div class="done">✓ All done! <strong>You can safely run this page again anytime after an upgrade.</strong><br><a href="index.php">→ Open BetterChat</a></div>
<?php endif; ?>
</body>
</html>
