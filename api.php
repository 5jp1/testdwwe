<?php
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With, X-Auth-Token');
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}
session_set_cookie_params(["samesite" => "None", "secure" => true]);
session_start();
header("Content-Security-Policy: frame-ancestors *");
header("X-Frame-Options: ALLOWALL");
require_once 'db.php';
header('Content-Type: application/json');

$pdo = getDB();

// ── Token-based Auth Support for Remote / Cross-Origin Clients ───────────────
$auth_token = '';
if (!empty($_SERVER['HTTP_AUTHORIZATION'])) {
    $auth_h = trim($_SERVER['HTTP_AUTHORIZATION']);
    $auth_token = (stripos($auth_h, 'Bearer ') === 0) ? substr($auth_h, 7) : $auth_h;
} elseif (!empty($_REQUEST['token'])) {
    $auth_token = trim($_REQUEST['token']);
} elseif (!empty($_SERVER['HTTP_X_AUTH_TOKEN'])) {
    $auth_token = trim($_SERVER['HTTP_X_AUTH_TOKEN']);
}

if (!empty($auth_token)) {
    $decoded_token = base64_decode($auth_token);
    $parts = explode(':', $decoded_token, 2);
    if (count($parts) === 2) {
        $t_uid = (int)$parts[0];
        $t_hash = $parts[1];
        try {
            $tStmt = $pdo->prepare("SELECT * FROM users WHERE id=?");
            $tStmt->execute([$t_uid]);
            $tRow = $tStmt->fetch();
            if ($tRow && md5($tRow['password']) === $t_hash) {
                $_SESSION['user_id'] = (int)$tRow['id'];
                $_SESSION['username'] = $tRow['username'];
            }
        } catch (Exception $e) {}
    }
}

// ── Public API Actions (Login, Register, Ping, Auth Check) ───────────────────
$action = $_REQUEST['action'] ?? '';

if ($action === 'ping') {
    echo json_encode(['ok' => true, 'service' => 'BetterChat API', 'server_time' => date('c')]);
    exit;
}

if ($action === 'login') {
    $u = trim($_POST['username'] ?? $_GET['username'] ?? '');
    $p = trim($_POST['password'] ?? $_GET['password'] ?? '');
    if (!$u || !$p) {
        echo json_encode(['ok' => false, 'error' => 'Username and password are required.']);
        exit;
    }
    $s = $pdo->prepare("SELECT * FROM users WHERE username = ?");
    $s->execute([$u]);
    $user = $s->fetch();
    if ($user && password_verify($p, $user['password'])) {
        if (!empty($user['is_banned'])) {
            echo json_encode(['ok' => false, 'error' => 'Your account has been banned.']);
            exit;
        }
        $_SESSION['user_id'] = (int)$user['id'];
        $_SESSION['username'] = $user['username'];
        $tok = base64_encode($user['id'] . ':' . md5($user['password']));
        $isAdmin = (!empty($user['is_admin']) || $user['username'] === 'gollclock');
        echo json_encode([
            'ok' => true,
            'token' => $tok,
            'user' => [
                'id' => (int)$user['id'],
                'username' => $user['username'],
                'avatar' => $user['avatar'],
                'name_color' => $user['name_color'] ?? '#3b82f6',
                'is_admin' => (bool)$isAdmin
            ]
        ]);
        exit;
    }
    echo json_encode(['ok' => false, 'error' => 'Incorrect username or password.']);
    exit;
}

if ($action === 'register') {
    $u = trim($_POST['username'] ?? $_GET['username'] ?? '');
    $p = trim($_POST['password'] ?? $_GET['password'] ?? '');
    if (strlen($u) < 3 || strlen($u) > 30) {
        echo json_encode(['ok' => false, 'error' => 'Username must be between 3 and 30 characters.']);
        exit;
    }
    if (strlen($p) < 4) {
        echo json_encode(['ok' => false, 'error' => 'Password must be at least 4 characters.']);
        exit;
    }
    $s = $pdo->prepare("SELECT id FROM users WHERE username = ?");
    $s->execute([$u]);
    if ($s->fetch()) {
        echo json_encode(['ok' => false, 'error' => 'Username is already taken. Please choose another.']);
        exit;
    }
    $hash = password_hash($p, PASSWORD_BCRYPT);
    $isAdmin = ($u === 'gollclock') ? 1 : 0;
    $ins = $pdo->prepare("INSERT INTO users (username, password, name_color, is_admin) VALUES (?, ?, '#3b82f6', ?)");
    $ins->execute([$u, $hash, $isAdmin]);
    $newId = (int)$pdo->lastInsertId();
    $_SESSION['user_id'] = $newId;
    $_SESSION['username'] = $u;
    $tok = base64_encode($newId . ':' . md5($hash));
    echo json_encode([
        'ok' => true,
        'token' => $tok,
        'user' => [
            'id' => $newId,
            'username' => $u,
            'avatar' => null,
            'name_color' => '#3b82f6',
            'is_admin' => (bool)$isAdmin
        ]
    ]);
    exit;
}

if ($action === 'auth_check') {
    if (!empty($_SESSION['user_id'])) {
        $s = $pdo->prepare("SELECT id, username, avatar, name_color, is_admin, is_banned FROM users WHERE id=?");
        $s->execute([(int)$_SESSION['user_id']]);
        $me = $s->fetch();
        if ($me && empty($me['is_banned'])) {
            echo json_encode([
                'ok' => true,
                'user' => [
                    'id' => (int)$me['id'],
                    'username' => $me['username'],
                    'avatar' => $me['avatar'],
                    'name_color' => $me['name_color'] ?? '#3b82f6',
                    'is_admin' => (!empty($me['is_admin']) || $me['username'] === 'gollclock')
                ]
            ]);
            exit;
        }
    }
    echo json_encode(['ok' => false, 'error' => 'Not authenticated']);
    exit;
}

if (empty($_SESSION['user_id'])) {
    echo json_encode(['ok' => false, 'error' => 'Not authenticated']); exit;
}

$uid   = (int)$_SESSION['user_id'];
$uname = $_SESSION['username'] ?? '';

// Load current user (defensive — fallback if new columns missing)
try {
    $pdo->exec("ALTER TABLE users ADD COLUMN IF NOT EXISTS last_ip VARCHAR(45) DEFAULT NULL");
    $pdo->exec("ALTER TABLE bans ADD COLUMN IF NOT EXISTS ban_type VARCHAR(20) DEFAULT 'account'");
    $pdo->exec("ALTER TABLE bans ADD COLUMN IF NOT EXISTS ban_icon VARCHAR(50) DEFAULT 'fa-gavel'");
    $pdo->exec("CREATE TABLE IF NOT EXISTS ip_bans (ip VARCHAR(45) PRIMARY KEY, reason TEXT, ban_icon VARCHAR(50) DEFAULT 'fa-gavel', created_at DATETIME DEFAULT CURRENT_TIMESTAMP)");
} catch (PDOException $e) {}

$ip = $_SERVER['REMOTE_ADDR'] ?? '';

// Check IP Ban
try {
    if ($ip) {
        $ipBanStmt = $pdo->prepare("SELECT reason FROM ip_bans WHERE ip=?");
        $ipBanStmt->execute([$ip]);
        if ($ipBan = $ipBanStmt->fetch()) {
            echo json_encode(['ok' => false, 'error' => 'IP Banned', 'banned_until' => 'permanent']); exit;
        }
    }
} catch (PDOException $e) {}

// Check Cookie Ban
if (isset($_COOKIE['_bc_bnd'])) {
    echo json_encode(['ok' => false, 'error' => 'Device Banned', 'banned_until' => 'permanent']); exit;
}

try {
    $meStmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
    $meStmt->execute([$uid]);
    $meRow = $meStmt->fetch();
    if ($meRow && $ip) {
        $pdo->prepare("UPDATE users SET last_ip=? WHERE id=?")->execute([$ip, $uid]);
    }
} catch (PDOException $e) {
    echo json_encode(['ok' => false, 'error' => 'DB error loading user']); exit;
}

if ($meRow && !empty($meRow['is_banned'])) {
    try {
        $banStmt = $pdo->prepare("SELECT * FROM bans WHERE user_id=? ORDER BY id DESC LIMIT 1");
        $banStmt->execute([$uid]);
        $ban = $banStmt->fetch();

        if ($ban) {
            $duration = strtolower(trim($ban['duration'] ?? 'permanent'));
            $created = strtotime($ban['created_at']);
            $expired = false;

            if ($duration !== 'permanent' && preg_match('/^(\d+)\s*(minute|minutes|hour|hours|day|days|week|weeks)$/', $duration, $m)) {
                $amount = (int)$m[1];
                $unit = $m[2];
                $expireTime = strtotime("+{$amount} {$unit}", $created);
                if (time() >= $expireTime) {
                    $expired = true;
                }
            }

            if ($expired) {
                $pdo->prepare("UPDATE users SET is_banned=0 WHERE id=?")->execute([$uid]);
            } else {
                if (($ban['ban_type'] ?? '') === 'cookie') {
                    setcookie('_bc_bnd', '1', time() + 10 * 365 * 24 * 3600, '/');
                }
                $msg = !empty($ban['reason']) ? $ban['reason'] : 'Account suspended';
                echo json_encode(['ok' => false, 'error' => $msg, 'banned_until' => $ban['duration'], 'ban_type' => $ban['ban_type'] ?? 'account']); exit;
            }
        }
    } catch (PDOException $e) {}
}

if (!$meRow) {
    echo json_encode(['ok' => false, 'error' => 'Account suspended']); exit;
}

if (!empty($meRow['force_logout'])) {
    $pdo->prepare("UPDATE users SET force_logout=0 WHERE id=?")->execute([$uid]);
    echo json_encode(['ok' => false, 'error' => 'force_logout']); exit;
}

// is_admin: column may not exist yet — fall back to username check
$isAdmin     = (!empty($meRow['is_admin']) || $uname === 'gollclock');
$isSuperAdmin = ($uname === 'gollclock');
$myPerms = [];

if (!empty($meRow['role_id'])) {
    try {
        $r = $pdo->prepare("SELECT permissions FROM roles WHERE id=?");
        $r->execute([$meRow['role_id']]);
        $role = $r->fetch();
        if ($role) {
           $myPerms = json_decode($role['permissions'], true) ?: [];
           if(count($myPerms) > 0) $isAdmin = true;
        }
    } catch(PDOException $e) {}
}

// Update last_seen
try { $pdo->prepare("UPDATE users SET last_seen = NOW() WHERE id = ?")->execute([$uid]); } catch (PDOException $e) {}

// ── Helpers ────────────────────────────────────────────────────────────────
function requireAdmin(bool $isAdmin): void {
    if (!$isAdmin) { echo json_encode(['ok' => false, 'error' => 'Admin only']); exit; }
}

function requirePerm(string $perm, bool $isSuperAdmin, array $myPerms): void {
    if ($isSuperAdmin) return;
    if (empty($myPerms[$perm])) {
        echo json_encode(['ok' => false, 'error' => 'Missing permission: ' . $perm]);
        exit;
    }
}

function isMaintenance(PDO $pdo): bool {
    try {
        $r = $pdo->query("SELECT maintenance FROM site_config WHERE id = 1")->fetch();
        return $r && $r['maintenance'] == 1;
    } catch (PDOException $e) { return false; }
}

function checkChannelAccess(PDO $pdo, int $cid, int $uid, bool $isAdmin): bool {
    if ($isAdmin) return true;
    if (!colExists($pdo, 'channels', 'type')) return true;
    $stmt = $pdo->prepare("SELECT type, dm_user_1, dm_user_2 FROM channels WHERE id=?");
    $stmt->execute([$cid]);
    $row = $stmt->fetch();
    if (!$row) return false;
    if ($row['type'] === 'dm') {
        if ($row['dm_user_1'] != $uid && $row['dm_user_2'] != $uid) return false;
    }
    return true;
}

// ── Column existence cache (check once per request) ────────────────────────
function colExists(PDO $pdo, string $table, string $col): bool {
    static $cache = [];
    $key = "$table.$col";
    if (!isset($cache[$key])) {
        try {
            $db = $pdo->query("SELECT DATABASE()")->fetchColumn();
            $s  = $pdo->prepare(
                "SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
                 WHERE TABLE_SCHEMA=? AND TABLE_NAME=? AND COLUMN_NAME=?"
            );
            $s->execute([$db, $table, $col]);
            $cache[$key] = (bool)$s->fetchColumn();
        } catch (PDOException $e) { $cache[$key] = false; }
    }
    return $cache[$key];
}

// ── Helper: Trigger Web Push for channel ────────────────────────────────────
function triggerWebPush($pdo, $cid, $senderUid) {
    try {
        $pdo->query("SELECT 1 FROM push_subscriptions LIMIT 1"); // Check table exists
    } catch(Exception $e) { return; }

    require_once 'webpush.php';
    $wp = new WebPush($pdo);

    // Get all subscribed users EXCEPT sender. 
    // In DMs, only the other person. In public channels, everyone who isn't banned.
    $st = $pdo->prepare("SELECT type, name FROM channels WHERE id = ?");
    $st->execute([$cid]);
    $ch = $st->fetch();
    if(!$ch) return;

    if (str_starts_with($ch['type'], 'dm_')) {
        $parts = explode('_', $ch['type']);
        $u1 = (int)$parts[1]; $u2 = (int)$parts[2];
        $targetUid = ($u1 === $senderUid) ? $u2 : $u1;
        $subs = $pdo->prepare("SELECT p.endpoint, p.auth, p.p256dh FROM push_subscriptions p JOIN users u ON u.id=p.user_id WHERE p.user_id = ? AND u.is_banned=0");
        $subs->execute([$targetUid]);
    } else {
        $subs = $pdo->prepare("SELECT p.endpoint, p.auth, p.p256dh FROM push_subscriptions p JOIN users u ON u.id=p.user_id WHERE p.user_id != ? AND u.is_banned=0");
        $subs->execute([$senderUid]);
    }

    $endpoints = $subs->fetchAll();
    foreach($endpoints as $sub) {
        $wp->sendPush($sub['endpoint'], $sub['auth'], $sub['p256dh']);
    }
}

// ── Router ─────────────────────────────────────────────────────────────────
try { switch ($action) {

// ── Login / Switch handling ───────────────────────────────────────────────
case 'get_vapid_key': {
    require_once 'webpush.php';
    $wp = new WebPush($pdo);
    echo json_encode(['ok'=>true, 'publicKey' => $wp->getPublicKey()]);
    break;
}

case 'subscribe_push': {
    $endpoint = $_POST['endpoint'] ?? '';
    $p256dh = $_POST['p256dh'] ?? '';
    $auth = $_POST['auth'] ?? '';
    if (!$endpoint) { echo json_encode(['ok'=>false]); break; }
    
    // Quick auto-create table safeguard
    $pdo->exec("CREATE TABLE IF NOT EXISTS `push_subscriptions`(
      `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      `user_id` INT UNSIGNED NOT NULL,
      `endpoint` TEXT NOT NULL,
      `p256dh` VARCHAR(255) NOT NULL,
      `auth` VARCHAR(255) NOT NULL,
      `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    $pdo->prepare("DELETE FROM push_subscriptions WHERE endpoint=?")->execute([$endpoint]);
    $pdo->prepare("INSERT INTO push_subscriptions (user_id, endpoint, p256dh, auth) VALUES (?,?,?,?)")
        ->execute([$uid, $endpoint, $p256dh, $auth]);
    echo json_encode(['ok'=>true]);
    break;
}

case 'get_offline_notifications': {
    // When service worker wakes up, it calls this to see what happened.
    // We'll just return the newest unread messages
    $s = $pdo->prepare("SELECT m.id, m.username, m.content, m.msg_type, c.name, c.type 
                        FROM messages m 
                        JOIN channels c ON c.id=m.channel_id 
                        WHERE m.user_id != ? AND m.is_system=0 
                          AND (m.msg_type != 'webrtc' OR m.content LIKE '%\"type\":\"call_request\"%')
                        ORDER BY m.id DESC LIMIT 1");
    $s->execute([$uid]);
    $msg = $s->fetch();
    echo json_encode(['ok'=>true, 'message'=>$msg]);
    break;
}

// ── Channels ────────────────────────────────────────────────────────────────
case 'get_channels':
    $hasType = colExists($pdo, 'channels', 'type');
    if ($hasType) {
        // Ensure "dm" is in the enum to avoid breaking DM channels
        try {
            $pdo->exec("ALTER TABLE channels MODIFY COLUMN type ENUM('text','announcement','dm') NOT NULL DEFAULT 'text'");
        } catch (\Throwable $e) {}
        $pdo->exec("DELETE FROM channels WHERE name = 'Voice Chat' AND type = 'voice'");
        
        // Hide DMs from the main channel list, also hide if type got corrupted to '' or 'text' but dm_user_1 is NOT NULL
        if (colExists($pdo, 'channels', 'dm_user_1')) {
            $rows = $pdo->query("SELECT * FROM channels WHERE type != 'dm' AND dm_user_1 IS NULL ORDER BY position")->fetchAll();
        } else {
            $rows = $pdo->query("SELECT * FROM channels WHERE type != 'dm' ORDER BY position")->fetchAll();
        }
    } else {
        $rows = $pdo->query("SELECT * FROM channels ORDER BY position")->fetchAll();
    }
    echo json_encode(['ok' => true, 'channels' => $rows]);
    break;

case 'get_or_create_dm': {
    $target_id = (int)($_POST['target_id'] ?? 0);
    if ($target_id <= 0) { echo json_encode(['ok'=>false, 'error'=>'Invalid user']); break; }
    
    if (!colExists($pdo, 'channels', 'dm_user_1')) {
        try {
            $pdo->exec("ALTER TABLE `channels` MODIFY `type` ENUM('text','announcement','dm') NOT NULL DEFAULT 'text'");
            $pdo->exec("ALTER TABLE `channels` ADD COLUMN `dm_user_1` INT UNSIGNED DEFAULT NULL");
            $pdo->exec("ALTER TABLE `channels` ADD COLUMN `dm_user_2` INT UNSIGNED DEFAULT NULL");
        } catch (Exception $e) {
            echo json_encode(['ok'=>false, 'error'=>'DB setup failed: ' . $e->getMessage()]);
            break;
        }
    }
    
    $u1 = min($uid, $target_id);
    $u2 = max($uid, $target_id);
    
    $stmt = $pdo->prepare("SELECT id FROM channels WHERE type='dm' AND dm_user_1=? AND dm_user_2=?");
    $stmt->execute([$u1, $u2]);
    $cid = $stmt->fetchColumn();
    
    if (!$cid) {
        $stmt = $pdo->prepare("INSERT INTO channels (name, type, dm_user_1, dm_user_2) VALUES ('DM', 'dm', ?, ?)");
        $stmt->execute([$u1, $u2]);
        $cid = $pdo->lastInsertId();
    }
    
    $tname = $pdo->prepare("SELECT username FROM users WHERE id=?");
    $tname->execute([$target_id]);
    $target_name = $tname->fetchColumn() ?: 'Unknown';
    
    echo json_encode(['ok'=>true, 'channel_id'=>$cid, 'target_name'=>$target_name]);
    break;
}

// ── Get messages ────────────────────────────────────────────────────────────
case 'get_messages': {
    $cid   = (int)($_GET['channel_id'] ?? 1);
    $after  = (int)($_GET['after_id']   ?? 0);
    $before = (int)($_GET['before_id']  ?? 0);

    if (!checkChannelAccess($pdo, $cid, $uid, $isAdmin)) {
        echo json_encode(['ok' => true, 'messages' => []]);
        break;
    }

    // Build SELECT defensively depending on which columns exist
    $hasMsgType    = colExists($pdo, 'messages', 'msg_type');
    $hasFileData   = colExists($pdo, 'messages', 'file_data');
    $hasFileName   = colExists($pdo, 'messages', 'file_name');
    $hasFileMime   = colExists($pdo, 'messages', 'file_mime');
    $hasEditedAt   = colExists($pdo, 'messages', 'edited_at');
    $hasIsAdmin    = colExists($pdo, 'users',    'is_admin');
    $hasTags       = colExists($pdo, 'users',    'custom_tag');
    $hasNitro      = colExists($pdo, 'users',    'is_nitro');
    $hasReplyTo    = colExists($pdo, 'messages', 'reply_to');
    
    $msgCols  = "m.id, m.channel_id, m.user_id, m.username, m.content, m.image_data, m.is_system, m.created_at";
    $msgCols .= $hasMsgType  ? ", m.msg_type"  : ", 'text' AS msg_type";
    $msgCols .= $hasFileData ? ", m.file_data" : ", NULL AS file_data";
    $msgCols .= $hasFileName ? ", m.file_name" : ", NULL AS file_name";
    $msgCols .= $hasFileMime ? ", m.file_mime" : ", NULL AS file_mime";
    $msgCols .= $hasEditedAt ? ", m.edited_at" : ", NULL AS edited_at";
    $msgCols .= $hasReplyTo  ? ", m.reply_to, (SELECT username FROM messages r WHERE r.id=m.reply_to) AS reply_username, (SELECT content FROM messages r WHERE r.id=m.reply_to) AS reply_content" : ", NULL AS reply_to, NULL AS reply_username, NULL AS reply_content";
    
    $hasAvatarOverlay = colExists($pdo, 'users', 'avatar_overlay');
    $userCols  = "u.avatar, u.name_color";
    $userCols .= $hasIsAdmin ? ", u.is_admin AS sender_is_admin" : ", 0 AS sender_is_admin";
    $userCols .= $hasTags ? ", u.custom_tag, u.custom_tag_color" : ", NULL AS custom_tag, NULL AS custom_tag_color";
    $userCols .= $hasNitro ? ", u.is_nitro" : ", 0 AS is_nitro";
    $userCols .= $hasAvatarOverlay ? ", u.avatar_overlay" : ", NULL AS avatar_overlay";

    if ($after > 0) {
        $s = $pdo->prepare(
            "SELECT $msgCols, $userCols
             FROM messages m LEFT JOIN users u ON u.id = m.user_id
             WHERE m.channel_id = ? AND m.id > ?
             ORDER BY m.id ASC LIMIT 40"
        );
        $s->execute([$cid, $after]);
    } else if ($before > 0) {
        $s = $pdo->prepare(
            "SELECT $msgCols, $userCols
             FROM messages m LEFT JOIN users u ON u.id = m.user_id
             WHERE m.channel_id = ? AND m.id < ?
             ORDER BY m.id DESC LIMIT 40"
        );
        $s->execute([$cid, $before]);
    } else {
        $s = $pdo->prepare(
            "SELECT $msgCols, $userCols
             FROM messages m LEFT JOIN users u ON u.id = m.user_id
             WHERE m.channel_id = ?
             ORDER BY m.id DESC LIMIT 40"
        );
        $s->execute([$cid]);
    }
    $msgs = $s->fetchAll();
    if ($after === 0) $msgs = array_reverse($msgs);
    echo json_encode(['ok' => true, 'messages' => $msgs]);
    break;
}

// ── Send WebRTC Signaling ───────────────────────────────────────────────────
case 'send_webrtc': {
    $cid     = (int)($_POST['channel_id'] ?? 1);
    // Only allow in DMs
    $st = $pdo->prepare("SELECT type FROM channels WHERE id = ?");
    $st->execute([$cid]);
    $ch = $st->fetch();
    if(!$ch || !str_starts_with($ch['type'], 'dm_')) { echo json_encode(['ok'=>false, 'error'=>'Must be DM']); break; }

    if (!checkChannelAccess($pdo, $cid, $uid, $isAdmin)) { echo json_encode(['ok' => false, 'error' => 'Access denied']); break; }
    
    $payload = $_POST['payload'] ?? '';
    if (!$payload) { echo json_encode(['ok' => false, 'error' => 'Empty payload']); break; }

    if (colExists($pdo, 'messages', 'msg_type')) {
        $pdo->prepare("INSERT INTO messages(channel_id,user_id,username,msg_type,content) VALUES(?,?,?,'webrtc',?)")
            ->execute([$cid, $uid, $uname, $payload]);
    } else {
        // Fallback for older database
        $pdo->prepare("INSERT INTO messages(channel_id,user_id,username,content) VALUES(?,?,?,?)")
            ->execute([$cid, $uid, $uname, 'WEBRTC:'.$payload]);
    }
    
    echo json_encode(['ok' => true]);
    break;
}

// ── Send text ────────────────────────────────────────────────────────────────
case 'send_message': {
    if ($meRow['is_muted'] && !$isAdmin) { echo json_encode(['ok' => false, 'error' => 'You are muted.']); break; }
    $cid     = (int)($_POST['channel_id'] ?? 1);
    if (!checkChannelAccess($pdo, $cid, $uid, $isAdmin)) { echo json_encode(['ok' => false, 'error' => 'Access denied']); break; }
    $content = trim($_POST['content'] ?? '');
    $reply_to = (int)($_POST['reply_to'] ?? 0);
    $reply_to = $reply_to > 0 ? $reply_to : null;
    
    if ($meRow['shadowbanned'] && !$isAdmin) { echo json_encode(['ok' => true]); break; }
    if ($content === '') { echo json_encode(['ok' => false, 'error' => 'Empty message']); break; }
    if (strlen($content) > 4000) $content = substr($content, 0, 4000);

    if (colExists($pdo, 'messages', 'reply_to')) {
        $pdo->prepare("INSERT INTO messages(channel_id,user_id,username,msg_type,content,reply_to) VALUES(?,?,?,'text',?,?)")
            ->execute([$cid, $uid, $uname, $content, $reply_to]);
    } elseif (colExists($pdo, 'messages', 'msg_type')) {
        $pdo->prepare("INSERT INTO messages(channel_id,user_id,username,msg_type,content) VALUES(?,?,?,'text',?)")
            ->execute([$cid, $uid, $uname, $content]);
    } else {
        $pdo->prepare("INSERT INTO messages(channel_id,user_id,username,content) VALUES(?,?,?,?)")
            ->execute([$cid, $uid, $uname, $content]);
    }
    triggerWebPush($pdo, $cid, $uid);
    echo json_encode(['ok' => true, 'id' => (int)$pdo->lastInsertId()]);
    break;
}

// ── Edit message ────────────────────────────────────────────────────────────
case 'edit_message': {
    if ($meRow['is_muted'] && !$isAdmin) { echo json_encode(['ok' => false, 'error' => 'You are muted.']); break; }
    $mid     = (int)($_POST['message_id'] ?? 0);
    $content = trim($_POST['content'] ?? '');
    if ($content === '') { echo json_encode(['ok' => false, 'error' => 'Empty']); break; }

    $s = $pdo->prepare("SELECT user_id FROM messages WHERE id = ?");
    $s->execute([$mid]); $msg = $s->fetch();
    if (!$msg) { echo json_encode(['ok' => false, 'error' => 'Not found']); break; }
    if ($msg['user_id'] != $uid && !$isAdmin) { echo json_encode(['ok' => false, 'error' => 'Forbidden']); break; }

    if (colExists($pdo, 'messages', 'edited_at')) {
        $pdo->prepare("UPDATE messages SET content = ?, edited_at = NOW() WHERE id = ?")->execute([$content, $mid]);
    } else {
        $pdo->prepare("UPDATE messages SET content = ? WHERE id = ?")->execute([$content, $mid]);
    }
    echo json_encode(['ok' => true]);
    break;
}

// ── Delete message ───────────────────────────────────────────────────────────
case 'delete_message': {
    $mid = (int)($_POST['message_id'] ?? 0);
    $s   = $pdo->prepare("SELECT user_id FROM messages WHERE id = ?");
    $s->execute([$mid]); $msg = $s->fetch();
    if (!$msg) { echo json_encode(['ok' => false, 'error' => 'Not found']); break; }
    if ($msg['user_id'] != $uid && !$isAdmin) { echo json_encode(['ok' => false, 'error' => 'Forbidden']); break; }
    $pdo->prepare("DELETE FROM messages WHERE id = ?")->execute([$mid]);
    echo json_encode(['ok' => true]);
    break;
}

// ── Send image ───────────────────────────────────────────────────────────────
case 'send_image': {
    if ($meRow['is_muted'] && !$isAdmin) { echo json_encode(['ok' => false, 'error' => 'You are muted.']); break; }
    if ($meRow['shadowbanned'] && !$isAdmin) { echo json_encode(['ok' => true]); break; }
    if (!$meRow['can_img'] && !$isAdmin) { echo json_encode(['ok' => false, 'error' => 'You cannot send images.']); break; }
    $allowImgs = $pdo->query("SELECT allow_images FROM site_config WHERE id=1")->fetchColumn() ?? 1;
    if ($allowImgs == 0 && !$isAdmin) { echo json_encode(['ok' => false, 'error' => 'Image uploads disabled']); break; }
    $cid     = (int)($_POST['channel_id'] ?? 1);
    if (!checkChannelAccess($pdo, $cid, $uid, $isAdmin)) { echo json_encode(['ok' => false, 'error' => 'Access denied']); break; }
    $imgData = $_POST['image_data'] ?? '';
    
    $isBase64 = preg_match('/^data:image\/(png|jpeg|gif|webp);base64,/', $imgData);
    $isGiphy = preg_match('/^https?:\/\/(media\d*\.giphy\.com|giphy\.com)\/.*\.gif/', $imgData);
    
    if (!$isBase64 && !$isGiphy) {
        echo json_encode(['ok' => false, 'error' => 'Invalid image data']); break;
    }
    if (strlen($imgData) > 6000000) { echo json_encode(['ok' => false, 'error' => 'Image too large']); break; }

    if (colExists($pdo, 'messages', 'msg_type')) {
        $pdo->prepare("INSERT INTO messages(channel_id,user_id,username,msg_type,image_data) VALUES(?,?,?,'image',?)")
            ->execute([$cid, $uid, $uname, $imgData]);
    } else {
        $pdo->prepare("INSERT INTO messages(channel_id,user_id,username,image_data) VALUES(?,?,?,?)")
            ->execute([$cid, $uid, $uname, $imgData]);
    }
    triggerWebPush($pdo, $cid, $uid);
    echo json_encode(['ok' => true, 'id' => (int)$pdo->lastInsertId()]);
    break;
}

// ── Send audio ───────────────────────────────────────────────────────────────
case 'send_audio': {
    if ($meRow['is_muted'] && !$isAdmin) { echo json_encode(['ok' => false, 'error' => 'You are muted.']); break; }
    if ($meRow['shadowbanned'] && !$isAdmin) { echo json_encode(['ok' => true]); break; }
    if (!$meRow['can_audio'] && !$isAdmin) { echo json_encode(['ok' => false, 'error' => 'You cannot send audio.']); break; }
    $allowAudio = $pdo->query("SELECT allow_audio FROM site_config WHERE id=1")->fetchColumn() ?? 1;
    if ($allowAudio == 0 && !$isAdmin) { echo json_encode(['ok' => false, 'error' => 'Audio uploads disabled']); break; }
    $cid       = (int)($_POST['channel_id'] ?? 1);
    if (!checkChannelAccess($pdo, $cid, $uid, $isAdmin)) { echo json_encode(['ok' => false, 'error' => 'Access denied']); break; }
    $audioData = $_POST['audio_data'] ?? '';
    if (!preg_match('/^data:.*?;base64,/', $audioData)) {
        echo json_encode(['ok' => false, 'error' => 'Invalid audio format']); break;
    }
    if (strlen($audioData) > 8000000) { echo json_encode(['ok' => false, 'error' => 'Audio too large']); break; }

    if (colExists($pdo, 'messages', 'file_data')) {
        $pdo->prepare("INSERT INTO messages(channel_id,user_id,username,msg_type,file_data) VALUES(?,?,?,'audio',?)")
            ->execute([$cid, $uid, $uname, $audioData]);
    } else {
        echo json_encode(['ok' => false, 'error' => 'Please run setup.php to enable audio']);
    }
    triggerWebPush($pdo, $cid, $uid);
    echo json_encode(['ok' => true, 'id' => (int)$pdo->lastInsertId()]);
    break;
}

// ── Send file (admin only) ────────────────────────────────────────────────────
case 'send_file': {
    requireAdmin($isAdmin);
    $cid      = (int)($_POST['channel_id'] ?? 1);
    if (!checkChannelAccess($pdo, $cid, $uid, $isAdmin)) { echo json_encode(['ok' => false, 'error' => 'Access denied']); break; }
    $fileData = $_POST['file_data']  ?? '';
    $fileName = basename($_POST['file_name'] ?? 'file');
    $fileMime = $_POST['file_mime']  ?? 'application/octet-stream';
    if (empty($fileData)) { echo json_encode(['ok' => false, 'error' => 'No file data']); break; }
    if (strlen($fileData) > 10000000) { echo json_encode(['ok' => false, 'error' => 'File too large']); break; }

    if (!colExists($pdo, 'messages', 'file_data')) {
        echo json_encode(['ok' => false, 'error' => 'Run setup.php to enable file sending']); break;
    }
    $pdo->prepare("INSERT INTO messages(channel_id,user_id,username,msg_type,file_data,file_name,file_mime) VALUES(?,?,?,'file',?,?,?)")
        ->execute([$cid, $uid, $uname, $fileData, $fileName, $fileMime]);
    triggerWebPush($pdo, $cid, $uid);
    echo json_encode(['ok' => true, 'id' => (int)$pdo->lastInsertId()]);
    break;
}

// ── Send iframe (admin only) ──────────────────────────────────────────────────
case 'send_iframe': {
    requireAdmin($isAdmin);
    $cid   = (int)($_POST['channel_id'] ?? 1);
    $url   = trim($_POST['url'] ?? '');
    $label = trim($_POST['label'] ?? $url);
    if (!filter_var($url, FILTER_VALIDATE_URL)) { echo json_encode(['ok' => false, 'error' => 'Invalid URL']); break; }

    if (colExists($pdo, 'messages', 'file_name')) {
        $pdo->prepare("INSERT INTO messages(channel_id,user_id,username,msg_type,content,file_name) VALUES(?,?,?,'iframe',?,?)")
            ->execute([$cid, $uid, $uname, $url, $label]);
    } else {
        $pdo->prepare("INSERT INTO messages(channel_id,user_id,username,content) VALUES(?,?,?,?)")
            ->execute([$cid, $uid, $uname, "[Embed: $url]"]);
    }
    echo json_encode(['ok' => true, 'id' => (int)$pdo->lastInsertId()]);
    break;
}

// ── Members ───────────────────────────────────────────────────────────────────
case 'get_members': {
    $hasIsAdmin = colExists($pdo, 'users', 'is_admin');
    $hasTags = colExists($pdo, 'users', 'custom_tag');
    $hasAvatarOverlay = colExists($pdo, 'users', 'avatar_overlay');
    $tagCols = $hasTags ? ", custom_tag, custom_tag_color" : ", NULL AS custom_tag, NULL AS custom_tag_color";
    $cols = "id, username, avatar, name_color, is_banned,
             (last_seen >= DATE_SUB(NOW(), INTERVAL 3 MINUTE)) AS is_online"
          . ($hasIsAdmin ? ", is_admin" : ", 0 AS is_admin")
          . ($hasAvatarOverlay ? ", avatar_overlay" : ", NULL AS avatar_overlay")
          . $tagCols;
    $rows = $pdo->query("SELECT $cols FROM users WHERE is_banned=0 ORDER BY is_online DESC, username ASC")->fetchAll();
    echo json_encode(['ok' => true, 'members' => $rows]);
    break;
}

// ── Friends ───────────────────────────────────────────────────────────────────
case 'get_friends': {
    $hasIsAdmin = colExists($pdo, 'users', 'is_admin');
    $hasAvatarOverlay = colExists($pdo, 'users', 'avatar_overlay');
    $cols = "u.id, u.username, u.avatar, u.name_color,
             (u.last_seen >= DATE_SUB(NOW(), INTERVAL 3 MINUTE)) AS is_online"
          . ($hasIsAdmin ? ", u.is_admin" : ", 0 AS is_admin")
          . ($hasAvatarOverlay ? ", u.avatar_overlay" : ", NULL AS avatar_overlay");
    $s = $pdo->prepare(
        "SELECT $cols FROM friends f
         JOIN users u ON u.id = CASE WHEN f.user_a=? THEN f.user_b ELSE f.user_a END
         WHERE (f.user_a=? OR f.user_b=?) AND u.is_banned=0
         ORDER BY is_online DESC, u.username ASC"
    );
    $s->execute([$uid, $uid, $uid]);
    echo json_encode(['ok' => true, 'friends' => $s->fetchAll()]);
    break;
}

case 'remove_friend': {
    $oid = (int)($_POST['user_id'] ?? 0);
    $pdo->prepare("DELETE FROM friends WHERE (user_a=? AND user_b=?) OR (user_a=? AND user_b=?)")
        ->execute([$uid, $oid, $oid, $uid]);
    echo json_encode(['ok' => true]);
    break;
}

// ── Profile update ─────────────────────────────────────────────────────────────
case 'submit_feedback': {
    $msg = trim($_POST['message'] ?? '');
    if(strlen($msg) < 5) {
        echo json_encode(['ok' => false, 'error' => 'Feedback message too short']);
        break;
    }
    try {
        $pdo->prepare("INSERT INTO feedback(user_id, message) VALUES(?,?)")->execute([$uid, $msg]);
        echo json_encode(['ok' => true]);
    } catch(PDOException $e) {
        echo json_encode(['ok' => false, 'error' => 'Failed. Maybe you need to run setup?']);
    }
    break;
}

case 'update_profile': {
    $color  = $_POST['name_color'] ?? '#3b82f6';
    $avatar = $_POST['avatar']     ?? null;
    $isVip  = !empty($meRow['is_vip']) || !empty($meRow['is_nitro']);
    
    if (!preg_match('/^#[0-9a-fA-F]{6}$/', $color)) $color = '#3b82f6';
    if ($avatar && strlen($avatar) > 6000000) { echo json_encode(['ok' => false, 'error' => 'Avatar too large']); break; }
    
    $avatarToSave = null;
    if ($isVip && !empty($_POST['avatar_url']) && filter_var($_POST['avatar_url'], FILTER_VALIDATE_URL)) {
        $avatarToSave = $_POST['avatar_url'];
    } else {
        if ($avatar && !preg_match('/^data:image\/(png|jpeg|gif|webp);base64,/', $avatar)) $avatar = null;
        if ($avatar) $avatarToSave = $avatar;
    }
    
    if ($avatarToSave !== null) {
        $pdo->prepare("UPDATE users SET name_color=?, avatar=? WHERE id=?")->execute([$color, $avatarToSave, $uid]);
    } else {
        $pdo->prepare("UPDATE users SET name_color=? WHERE id=?")->execute([$color, $uid]);
    }
    
    if ($isVip) {
        // Tag management
        if (isset($_POST['vip_tag']) && colExists($pdo, 'users', 'custom_tag')) {
            $vipTag = trim($_POST['vip_tag']);
            $pdo->prepare("UPDATE users SET custom_tag=? WHERE id=?")->execute([$vipTag ?: null, $uid]);
        }
        // Theme management
        if (isset($_POST['vip_theme'])) {
            try { 
                $pdo->exec("ALTER TABLE users ADD COLUMN IF NOT EXISTS site_theme VARCHAR(50) DEFAULT NULL"); 
                $pdo->exec("ALTER TABLE users MODIFY site_theme VARCHAR(50) DEFAULT NULL"); 
            } catch(Exception $e){}
            
            $th1 = trim($_POST['vip_theme']);
            $th2 = trim($_POST['vip_theme2'] ?? $th1);
            $th3 = trim($_POST['vip_accent'] ?? '#2563eb');
            
            if (preg_match('/^#[0-9a-fA-F]{3,6}$/', $th1) && preg_match('/^#[0-9a-fA-F]{3,6}$/', $th2) && preg_match('/^#[0-9a-fA-F]{3,6}$/', $th3)) {
                $combo = "$th1,$th2,$th3";
                $pdo->prepare("UPDATE users SET site_theme=? WHERE id=?")->execute([$combo, $uid]);
            }
        }
    }
    echo json_encode(['ok' => true]);
    break;
}

// ── Change password ─────────────────────────────────────────────────────────────
case 'change_password': {
    $oldPw = $_POST['old_password'] ?? '';
    $newPw = $_POST['new_password'] ?? '';
    if (strlen($newPw) < 6) { echo json_encode(['ok' => false, 'error' => 'Min 6 characters']); break; }
    if (!password_verify($oldPw, $meRow['password'])) { echo json_encode(['ok' => false, 'error' => 'Current password incorrect']); break; }
    $pdo->prepare("UPDATE users SET password=? WHERE id=?")->execute([password_hash($newPw, PASSWORD_BCRYPT), $uid]);
    echo json_encode(['ok' => true]);
    break;
}

// ── Friend requests ─────────────────────────────────────────────────────────────
case 'send_friend_request': {
    $toName = trim($_POST['to_username'] ?? '');
    if (strtolower($toName) === strtolower($uname)) { echo json_encode(['ok' => false, 'error' => "Can't friend yourself"]); break; }
    $s = $pdo->prepare("SELECT id FROM users WHERE username=? AND is_banned=0"); $s->execute([$toName]);
    $target = $s->fetch();
    if (!$target) { echo json_encode(['ok' => false, 'error' => 'User not found']); break; }
    $fc = $pdo->prepare("SELECT id FROM friends WHERE (user_a=? AND user_b=?) OR (user_a=? AND user_b=?)");
    $fc->execute([$uid, $target['id'], $target['id'], $uid]);
    if ($fc->fetch()) { echo json_encode(['ok' => false, 'error' => 'Already friends']); break; }
    $dup = $pdo->prepare("SELECT id FROM friend_requests WHERE ((from_id=? AND to_id=?) OR (from_id=? AND to_id=?)) AND status='pending'");
    $dup->execute([$uid, $target['id'], $target['id'], $uid]);
    if ($dup->fetch()) { echo json_encode(['ok' => false, 'error' => 'Request already pending']); break; }
    $pdo->prepare("INSERT INTO friend_requests(from_id,to_id) VALUES(?,?)")->execute([$uid, $target['id']]);
    $pdo->prepare("INSERT INTO inbox(to_id,type,content) VALUES(?,'system',?)")
        ->execute([$target['id'], "👥 $uname sent you a friend request!"]);
    echo json_encode(['ok' => true]);
    break;
}

case 'get_inbox': {
    $s = $pdo->prepare("SELECT fr.id,fr.from_id,u.username AS from_name,fr.created_at FROM friend_requests fr JOIN users u ON u.id=fr.from_id WHERE fr.to_id=? AND fr.status='pending' ORDER BY fr.created_at DESC");
    $s->execute([$uid]); $frs = $s->fetchAll();
    $s2 = $pdo->prepare("SELECT * FROM inbox WHERE (to_id=? OR to_id IS NULL) ORDER BY created_at DESC LIMIT 40");
    $s2->execute([$uid]); $msgs = $s2->fetchAll();
    $s3 = $pdo->prepare("SELECT COUNT(*) FROM inbox WHERE (to_id=? OR to_id IS NULL) AND is_read=0");
    $s3->execute([$uid]);
    echo json_encode(['ok' => true, 'friend_requests' => $frs, 'messages' => $msgs, 'unread' => (int)$s3->fetchColumn() + count($frs)]);
    break;
}

case 'respond_friend_request': {
    $frid   = (int)($_POST['fr_id'] ?? 0);
    $accept = ($_POST['accept'] ?? 'no') === 'yes';
    $s = $pdo->prepare("SELECT * FROM friend_requests WHERE id=? AND to_id=?"); $s->execute([$frid, $uid]); $fr = $s->fetch();
    if (!$fr) { echo json_encode(['ok' => false, 'error' => 'Not found']); break; }
    $pdo->prepare("UPDATE friend_requests SET status=? WHERE id=?")->execute([$accept ? 'accepted' : 'declined', $frid]);
    if ($accept) {
        $ex = $pdo->prepare("SELECT id FROM friends WHERE (user_a=? AND user_b=?) OR (user_a=? AND user_b=?)");
        $ex->execute([$uid, $fr['from_id'], $fr['from_id'], $uid]);
        if (!$ex->fetch()) $pdo->prepare("INSERT INTO friends(user_a,user_b) VALUES(?,?)")->execute([$uid, $fr['from_id']]);
        $pdo->prepare("INSERT INTO inbox(to_id,type,content) VALUES(?,'friend_accept',?)")->execute([$fr['from_id'], "✅ $uname accepted your friend request!"]);
    }
    echo json_encode(['ok' => true]);
    break;
}

case 'mark_inbox_read':
    $pdo->prepare("UPDATE inbox SET is_read=1 WHERE to_id=? OR to_id IS NULL")->execute([$uid]);
    echo json_encode(['ok' => true]); break;

// ══════════════════════════════════════════════════════════════════════════════
// ADMIN ENDPOINTS
// ══════════════════════════════════════════════════════════════════════════════

case 'admin_get_users': {
    requireAdmin($isAdmin);
    $q = trim($_GET['q'] ?? '');
    $hasIsAdmin = colExists($pdo, 'users', 'is_admin');
    $hasAvatarOverlay = colExists($pdo, 'users', 'avatar_overlay');
    
    $cols = "u.id, u.username, u.is_banned, u.last_seen, u.created_at, u.avatar, u.name_color,
             b.reason, b.duration, b.created_at AS ban_created_at,
             ba.username AS banned_by_name"
          . ($hasIsAdmin ? ", u.is_admin" : ", 0 AS is_admin")
          . ($hasAvatarOverlay ? ", u.avatar_overlay" : ", NULL AS avatar_overlay");
    $join = "LEFT JOIN bans b ON b.user_id = u.id AND b.id = (SELECT MAX(id) FROM bans WHERE user_id = u.id)
             LEFT JOIN users ba ON ba.id = b.banned_by";
    if ($q !== '') {
        $s = $pdo->prepare("SELECT $cols FROM users u $join WHERE u.username LIKE ? ORDER BY u.id DESC LIMIT 100");
        $s->execute(["%$q%"]);
    } else {
        $s = $pdo->query("SELECT $cols FROM users u $join ORDER BY u.id DESC LIMIT 200");
    }
    echo json_encode(['ok' => true, 'users' => $s->fetchAll()]);
    break;
}

case 'admin_get_bans': {
    requireAdmin($isAdmin);
    $q = trim($_GET['q'] ?? '');
    
    $hasAvatarOverlay = colExists($pdo, 'users', 'avatar_overlay');
    
    $cols = "b.id AS ban_id, b.reason, b.duration, b.created_at AS ban_created_at, u.id, u.username, u.avatar, u.name_color, ba.username AS banned_by_name"
          . ($hasAvatarOverlay ? ", u.avatar_overlay" : ", NULL AS avatar_overlay");
    $join = "JOIN users u ON u.id = b.user_id LEFT JOIN users ba ON ba.id = b.banned_by";
    if ($q !== '') {
        $s = $pdo->prepare("SELECT $cols FROM bans b $join WHERE u.username LIKE ? ORDER BY b.id DESC LIMIT 100");
        $s->execute(["%$q%"]);
    } else {
        $s = $pdo->query("SELECT $cols FROM bans b $join ORDER BY b.id DESC LIMIT 200");
    }
    echo json_encode(['ok' => true, 'bans' => $s->fetchAll()]);
    break;
}

case 'admin_announce': {
    requireAdmin($isAdmin);
    $text = trim($_POST['content'] ?? '');
    if ($text === '') { echo json_encode(['ok' => false, 'error' => 'Empty']); break; }
    $channels = $pdo->query("SELECT id FROM channels")->fetchAll(PDO::FETCH_COLUMN);
    if (colExists($pdo, 'messages', 'msg_type')) {
        $s = $pdo->prepare("INSERT INTO messages(channel_id,user_id,username,msg_type,content,is_system) VALUES(?,?,'SYSTEM','system',?,1)");
    } else {
        $s = $pdo->prepare("INSERT INTO messages(channel_id,user_id,username,content,is_system) VALUES(?,?,'SYSTEM',?,1)");
    }
    foreach ($channels as $cid) $s->execute([$cid, $uid, "📢 ANNOUNCEMENT: $text"]);
    $pdo->prepare("INSERT INTO inbox(to_id,type,content) VALUES(NULL,'announcement',?)")->execute(["📢 $text"]);
    echo json_encode(['ok' => true]);
    break;
}

case 'admin_ban': {
    requireAdmin($isAdmin);
    $tid    = (int)($_POST['user_id'] ?? 0);
    $reason = trim($_POST['reason']   ?? 'No reason');
    $banIcon = trim($_POST['ban_icon'] ?? 'fa-gavel');
    $dur    = trim($_POST['duration'] ?? 'permanent'); // 'permanent', 'timed' (but we overwrite), 'ip', 'cookie'
    $timeAmount = (int)($_POST['time_amount'] ?? 0);
    $timeUnit = trim($_POST['time_unit'] ?? 'days');
    
    $banType = 'account';
    if ($dur === 'ip') {
        $banType = 'ip';
        $dur = 'permanent';
    } elseif ($dur === 'cookie') {
        $banType = 'cookie';
        $dur = 'permanent';
    } elseif ($dur === 'timed' && $timeAmount > 0) {
        $dur = $timeAmount . ' ' . $timeUnit;
    }

    if ($tid === $uid) { echo json_encode(['ok' => false, 'error' => "Can't ban yourself"]); break; }
    // Non-superadmin can't ban another admin
    if (!$isSuperAdmin && colExists($pdo, 'users', 'is_admin')) {
        $tRow = $pdo->prepare("SELECT is_admin, last_ip FROM users WHERE id=?"); $tRow->execute([$tid]); $tRow = $tRow->fetch();
        if ($tRow && $tRow['is_admin']) { echo json_encode(['ok' => false, 'error' => 'Cannot ban another admin']); break; }
    } else {
        $tRow = $pdo->prepare("SELECT is_admin, last_ip FROM users WHERE id=?"); $tRow->execute([$tid]); $tRow = $tRow->fetch();
    }

    if ($banType === 'ip') {
        $targetIp = $tRow['last_ip'] ?? '';
        if (!$targetIp) {
            echo json_encode(['ok' => false, 'error' => "Cannot IP Ban: User's IP is unknown."]); break;
        }
        $pdo->prepare("INSERT IGNORE INTO ip_bans(ip, reason, ban_icon) VALUES(?,?,?)")->execute([$targetIp, $reason, $banIcon]);
    }

    $pdo->prepare("UPDATE users SET is_banned=1 WHERE id=?")->execute([$tid]);
    $pdo->prepare("INSERT INTO bans(user_id,reason,duration,banned_by,ban_type,ban_icon) VALUES(?,?,?,?,?,?)")->execute([$tid, $reason, $dur, $uid, $banType, $banIcon]);
    echo json_encode(['ok' => true]);
    break;
}

case 'admin_unban': {
    requireAdmin($isAdmin);
    $tid = (int)($_POST['user_id'] ?? 0);
    $pdo->prepare("UPDATE users SET is_banned=0 WHERE id=?")->execute([$tid]);
    $pdo->prepare("DELETE FROM bans WHERE user_id=?")->execute([$tid]);
    $pdo->prepare("INSERT INTO inbox(to_id,type,content) VALUES(?,'system',?)")->execute([$tid, '✅ You have been unbanned by an admin.']);
    echo json_encode(['ok' => true]);
    break;
}

case 'admin_action': {
    $tid = (int)($_POST['user_id'] ?? 0);
    $act = $_POST['act'] ?? '';

    // leave_control MUST come before requireAdmin — when controlling a non-admin
    // user the session IS that user so $isAdmin is false and requireAdmin blocks.
    if ($act === 'leave_control') {
        if (!empty($_SESSION['admin_original_id'])) {
            $_SESSION['user_id'] = $_SESSION['admin_original_id'];
            $_SESSION['username'] = $_SESSION['admin_original_name'];
            unset($_SESSION['admin_original_id']);
            unset($_SESSION['admin_original_name']);
            echo json_encode(['ok' => true]);
        } else {
            echo json_encode(['ok' => false, 'error' => 'Not in control mode']);
        }
        break;
    }

    requireAdmin($isAdmin);
    
    if ($tid === $uid) { 
        echo json_encode(['ok'=>false, 'error'=>"Can't perform this action on yourself"]); 
        break; 
    }
    
    $tRow = $pdo->prepare("SELECT id, username, is_admin FROM users WHERE id=?"); $tRow->execute([$tid]); $tUser = $tRow->fetch();
    if (!$tUser) {
        echo json_encode(['ok' => false, 'error' => 'User not found']);
        break;
    }

    if ($tUser['username'] === 'gollclock' && $act !== 'control' && $act !== 'seen_ip') { 
        echo json_encode(['ok'=>false, 'error'=>"Cannot modify superadmin"]); break; 
    }
    
    $actPermMap = [
        'delete' => 'ua-delete',
        'reset_pass' => 'ua-reset',
        'demote' => 'ua-promote',
        'promote' => 'ua-promote',
        'control' => 'ua-control',
        'kick' => 'ua-kick',
        'mute' => 'ua-mute',
        'unmute' => 'ua-mute',
        'remove_avatar' => 'ua-avatar',
        'reset_color' => 'ua-color',
        'set_tag' => 'ua-tag',
        'set_tag_color' => 'ua-tag',
        'warn' => 'ua-warn',
        'wipe_inbox' => 'ua-mute',
        'revoke_img' => 'ua-media',
        'allow_img' => 'ua-media',
        'revoke_audio' => 'ua-media',
        'allow_audio' => 'ua-media',
        'del_friends' => 'ua-delete',
        'shadowban' => 'ua-shadowban',
        'unshadowban' => 'ua-shadowban',
        'mark_vip' => 'ua-vip',
        'remove_vip' => 'ua-vip',
        'change_username' => 'ua-reset',
        'force_say' => 'ua-control',
        'purge_user' => 'ua-purge',
    ];

    if (!$isSuperAdmin && isset($actPermMap[$act]) && empty($myPerms[$actPermMap[$act]])) {
        echo json_encode(['ok'=>false, 'error'=>"Missing permission: " . $actPermMap[$act]]); break; 
    }

    switch ($act) {
        case 'delete':
            $pdo->prepare("DELETE FROM users WHERE id=?")->execute([$tid]);
            echo json_encode(['ok' => true]);
            break;
            
        case 'reset_pass':
            $newPw = trim($_POST['val'] ?? '');
            if (strlen($newPw) < 6) { echo json_encode(['ok' => false, 'error' => 'Min 6 chars']); break; }
            $pdo->prepare("UPDATE users SET password=? WHERE id=?")->execute([password_hash($newPw, PASSWORD_BCRYPT), $tid]);
            $pdo->prepare("INSERT INTO inbox(to_id,type,content) VALUES(?,'system',?)")->execute([$tid, "🔑 Your password was reset by an admin. New: $newPw"]);
            echo json_encode(['ok' => true]);
            break;
            
        case 'demote':
            $pdo->prepare("UPDATE users SET is_admin=0 WHERE id=?")->execute([$tid]);
            $pdo->prepare("INSERT INTO inbox(to_id,type,content) VALUES(?,'system',?)")->execute([$tid, "❌ You are no longer an Admin."]);
            echo json_encode(['ok' => true]);
            break;
            
        case 'promote':
            if (!colExists($pdo, 'users', 'is_admin')) { echo json_encode(['ok' => false, 'error' => 'Run setup.php to enable admin promotion']); break; }
            $pdo->prepare("UPDATE users SET is_admin=1 WHERE id=?")->execute([$tid]);
            $pdo->prepare("INSERT INTO inbox(to_id,type,content) VALUES(?,'system',?)")->execute([$tid, "🛡 You've been promoted to Admin by $uname!"]);
            echo json_encode(['ok' => true]);
            break;
            
        case 'control':
            $_SESSION['admin_original_id'] = $uid;
            $_SESSION['admin_original_name'] = $uname;
            $_SESSION['user_id'] = $tUser['id'];
            $_SESSION['username'] = $tUser['username'];
            echo json_encode(['ok' => true]);
            break;
            
        case 'kick':
            $pdo->prepare("UPDATE users SET force_logout=1 WHERE id=?")->execute([$tid]);
            echo json_encode(['ok' => true]);
            break;
            
        case 'mute':
            $pdo->prepare("UPDATE users SET is_muted=1 WHERE id=?")->execute([$tid]);
            echo json_encode(['ok' => true]);
            break;
            
        case 'unmute':
            $pdo->prepare("UPDATE users SET is_muted=0 WHERE id=?")->execute([$tid]);
            echo json_encode(['ok' => true]);
            break;
            
        case 'remove_avatar':
            $pdo->prepare("UPDATE users SET avatar=NULL WHERE id=?")->execute([$tid]);
            echo json_encode(['ok' => true]);
            break;
            
        case 'reset_color':
            $pdo->prepare("UPDATE users SET name_color='#3b82f6' WHERE id=?")->execute([$tid]);
            echo json_encode(['ok' => true]);
            break;

        case 'set_tag':
            $tag = trim($_POST['val'] ?? '');
            if($tag === '') $tag = null;
            $pdo->prepare("UPDATE users SET custom_tag=? WHERE id=?")->execute([$tag, $tid]);
            echo json_encode(['ok' => true]);
            break;

        case 'set_tag_color':
            $color = trim($_POST['val'] ?? '');
            if(!preg_match('/^#[0-9a-fA-F]{3,6}$/', $color)) {
                echo json_encode(['ok' => false, 'error' => 'Invalid hex color']); break;
            }
            $pdo->prepare("UPDATE users SET custom_tag_color=? WHERE id=?")->execute([$color, $tid]);
            echo json_encode(['ok' => true]);
            break;
            
        case 'warn':
            $msg = trim($_POST['val'] ?? 'Warning from Admin');
            $pdo->prepare("INSERT INTO inbox(to_id,type,content) VALUES(?,'system',?)")->execute([$tid, "⚠️ WARNING: $msg"]);
            echo json_encode(['ok' => true]);
            break;
            
        case 'wipe_inbox':
            $pdo->prepare("DELETE FROM inbox WHERE to_id=?")->execute([$tid]);
            echo json_encode(['ok' => true]);
            break;
            
        case 'revoke_img':
            $pdo->prepare("UPDATE users SET can_img=0 WHERE id=?")->execute([$tid]);
            echo json_encode(['ok' => true]);
            break;
            
        case 'allow_img':
            $pdo->prepare("UPDATE users SET can_img=1 WHERE id=?")->execute([$tid]);
            echo json_encode(['ok' => true]);
            break;
            
        case 'revoke_audio':
            $pdo->prepare("UPDATE users SET can_audio=0 WHERE id=?")->execute([$tid]);
            echo json_encode(['ok' => true]);
            break;
            
        case 'allow_audio':
            $pdo->prepare("UPDATE users SET can_audio=1 WHERE id=?")->execute([$tid]);
            echo json_encode(['ok' => true]);
            break;
            
        case 'del_friends':
            $pdo->prepare("DELETE FROM friends WHERE user_a=? OR user_b=?")->execute([$tid, $tid]);
            $pdo->prepare("DELETE FROM friend_requests WHERE from_id=? OR to_id=?")->execute([$tid, $tid]);
            echo json_encode(['ok' => true]);
            break;
            
        case 'shadowban':
            $pdo->prepare("UPDATE users SET shadowbanned=1 WHERE id=?")->execute([$tid]);
            echo json_encode(['ok' => true]);
            break;
            
        case 'unshadowban':
            $pdo->prepare("UPDATE users SET shadowbanned=0 WHERE id=?")->execute([$tid]);
            echo json_encode(['ok' => true]);
            break;
            
        case 'mark_vip':
            $pdo->prepare("UPDATE users SET is_vip=1 WHERE id=?")->execute([$tid]);
            echo json_encode(['ok' => true]);
            break;
            
        case 'remove_vip':
            $pdo->prepare("UPDATE users SET is_vip=0 WHERE id=?")->execute([$tid]);
            echo json_encode(['ok' => true]);
            break;
            
        case 'change_username':
            $newU = trim($_POST['val'] ?? '');
            if(strlen($newU) >= 2 && strlen($newU) <= 32 && preg_match('/^[a-zA-Z0-9_\-]+$/', $newU)) {
                $c = $pdo->prepare("SELECT id FROM users WHERE username=?"); $c->execute([$newU]);
                if (!$c->fetch()) {
                    $pdo->prepare("UPDATE users SET username=? WHERE id=?")->execute([$newU, $tid]);
                    echo json_encode(['ok' => true]);
                } else {
                    echo json_encode(['ok' => false, 'error' => 'Username taken']);
                }
            } else {
                echo json_encode(['ok' => false, 'error' => 'Invalid username format']);
            }
            break;
            
        case 'force_say':
            $msg = trim($_POST['val'] ?? '');
            if ($msg) {
                // Determine general channel ID properly
                $sGen = $pdo->query("SELECT id FROM channels WHERE name='general' OR type='text' ORDER BY position ASC LIMIT 1")->fetch();
                $genId = $sGen ? $sGen['id'] : 1;
                $pdo->prepare("INSERT INTO messages(channel_id,user_id,username,msg_type,content,is_system) VALUES(?,?,?,'text',?,0)")
                    ->execute([$genId, $tid, $tUser['username'], $msg]);
                echo json_encode(['ok' => true]);
            } else {
                echo json_encode(['ok' => false, 'error' => 'Message is empty']);
            }
            break;
            
        case 'purge_user':
            $pdo->prepare("DELETE FROM messages WHERE user_id=?")->execute([$tid]);
            echo json_encode(['ok' => true]);
            break;
            
        case 'del_feedback':
            if ($uname === 'gollclock') {
                $fid = (int)($_POST['val'] ?? 0);
                $pdo->prepare("DELETE FROM feedback WHERE id=?")->execute([$fid]);
                echo json_encode(['ok' => true]);
            } else { echo json_encode(['ok' => false]); }
            break;

        default:
            echo json_encode(['ok' => false, 'error' => 'Unknown action']);
            break;
    }
    break;
}

case 'admin_get_feedback': {
    if ($uname !== 'gollclock') { echo json_encode(['ok' => false]); break; }
    try {
        $r = $pdo->query("SELECT f.id, f.message, f.created_at, u.username, u.avatar, u.name_color FROM feedback f JOIN users u ON u.id=f.user_id ORDER BY f.id DESC")->fetchAll();
        echo json_encode(['ok' => true, 'feedbacks' => $r]);
    } catch (PDOException $e) {
        echo json_encode(['ok' => false, 'error' => 'Table missing? run setup']);
    }
    break;
}

case 'admin_get_maintenance': {
    requireAdmin($isAdmin);
    $on  = isMaintenance($pdo);
    $msg = ''; try { $msg = $pdo->query("SELECT maintenance_msg FROM site_config WHERE id=1")->fetchColumn() ?: ''; } catch (PDOException $e) {}
    echo json_encode(['ok' => true, 'on' => $on, 'message' => $msg]);
    break;
}

case 'admin_set_maintenance': {
    requireAdmin($isAdmin);
    $on  = ($_POST['on'] ?? '0') === '1' ? 1 : 0;
    $msg = trim($_POST['message'] ?? 'BetterChat is under maintenance. Check back soon!');
    $pdo->prepare("UPDATE site_config SET maintenance=?, maintenance_msg=? WHERE id=1")->execute([$on, $msg]);
    echo json_encode(['ok' => true, 'on' => $on === 1]);
    break;
}

case 'admin_add_channel': {
    requireAdmin($isAdmin);
    $name = trim($_POST['name'] ?? '');
    if (!$name) { echo json_encode(['ok' => false, 'error' => 'Name required']); break; }
    $pos = (int)$pdo->query("SELECT MAX(position) FROM channels")->fetchColumn() + 1;
    $pdo->prepare("INSERT INTO channels(name, position) VALUES(?, ?)")->execute([$name, $pos]);
    echo json_encode(['ok' => true]);
    break;
}

case 'admin_del_channel': {
    requireAdmin($isAdmin);
    $id = (int)($_POST['id'] ?? 0);
    if ($id === 1) { echo json_encode(['ok' => false, 'error' => 'Cannot delete general channel']); break; }
    $pdo->prepare("DELETE FROM messages WHERE channel_id=?")->execute([$id]);
    $pdo->prepare("DELETE FROM channels WHERE id=?")->execute([$id]);
    echo json_encode(['ok' => true]);
    break;
}

case 'admin_get_stats': {
    requireAdmin($isAdmin);
    $users = $pdo->query("SELECT COUNT(*) FROM users")->fetchColumn();
    $msgs = $pdo->query("SELECT COUNT(*) FROM messages")->fetchColumn();
    $chans = $pdo->query("SELECT COUNT(*) FROM channels")->fetchColumn();
    $bans = $pdo->query("SELECT COUNT(*) FROM bans")->fetchColumn();
    echo json_encode(['ok' => true, 'stats' => ['users' => $users, 'messages' => $msgs, 'channels' => $chans, 'bans' => $bans]]);
    break;
}

case 'admin_purge_user': {
    requireAdmin($isAdmin);
    $uid_target = (int)($_POST['user_id'] ?? 0);
    $s = $pdo->prepare("DELETE FROM messages WHERE user_id=?");
    $s->execute([$uid_target]);
    echo json_encode(['ok' => true, 'deleted' => $s->rowCount()]);
    break;
}

case 'admin_get_settings': {
    requireAdmin($isAdmin);
    $r = $pdo->query("SELECT allow_images, allow_audio, custom_wordle FROM site_config WHERE id=1")->fetch();
    echo json_encode(['ok' => true, 'settings' => [
        'allow_images' => $r ? (string)$r['allow_images'] : '1',
        'allow_audio' => $r ? (string)$r['allow_audio'] : '1',
        'custom_wordle' => $r ? $r['custom_wordle'] : ''
    ]]);
    break;
}

case 'admin_save_settings': {
    requireAdmin($isAdmin);
    $imgs = ($_POST['allow_images'] ?? '1') === '1' ? 1 : 0;
    $audio = ($_POST['allow_audio'] ?? '1') === '1' ? 1 : 0;
    $wordle = strtoupper(trim($_POST['custom_wordle'] ?? ''));
    if ($wordle && strlen($wordle) !== 5) {
        $wordle = '';
    }
    
    $pdo->prepare("UPDATE site_config SET allow_images=?, allow_audio=?, custom_wordle=? WHERE id=1")
        ->execute([$imgs, $audio, $wordle]);
    echo json_encode(['ok' => true]);
    break;
}

case 'get_wordle': {
    $stmt = $pdo->query("SELECT custom_wordle FROM site_config WHERE id=1");
    $setting = $stmt->fetchColumn();
    $word = '';
    
    if (!empty($setting) && strlen($setting) === 5) {
        $word = strtoupper($setting);
    } else {
        // Fetch from NYT API for the current date
        $dateStr = date('Y-m-d');
        $apiInfo = @file_get_contents("https://www.nytimes.com/svc/wordle/v2/{$dateStr}.json");
        if ($apiInfo) {
            $data = json_decode($apiInfo, true);
            if (!empty($data['solution'])) {
                $word = strtoupper($data['solution']);
            }
        }
        
        // Final fallback if NYT fails: deterministic word based on date
        if (empty($word)) {
            $fallbacks = ['APPLE', 'TRAIN', 'SMART', 'BRAIN', 'WATER', 'EARTH', 'LIGHT', 'SOUND', 'CRANE', 'PLANT', 'GHOST', 'HEART', 'SMILE'];
            $index = hexdec(substr(md5($dateStr), 0, 8)) % count($fallbacks);
            $word = $fallbacks[$index];
        }
    }
    
    // We send it to frontend, yes it's inspectable, but it saves having to manage all logic securely.
    echo json_encode(['ok' => true, 'word' => $word, 'date' => date('Y-m-d')]);
    break;
}

case 'admin_get_sessions': {
    requireAdmin($isAdmin);
    $rows = $pdo->query("SELECT id, username, last_seen FROM users ORDER BY last_seen DESC LIMIT 50")->fetchAll();
    echo json_encode(['ok' => true, 'sessions' => $rows]);
    break;
}

case 'check_maintenance': {
    $on  = isMaintenance($pdo);
    $msg = ''; try { $msg = $pdo->query("SELECT maintenance_msg FROM site_config WHERE id=1")->fetchColumn() ?: ''; } catch (PDOException $e) {}
    echo json_encode(['ok' => true, 'on' => $on, 'message' => $msg]);
    break;
}

case 'get_me':
    echo json_encode(['ok' => true, 'user' => [
        'id'       => $meRow['id'],
        'username' => $meRow['username'],
        'avatar'   => $meRow['avatar'],
        'name_color' => $meRow['name_color'],
        'is_admin' => $isAdmin,
    ]]);
    break;

case 'typing': {
    $cid = (int)($_POST['channel_id'] ?? 1);
    if (!checkChannelAccess($pdo, $cid, $uid, $isAdmin)) { echo json_encode(['ok' => false]); break; }
    try {
        $pdo->prepare("INSERT INTO typing_status(user_id, channel_id, last_typed) VALUES(?,?,NOW()) ON DUPLICATE KEY UPDATE channel_id=?, last_typed=NOW()")
            ->execute([$uid, $cid, $cid]);
        echo json_encode(['ok' => true]);
    } catch(PDOException $e) { echo json_encode(['ok' => false]); }
    break;
}

case 'get_typing': {
    $cid = (int)($_GET['channel_id'] ?? 1);
    try {
        $s = $pdo->prepare("SELECT u.username FROM typing_status t JOIN users u ON u.id=t.user_id WHERE t.channel_id=? AND t.user_id!=? AND t.last_typed >= DATE_SUB(NOW(), INTERVAL 3 SECOND)");
        $s->execute([$cid, $uid]);
        $typers = $s->fetchAll(PDO::FETCH_COLUMN);
        echo json_encode(['ok' => true, 'typing' => $typers]);
    } catch(PDOException $e) { echo json_encode(['ok' => false, 'typing' => []]); }
    break;
}

case 'admin_get_roles': {
    if ($uname !== 'gollclock') { echo json_encode(['ok' => false, 'error' => 'Superadmin only']); break; }
    try {
        $roles = $pdo->query("SELECT * FROM roles ORDER BY id ASC")->fetchAll();
        echo json_encode(['ok' => true, 'roles' => $roles]);
    } catch(PDOException $e) { echo json_encode(['ok' => false]); }
    break;
}

case 'admin_create_role': {
    if ($uname !== 'gollclock') { echo json_encode(['ok' => false]); break; }
    $name = trim($_POST['name'] ?? 'New Role');
    $color = trim($_POST['color'] ?? '#ffffff');
    $perms = trim($_POST['permissions'] ?? '{}');
    try {
        $pdo->prepare("INSERT INTO roles(name, color, permissions) VALUES(?,?,?)")->execute([$name, $color, $perms]);
        echo json_encode(['ok' => true]);
    } catch(PDOException $e) { echo json_encode(['ok' => false, 'error' => $e->getMessage()]); }
    break;
}

case 'admin_assign_role': {
    if ($uname !== 'gollclock') { echo json_encode(['ok' => false]); break; }
    $tid = (int)($_POST['user_id'] ?? 0);
    $rid = (int)($_POST['role_id'] ?? 0);
    try {
        if ($rid === 0) {
            $pdo->prepare("UPDATE users SET role_id=NULL WHERE id=?")->execute([$tid]);
        } else {
            $pdo->prepare("UPDATE users SET role_id=? WHERE id=?")->execute([$rid, $tid]);
        }
        echo json_encode(['ok' => true]);
    } catch(PDOException $e) { echo json_encode(['ok' => false]); }
    break;
}

case 'admin_set_overlay': {
    if ($uname !== 'gollclock') { echo json_encode(['ok' => false]); break; }
    $tid = (int)($_POST['user_id'] ?? 0);
    $url = trim($_POST['overlay'] ?? '');
    $scale = (float)($_POST['scale'] ?? 1.0);
    $offsetX = (int)($_POST['offset_x'] ?? 0);
    $offsetY = (int)($_POST['offset_y'] ?? 0);
    $data = $url ? json_encode(['url'=>$url, 'scale'=>$scale, 'x'=>$offsetX, 'y'=>$offsetY]) : null;
    try {
        $pdo->prepare("UPDATE users SET avatar_overlay=? WHERE id=?")->execute([$data, $tid]);
        echo json_encode(['ok' => true]);
    } catch(PDOException $e) { echo json_encode(['ok' => false]); }
    break;
}

case 'admin_set_ban_template': {
    requireAdmin($isAdmin);
    $type = trim($_POST['ban_type'] ?? '');
    $html = trim($_POST['html'] ?? '');
    if (!$type) { echo json_encode(['ok' => false]); break; }
    try {
        if ($html) {
            $pdo->prepare("REPLACE INTO ban_templates(ban_type, html_content) VALUES(?,?)")->execute([$type, $html]);
        } else {
            $pdo->prepare("DELETE FROM ban_templates WHERE ban_type=?")->execute([$type]);
        }
        echo json_encode(['ok' => true]);
    } catch(PDOException $e) { echo json_encode(['ok' => false]); }
    break;
}

case 'admin_start_challenge': {
    if ($uname !== 'gollclock') { echo json_encode(['ok' => false]); break; }
    $word = trim($_POST['word'] ?? '');
    try {
        $pdo->prepare("UPDATE site_config SET active_challenge=? WHERE id=1")->execute([$word ?: null]);
        if ($word) {
            $sGen = $pdo->query("SELECT id FROM channels WHERE name='general' OR type='text' ORDER BY position ASC LIMIT 1")->fetch();
            $genId = $sGen ? $sGen['id'] : 1;
            $pdo->prepare("INSERT INTO messages(channel_id,user_id,username,msg_type,content,is_system) VALUES(?,?,'SYSTEM','system',?,1)")
                ->execute([$genId, $uid, "🎁 A Nitro challenge has started! Type the secret word to claim it!"]);
        }
        echo json_encode(['ok' => true]);
    } catch(PDOException $e) { echo json_encode(['ok' => false]); }
    break;
}

case 'claim_nitro': {
    $guess = trim($_POST['guess'] ?? '');
    try {
        $ch = $pdo->query("SELECT active_challenge FROM site_config WHERE id=1")->fetchColumn();
        if ($ch && strtolower($ch) === strtolower($guess)) {
            $pdo->prepare("UPDATE users SET is_nitro=1 WHERE id=?")->execute([$uid]);
            $pdo->prepare("UPDATE site_config SET active_challenge=NULL WHERE id=1")->execute(); // consume challenge
            
            $sGen = $pdo->query("SELECT id FROM channels WHERE name='general' OR type='text' ORDER BY position ASC LIMIT 1")->fetch();
            $genId = $sGen ? $sGen['id'] : 1;
            $pdo->prepare("INSERT INTO messages(channel_id,user_id,username,msg_type,content,is_system) VALUES(?,?,'SYSTEM','system',?,1)")
                ->execute([$genId, $uid, "🎉 {$uname} won the Nitro challenge!"]);
                
            echo json_encode(['ok' => true, 'won' => true]);
        } else {
            echo json_encode(['ok' => true, 'won' => false]);
        }
    } catch(PDOException $e) { echo json_encode(['ok' => false]); }
    break;
}

default:
    echo json_encode(['ok' => false, 'error' => 'Unknown action: ' . htmlspecialchars($action)]);

}} catch (PDOException $e) {
    echo json_encode(['ok' => false, 'error' => 'DB error: ' . $e->getMessage()]);
} catch (Throwable $e) {
    echo json_encode(['ok' => false, 'error' => 'Server error: ' . $e->getMessage()]);
}
