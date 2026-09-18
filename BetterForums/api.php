<?php
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With, X-Auth-Token');
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}
header('Content-Type: application/json; charset=utf-8');

require_once __DIR__ . '/db.php';

// Parse JSON request body if provided
$raw_input = file_get_contents('php://input');
$json_data = json_decode($raw_input, true) ?: [];
$req = array_merge($_GET, $_POST, $json_data);

function get_real_client_ip_api() {
    $headers = ['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP', 'REMOTE_ADDR'];
    foreach ($headers as $h) {
        if (!empty($_SERVER[$h])) {
            $ips = explode(',', $_SERVER[$h]);
            $candidate = trim($ips[0]);
            if (filter_var($candidate, FILTER_VALIDATE_IP)) {
                if (!in_array($candidate, ['127.0.0.1', '::1', '0.0.0.0', 'localhost'])) {
                    return $candidate;
                }
            }
        }
    }
    return $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
}

$client_ip = get_real_client_ip_api();
$client_ip_safe = mysqli_real_escape_string($conn, $client_ip);

// IP Ban Check
$is_loopback = in_array($client_ip, ['127.0.0.1', '::1', '0.0.0.0', 'localhost']);
if (!$is_loopback) {
    $ip_chk = mysqli_query($conn, "SELECT id, reason FROM ip_bans WHERE ip_address = '$client_ip_safe'");
    if ($ip_chk && mysqli_num_rows($ip_chk) > 0) {
        $ip_row = mysqli_fetch_assoc($ip_chk);
        echo json_encode([
            'ok' => false,
            'banned' => true,
            'ip_banned' => true,
            'error' => 'Your IP address (' . $client_ip . ') is banned: ' . ($ip_row['reason'] ?: 'Access Denied')
        ]);
        exit;
    }
}

// Extract auth token
$auth_token = '';
if (!empty($_SERVER['HTTP_AUTHORIZATION'])) {
    $auth_header = trim($_SERVER['HTTP_AUTHORIZATION']);
    if (stripos($auth_header, 'Bearer ') === 0) {
        $auth_token = substr($auth_header, 7);
    } else {
        $auth_token = $auth_header;
    }
} elseif (!empty($req['token'])) {
    $auth_token = trim($req['token']);
} elseif (!empty($_COOKIE['BF_AUTH_SAFE'])) {
    $auth_token = trim($_COOKIE['BF_AUTH_SAFE']);
}

$curr_user = null;
$is_owner = false;
$is_admin = false;
$is_mod = false;
$is_staff = false;

if (!empty($auth_token)) {
    $decoded_auth = base64_decode($auth_token);
    $auth_parts = explode(':', $decoded_auth, 2);
    if (count($auth_parts) === 2) {
        $u_name = mysqli_real_escape_string($conn, $auth_parts[0]);
        $u_hash = $auth_parts[1];
        $u_res = mysqli_query($conn, "SELECT * FROM users WHERE username = '$u_name'");
        if ($u_res && mysqli_num_rows($u_res) > 0) {
            $user_row = mysqli_fetch_assoc($u_res);
            if (md5($user_row['password_hash']) === $u_hash) {
                // Check ban
                $is_super = (strtolower($user_row['username']) === 'gollclock');
                if (!$is_super && $user_row['role'] !== 'OWNER') {
                    $b_chk = mysqli_query($conn, "SELECT id, reason FROM moderation_actions WHERE target_username = '{$user_row['username']}' AND action_type = 'BAN' AND status = 'APPROVED'");
                    if ($b_chk && mysqli_num_rows($b_chk) > 0) {
                        $b_row = mysqli_fetch_assoc($b_chk);
                        echo json_encode(['ok' => false, 'banned' => true, 'error' => 'Your account is banned: ' . ($b_row['reason'] ?: 'Suspended')]);
                        exit;
                    }
                }
                $curr_user = $user_row;
                $is_owner = ($curr_user['role'] === 'OWNER' || $is_super);
                $is_admin = ($curr_user['role'] === 'ADMIN' || !empty($curr_user['is_admin']) || $is_owner);
                $is_mod = ($curr_user['role'] === 'MOD' || !empty($curr_user['is_mod']) || $is_admin);
                $is_staff = $is_mod;
            }
        }
    }
}

$action = $req['action'] ?? 'get_feed';

// ── Action: Ping / System Info ────────────────────────────────────────────────
if ($action === 'ping' || $action === 'get_system_info') {
    $hc_res = mysqli_query($conn, "SELECT hit_counter, announcement_banner, maintenance, maintenance_msg FROM system_config WHERE id = 1");
    $cfg = mysqli_fetch_assoc($hc_res) ?: ['hit_counter' => 1, 'announcement_banner' => '', 'maintenance' => 0, 'maintenance_msg' => ''];
    
    // Pick MOTD
    $motd = 'Welcome to BetterForums - The Front Page of the Web!';
    $motd_res = mysqli_query($conn, "SELECT message_text FROM motd_pool ORDER BY RAND() LIMIT 1");
    if ($motd_res && mysqli_num_rows($motd_res) > 0) {
        $motd_row = mysqli_fetch_assoc($motd_res);
        if (!empty($motd_row['message_text'])) {
            $motd = $motd_row['message_text'];
        }
    }
    
    echo json_encode([
        'ok' => true,
        'database' => defined('BF_DB_NAME') ? BF_DB_NAME : 'secretsqlhoster_betterformus',
        'hit_counter' => (int)$cfg['hit_counter'],
        'announcement_banner' => $cfg['announcement_banner'] ?: '',
        'maintenance' => (int)$cfg['maintenance'],
        'maintenance_msg' => $cfg['maintenance_msg'] ?: '',
        'motd' => $motd,
        'server_time' => date('c')
    ]);
    exit;
}

// ── Action: Auth Check / Get Me ──────────────────────────────────────────────
if ($action === 'auth_check' || $action === 'get_me') {
    if (!$curr_user) {
        echo json_encode(['ok' => false, 'error' => 'Not authenticated', 'user' => null]);
        exit;
    }
    
    // Calculate karma
    $uid = (int)$curr_user['id'];
    $pk_q = mysqli_query($conn, "SELECT COALESCE(SUM(uv.vote_type), 0) as post_karma FROM user_votes uv JOIN posts p ON uv.target_id = p.id WHERE uv.target_type = 'post' AND p.user_id = $uid AND p.is_deleted = 0");
    $pk = $pk_q ? (int)mysqli_fetch_assoc($pk_q)['post_karma'] : 0;
    
    $ck_q = mysqli_query($conn, "SELECT COALESCE(SUM(uv.vote_type), 0) as comment_karma FROM user_votes uv JOIN comments c ON uv.target_id = c.id WHERE uv.target_type = 'comment' AND c.user_id = $uid AND c.is_deleted = 0");
    $ck = $ck_q ? (int)mysqli_fetch_assoc($ck_q)['comment_karma'] : 0;
    
    echo json_encode([
        'ok' => true,
        'user' => [
            'id' => (int)$curr_user['id'],
            'username' => $curr_user['username'],
            'display_name' => $curr_user['display_name'] ?: $curr_user['username'],
            'role' => $curr_user['role'],
            'custom_badge' => $curr_user['custom_badge'] ?: '',
            'status_flair' => $curr_user['status_flair'] ?: '',
            'avatar_data' => $curr_user['avatar_data'] ?: '',
            'bio' => $curr_user['bio'] ?: '',
            'name_color' => $curr_user['name_color'] ?: '#94a3b8',
            'theme' => $curr_user['theme'] ?: 'dark',
            'is_owner' => $is_owner,
            'is_admin' => $is_admin,
            'is_mod' => $is_mod,
            'post_karma' => $pk,
            'comment_karma' => $ck,
            'total_karma' => $pk + $ck
        ]
    ]);
    exit;
}

// ── Action: Register ────────────────────────────────────────────────────────
if ($action === 'register') {
    $username = trim($req['username'] ?? '');
    $password = trim($req['password'] ?? '');
    
    if (empty($username) || empty($password)) {
        echo json_encode(['ok' => false, 'error' => 'Username and password are required.']);
        exit;
    }
    if (strlen($username) < 3 || strlen($username) > 30) {
        echo json_encode(['ok' => false, 'error' => 'Username must be between 3 and 30 characters.']);
        exit;
    }
    if (strlen($password) < 4) {
        echo json_encode(['ok' => false, 'error' => 'Password must be at least 4 characters.']);
        exit;
    }
    
    $u_safe = mysqli_real_escape_string($conn, $username);
    $check = mysqli_query($conn, "SELECT id FROM users WHERE username = '$u_safe'");
    if (mysqli_num_rows($check) > 0) {
        echo json_encode(['ok' => false, 'error' => 'That username is already taken. Please choose another.']);
        exit;
    }
    
    $hash = password_hash($password, PASSWORD_BCRYPT);
    $is_super = (strtolower($username) === 'gollclock');
    $role = $is_super ? 'OWNER' : 'USER';
    $badge = $is_super ? 'Owner' : '';
    $is_adm = $is_super ? 1 : 0;
    
    $ins = mysqli_query($conn, "INSERT INTO users (username, password_hash, role, ip_address, is_shadowbanned, hide_from_search, display_name, bio, avatar_type, avatar_data, status_flair, custom_badge, is_admin, is_mod, theme) VALUES ('$u_safe', '$hash', '$role', '$client_ip_safe', 0, 0, '$u_safe', '', 'url', '', '', '$badge', $is_adm, $is_adm, 'dark')");
    
    if ($ins) {
        $uid = mysqli_insert_id($conn);
        $token = base64_encode($username . ':' . md5($hash));
        echo json_encode([
            'ok' => true,
            'token' => $token,
            'user' => [
                'id' => $uid,
                'username' => $username,
                'display_name' => $username,
                'role' => $role,
                'custom_badge' => $badge,
                'status_flair' => '',
                'avatar_data' => '',
                'bio' => '',
                'theme' => 'dark',
                'is_owner' => $is_super,
                'is_admin' => (bool)$is_adm,
                'is_mod' => (bool)$is_adm,
                'total_karma' => 0
            ]
        ]);
    } else {
        echo json_encode(['ok' => false, 'error' => 'Registration failed: ' . mysqli_error($conn)]);
    }
    exit;
}

// ── Action: Login ───────────────────────────────────────────────────────────
if ($action === 'login') {
    $username = trim($req['username'] ?? '');
    $password = trim($req['password'] ?? '');
    
    if (empty($username) || empty($password)) {
        echo json_encode(['ok' => false, 'error' => 'Username and password are required.']);
        exit;
    }
    
    $u_safe = mysqli_real_escape_string($conn, $username);
    $res = mysqli_query($conn, "SELECT * FROM users WHERE username = '$u_safe'");
    if ($res && mysqli_num_rows($res) > 0) {
        $u = mysqli_fetch_assoc($res);
        if (password_verify($password, $u['password_hash'])) {
            $is_super = (strtolower($u['username']) === 'gollclock');
            if (!$is_super && $u['role'] !== 'OWNER') {
                $ban_check = mysqli_query($conn, "SELECT id, reason FROM moderation_actions WHERE target_username = '$u_safe' AND action_type = 'BAN' AND status = 'APPROVED'");
                if ($ban_check && mysqli_num_rows($ban_check) > 0) {
                    $b_row = mysqli_fetch_assoc($ban_check);
                    echo json_encode(['ok' => false, 'banned' => true, 'error' => 'Your account has been banned: ' . ($b_row['reason'] ?: 'Suspended')]);
                    exit;
                }
            }
            
            mysqli_query($conn, "UPDATE users SET ip_address = '$client_ip_safe' WHERE id = " . intval($u['id']));
            $token = base64_encode($u['username'] . ':' . md5($u['password_hash']));
            
            $uid = (int)$u['id'];
            $pk_q = mysqli_query($conn, "SELECT COALESCE(SUM(uv.vote_type), 0) as post_karma FROM user_votes uv JOIN posts p ON uv.target_id = p.id WHERE uv.target_type = 'post' AND p.user_id = $uid AND p.is_deleted = 0");
            $pk = $pk_q ? (int)mysqli_fetch_assoc($pk_q)['post_karma'] : 0;
            $ck_q = mysqli_query($conn, "SELECT COALESCE(SUM(uv.vote_type), 0) as comment_karma FROM user_votes uv JOIN comments c ON uv.target_id = c.id WHERE uv.target_type = 'comment' AND c.user_id = $uid AND c.is_deleted = 0");
            $ck = $ck_q ? (int)mysqli_fetch_assoc($ck_q)['comment_karma'] : 0;
            
            $is_owner_val = ($u['role'] === 'OWNER' || $is_super);
            $is_admin_val = ($u['role'] === 'ADMIN' || !empty($u['is_admin']) || $is_owner_val);
            $is_mod_val = ($u['role'] === 'MOD' || !empty($u['is_mod']) || $is_admin_val);
            
            echo json_encode([
                'ok' => true,
                'token' => $token,
                'user' => [
                    'id' => (int)$u['id'],
                    'username' => $u['username'],
                    'display_name' => $u['display_name'] ?: $u['username'],
                    'role' => $u['role'],
                    'custom_badge' => $u['custom_badge'] ?: '',
                    'status_flair' => $u['status_flair'] ?: '',
                    'avatar_data' => $u['avatar_data'] ?: '',
                    'bio' => $u['bio'] ?: '',
                    'name_color' => $u['name_color'] ?: '#94a3b8',
                    'theme' => $u['theme'] ?: 'dark',
                    'is_owner' => $is_owner_val,
                    'is_admin' => $is_admin_val,
                    'is_mod' => $is_mod_val,
                    'post_karma' => $pk,
                    'comment_karma' => $ck,
                    'total_karma' => $pk + $ck
                ]
            ]);
            exit;
        }
    }
    
    echo json_encode(['ok' => false, 'error' => 'Incorrect username or password.']);
    exit;
}

// ── Action: Get Subbetters ──────────────────────────────────────────────────
if ($action === 'get_subbetters') {
    $res = mysqli_query($conn, "SELECT s.*, COUNT(p.id) as post_count FROM subbetters s LEFT JOIN posts p ON s.id=p.subbetter_id AND p.is_deleted=0 GROUP BY s.id ORDER BY s.name ASC");
    $subs = [];
    while ($r = mysqli_fetch_assoc($res)) {
        $subs[] = [
            'id' => (int)$r['id'],
            'name' => $r['name'],
            'description' => $r['description'] ?: '',
            'created_by' => $r['created_by'],
            'created_at' => $r['created_at'],
            'is_locked' => (bool)$r['is_locked'],
            'post_count' => (int)$r['post_count']
        ];
    }
    echo json_encode(['ok' => true, 'subbetters' => $subs]);
    exit;
}

// ── Action: Get Feed / Posts List ───────────────────────────────────────────
if ($action === 'get_feed') {
    $sub_filter = trim($req['b'] ?? '');
    $sort = trim($req['sort'] ?? 'hot'); // hot, new, top
    $search = trim($req['q'] ?? '');
    $page = max(1, (int)($req['page'] ?? 1));
    $limit = 30;
    $offset = ($page - 1) * $limit;
    
    $where_clauses = ["p.is_deleted = 0"];
    
    if (!empty($sub_filter) && strtolower($sub_filter) !== 'all') {
        $sf_safe = mysqli_real_escape_string($conn, $sub_filter);
        $where_clauses[] = "s.name = '$sf_safe'";
    }
    
    if (!empty($search)) {
        $q_safe = mysqli_real_escape_string($conn, $search);
        $where_clauses[] = "(p.title LIKE '%$q_safe%' OR p.content LIKE '%$q_safe%' OR u.username LIKE '%$q_safe%')";
    }
    
    $where_sql = implode(' AND ', $where_clauses);
    
    // Order by
    if ($sort === 'new') {
        $order_sql = "p.is_pinned DESC, p.created_at DESC";
    } elseif ($sort === 'top') {
        $order_sql = "p.is_pinned DESC, score DESC, p.created_at DESC";
    } else { // hot
        $order_sql = "p.is_pinned DESC, (score * 10000 + UNIX_TIMESTAMP(p.created_at)) DESC";
    }
    
    $uid = $curr_user ? (int)$curr_user['id'] : 0;
    
    $sql = "SELECT p.*, s.name as sub_name, u.username, u.display_name, u.role as user_role, u.custom_badge, u.status_flair, u.avatar_data, u.name_color,
            COALESCE((SELECT SUM(vote_type) FROM user_votes WHERE target_type='post' AND target_id=p.id), 0) as score,
            (SELECT vote_type FROM user_votes WHERE target_type='post' AND target_id=p.id AND user_id=$uid) as user_vote,
            (SELECT COUNT(id) FROM comments WHERE post_id=p.id AND is_deleted=0) as comment_count,
            (SELECT COUNT(id) FROM saved_posts WHERE post_id=p.id AND user_id=$uid) as is_saved
            FROM posts p
            JOIN subbetters s ON p.subbetter_id = s.id
            JOIN users u ON p.user_id = u.id
            WHERE $where_sql
            ORDER BY $order_sql
            LIMIT $limit OFFSET $offset";
            
    $res = mysqli_query($conn, $sql);
    $posts = [];
    if ($res) {
        while ($p = mysqli_fetch_assoc($res)) {
            $posts[] = [
                'id' => (int)$p['id'],
                'subbetter_id' => (int)$p['subbetter_id'],
                'sub_name' => $p['sub_name'],
                'title' => $p['title'],
                'content' => $p['content'],
                'image_url' => $p['image_url'] ?: '',
                'link_url' => $p['link_url'] ?: '',
                'flair' => $p['flair'] ?: '',
                'created_at' => $p['created_at'],
                'is_pinned' => (bool)$p['is_pinned'],
                'is_locked' => (bool)$p['is_locked'],
                'username' => $p['username'],
                'display_name' => $p['display_name'] ?: $p['username'],
                'user_role' => $p['user_role'],
                'custom_badge' => $p['custom_badge'] ?: '',
                'status_flair' => $p['status_flair'] ?: '',
                'avatar_data' => $p['avatar_data'] ?: '',
                'name_color' => $p['name_color'] ?: '#94a3b8',
                'score' => (int)$p['score'],
                'user_vote' => $p['user_vote'] !== null ? (int)$p['user_vote'] : 0,
                'comment_count' => (int)$p['comment_count'],
                'is_saved' => (bool)$p['is_saved']
            ];
        }
    }
    
    // Subbetters list
    $subs_q = mysqli_query($conn, "SELECT id, name, description FROM subbetters ORDER BY name ASC");
    $subbetters = [];
    while ($sr = mysqli_fetch_assoc($subs_q)) {
        $subbetters[] = ['id' => (int)$sr['id'], 'name' => $sr['name'], 'description' => $sr['description']];
    }
    
    // Hit counter & announcement
    $hc_res = mysqli_query($conn, "SELECT hit_counter, announcement_banner FROM system_config WHERE id = 1");
    $cfg = mysqli_fetch_assoc($hc_res);
    
    echo json_encode([
        'ok' => true,
        'posts' => $posts,
        'subbetters' => $subbetters,
        'hit_counter' => $cfg ? (int)$cfg['hit_counter'] : 1,
        'announcement_banner' => $cfg ? ($cfg['announcement_banner'] ?: '') : '',
        'page' => $page
    ]);
    exit;
}

// ── Action: Get Single Post & Comments Tree ─────────────────────────────────
if ($action === 'get_post') {
    $pid = (int)($req['id'] ?? 0);
    if (!$pid) {
        echo json_encode(['ok' => false, 'error' => 'Invalid post ID']);
        exit;
    }
    
    $uid = $curr_user ? (int)$curr_user['id'] : 0;
    
    $sql = "SELECT p.*, s.name as sub_name, s.description as sub_desc, u.username, u.display_name, u.role as user_role, u.custom_badge, u.status_flair, u.avatar_data, u.name_color,
            COALESCE((SELECT SUM(vote_type) FROM user_votes WHERE target_type='post' AND target_id=p.id), 0) as score,
            (SELECT vote_type FROM user_votes WHERE target_type='post' AND target_id=p.id AND user_id=$uid) as user_vote,
            (SELECT COUNT(id) FROM comments WHERE post_id=p.id AND is_deleted=0) as comment_count,
            (SELECT COUNT(id) FROM saved_posts WHERE post_id=p.id AND user_id=$uid) as is_saved
            FROM posts p
            JOIN subbetters s ON p.subbetter_id = s.id
            JOIN users u ON p.user_id = u.id
            WHERE p.id = $pid AND p.is_deleted = 0";
            
    $res = mysqli_query($conn, $sql);
    if (!$res || mysqli_num_rows($res) === 0) {
        echo json_encode(['ok' => false, 'error' => 'Post not found or deleted']);
        exit;
    }
    $p = mysqli_fetch_assoc($res);
    $post_data = [
        'id' => (int)$p['id'],
        'subbetter_id' => (int)$p['subbetter_id'],
        'sub_name' => $p['sub_name'],
        'sub_desc' => $p['sub_desc'] ?: '',
        'title' => $p['title'],
        'content' => $p['content'],
        'image_url' => $p['image_url'] ?: '',
        'link_url' => $p['link_url'] ?: '',
        'flair' => $p['flair'] ?: '',
        'created_at' => $p['created_at'],
        'is_pinned' => (bool)$p['is_pinned'],
        'is_locked' => (bool)$p['is_locked'],
        'username' => $p['username'],
        'display_name' => $p['display_name'] ?: $p['username'],
        'user_role' => $p['user_role'],
        'custom_badge' => $p['custom_badge'] ?: '',
        'status_flair' => $p['status_flair'] ?: '',
        'avatar_data' => $p['avatar_data'] ?: '',
        'name_color' => $p['name_color'] ?: '#94a3b8',
        'score' => (int)$p['score'],
        'user_vote' => $p['user_vote'] !== null ? (int)$p['user_vote'] : 0,
        'comment_count' => (int)$p['comment_count'],
        'is_saved' => (bool)$p['is_saved']
    ];
    
    // Fetch comments
    $c_sql = "SELECT c.*, u.username, u.display_name, u.role as user_role, u.custom_badge, u.status_flair, u.avatar_data, u.name_color,
              COALESCE((SELECT SUM(vote_type) FROM user_votes WHERE target_type='comment' AND target_id=c.id), 0) as score,
              (SELECT vote_type FROM user_votes WHERE target_type='comment' AND target_id=c.id AND user_id=$uid) as user_vote
              FROM comments c
              JOIN users u ON c.user_id = u.id
              WHERE c.post_id = $pid AND c.is_deleted = 0
              ORDER BY c.created_at ASC";
    $c_res = mysqli_query($conn, $c_sql);
    $all_comments = [];
    while ($c = mysqli_fetch_assoc($c_res)) {
        $all_comments[] = [
            'id' => (int)$c['id'],
            'post_id' => (int)$c['post_id'],
            'parent_id' => (int)$c['parent_id'],
            'user_id' => (int)$c['user_id'],
            'content' => $c['content'],
            'created_at' => $c['created_at'],
            'username' => $c['username'],
            'display_name' => $c['display_name'] ?: $c['username'],
            'user_role' => $c['user_role'],
            'custom_badge' => $c['custom_badge'] ?: '',
            'status_flair' => $c['status_flair'] ?: '',
            'avatar_data' => $c['avatar_data'] ?: '',
            'name_color' => $c['name_color'] ?: '#94a3b8',
            'score' => (int)$c['score'],
            'user_vote' => $c['user_vote'] !== null ? (int)$c['user_vote'] : 0
        ];
    }
    
    echo json_encode([
        'ok' => true,
        'post' => $post_data,
        'comments' => $all_comments
    ]);
    exit;
}

// ── Require Auth for modifying actions ──────────────────────────────────────
if (!$curr_user) {
    echo json_encode(['ok' => false, 'error' => 'You must be logged in to perform this action.']);
    exit;
}

$uid = (int)$curr_user['id'];

// ── Action: Vote (Post or Comment) ──────────────────────────────────────────
if ($action === 'vote') {
    $type = $req['type'] === 'comment' ? 'comment' : 'post';
    $target_id = (int)($req['id'] ?? 0);
    $vote_val = (int)($req['v'] ?? 0);
    if ($vote_val > 1) $vote_val = 1;
    if ($vote_val < -1) $vote_val = -1;
    
    if (!$target_id) {
        echo json_encode(['ok' => false, 'error' => 'Invalid target ID']);
        exit;
    }
    
    // Check existing vote
    $chk = mysqli_query($conn, "SELECT id, vote_type FROM user_votes WHERE user_id=$uid AND target_type='$type' AND target_id=$target_id");
    if ($chk && mysqli_num_rows($chk) > 0) {
        $v_row = mysqli_fetch_assoc($chk);
        if ($v_row['vote_type'] == $vote_val) {
            // Unvote
            mysqli_query($conn, "DELETE FROM user_votes WHERE id=" . intval($v_row['id']));
            $new_user_vote = 0;
        } else {
            // Update vote
            mysqli_query($conn, "UPDATE user_votes SET vote_type=$vote_val WHERE id=" . intval($v_row['id']));
            $new_user_vote = $vote_val;
        }
    } else {
        if ($vote_val != 0) {
            mysqli_query($conn, "INSERT INTO user_votes (user_id, target_type, target_id, vote_type) VALUES ($uid, '$type', $target_id, $vote_val)");
            $new_user_vote = $vote_val;
        } else {
            $new_user_vote = 0;
        }
    }
    
    // Calculate new total score
    $sc_q = mysqli_query($conn, "SELECT COALESCE(SUM(vote_type), 0) as new_score FROM user_votes WHERE target_type='$type' AND target_id=$target_id");
    $new_score = $sc_q ? (int)mysqli_fetch_assoc($sc_q)['new_score'] : 0;
    
    echo json_encode([
        'ok' => true,
        'type' => $type,
        'id' => $target_id,
        'score' => $new_score,
        'user_vote' => $new_user_vote
    ]);
    exit;
}

// ── Action: Submit Post ─────────────────────────────────────────────────────
if ($action === 'submit_post') {
    $sub_name = trim($req['sub_name'] ?? '');
    $title = trim($req['title'] ?? '');
    $content = trim($req['content'] ?? '');
    $image_url = trim($req['image_url'] ?? '');
    $link_url = trim($req['link_url'] ?? '');
    $flair = trim($req['flair'] ?? '');
    
    if (empty($title)) {
        echo json_encode(['ok' => false, 'error' => 'Title is required.']);
        exit;
    }
    if (empty($sub_name)) {
        $sub_name = 'general';
    }
    
    $sub_name_clean = preg_replace('/^r\//i', '', $sub_name);
    $sub_safe = mysqli_real_escape_string($conn, $sub_name_clean);
    
    // Get subbetter ID or create if not exists
    $sub_chk = mysqli_query($conn, "SELECT id, is_locked FROM subbetters WHERE name='$sub_safe'");
    if ($sub_chk && mysqli_num_rows($sub_chk) > 0) {
        $sub_row = mysqli_fetch_assoc($sub_chk);
        if ($sub_row['is_locked'] && !$is_staff) {
            echo json_encode(['ok' => false, 'error' => 'This community is locked by moderators.']);
            exit;
        }
        $sub_id = (int)$sub_row['id'];
    } else {
        mysqli_query($conn, "INSERT INTO subbetters (name, description, created_by) VALUES ('$sub_safe', 'Community for $sub_safe discussions', '{$curr_user['username']}')");
        $sub_id = mysqli_insert_id($conn);
    }
    
    $title_safe = mysqli_real_escape_string($conn, $title);
    $content_safe = mysqli_real_escape_string($conn, $content);
    $img_safe = mysqli_real_escape_string($conn, $image_url);
    $link_safe = mysqli_real_escape_string($conn, $link_url);
    $flair_safe = mysqli_real_escape_string($conn, $flair);
    
    $ins = mysqli_query($conn, "INSERT INTO posts (subbetter_id, user_id, title, content, image_url, link_url, flair, ip_address, is_deleted, is_pinned, is_locked)
                         VALUES ($sub_id, $uid, '$title_safe', '$content_safe', '$img_safe', '$link_safe', '$flair_safe', '$client_ip_safe', 0, 0, 0)");
                         
    if ($ins) {
        $new_post_id = mysqli_insert_id($conn);
        // Automatically upvote own post
        mysqli_query($conn, "INSERT INTO user_votes (user_id, target_type, target_id, vote_type) VALUES ($uid, 'post', $new_post_id, 1)");
        echo json_encode(['ok' => true, 'post_id' => $new_post_id, 'sub_name' => $sub_name_clean]);
    } else {
        echo json_encode(['ok' => false, 'error' => 'Failed to create post: ' . mysqli_error($conn)]);
    }
    exit;
}

// ── Action: Submit Comment ──────────────────────────────────────────────────
if ($action === 'submit_comment') {
    $post_id = (int)($req['post_id'] ?? 0);
    $parent_id = (int)($req['parent_id'] ?? 0);
    $content = trim($req['content'] ?? '');
    
    if (!$post_id || empty($content)) {
        echo json_encode(['ok' => false, 'error' => 'Comment content is required.']);
        exit;
    }
    
    // Check if post is locked
    $p_chk = mysqli_query($conn, "SELECT is_locked, is_deleted FROM posts WHERE id=$post_id");
    if (!$p_chk || mysqli_num_rows($p_chk) === 0) {
        echo json_encode(['ok' => false, 'error' => 'Post not found.']);
        exit;
    }
    $p_row = mysqli_fetch_assoc($p_chk);
    if ($p_row['is_deleted']) {
        echo json_encode(['ok' => false, 'error' => 'This post has been deleted.']);
        exit;
    }
    if ($p_row['is_locked'] && !$is_staff) {
        echo json_encode(['ok' => false, 'error' => 'Comments are locked on this post.']);
        exit;
    }
    
    $c_safe = mysqli_real_escape_string($conn, $content);
    $ins = mysqli_query($conn, "INSERT INTO comments (post_id, parent_id, user_id, content, ip_address, is_deleted)
                         VALUES ($post_id, $parent_id, $uid, '$c_safe', '$client_ip_safe', 0)");
                         
    if ($ins) {
        $cid = mysqli_insert_id($conn);
        // Upvote own comment
        mysqli_query($conn, "INSERT INTO user_votes (user_id, target_type, target_id, vote_type) VALUES ($uid, 'comment', $cid, 1)");
        echo json_encode([
            'ok' => true,
            'comment' => [
                'id' => $cid,
                'post_id' => $post_id,
                'parent_id' => $parent_id,
                'user_id' => $uid,
                'content' => $content,
                'created_at' => date('Y-m-d H:i:s'),
                'username' => $curr_user['username'],
                'display_name' => $curr_user['display_name'] ?: $curr_user['username'],
                'user_role' => $curr_user['role'],
                'custom_badge' => $curr_user['custom_badge'] ?: '',
                'status_flair' => $curr_user['status_flair'] ?: '',
                'avatar_data' => $curr_user['avatar_data'] ?: '',
                'name_color' => $curr_user['name_color'] ?: '#94a3b8',
                'score' => 1,
                'user_vote' => 1
            ]
        ]);
    } else {
        echo json_encode(['ok' => false, 'error' => 'Failed to save comment: ' . mysqli_error($conn)]);
    }
    exit;
}

// ── Action: Delete Post ─────────────────────────────────────────────────────
if ($action === 'delete_post') {
    $pid = (int)($req['id'] ?? 0);
    $p_res = mysqli_query($conn, "SELECT user_id FROM posts WHERE id=$pid");
    if ($p_res && mysqli_num_rows($p_res) > 0) {
        $p = mysqli_fetch_assoc($p_res);
        if ($p['user_id'] == $uid || $is_staff) {
            mysqli_query($conn, "UPDATE posts SET is_deleted=1 WHERE id=$pid");
            echo json_encode(['ok' => true]);
            exit;
        }
    }
    echo json_encode(['ok' => false, 'error' => 'Unauthorized']);
    exit;
}

// ── Action: Delete Comment ──────────────────────────────────────────────────
if ($action === 'delete_comment') {
    $cid = (int)($req['id'] ?? 0);
    $c_res = mysqli_query($conn, "SELECT user_id FROM comments WHERE id=$cid");
    if ($c_res && mysqli_num_rows($c_res) > 0) {
        $c = mysqli_fetch_assoc($c_res);
        if ($c['user_id'] == $uid || $is_staff) {
            mysqli_query($conn, "UPDATE comments SET is_deleted=1 WHERE id=$cid");
            echo json_encode(['ok' => true]);
            exit;
        }
    }
    echo json_encode(['ok' => false, 'error' => 'Unauthorized']);
    exit;
}

// ── Action: Toggle Save Post ────────────────────────────────────────────────
if ($action === 'save_post') {
    $pid = (int)($req['id'] ?? 0);
    $s_chk = mysqli_query($conn, "SELECT id FROM saved_posts WHERE user_id=$uid AND post_id=$pid");
    if ($s_chk && mysqli_num_rows($s_chk) > 0) {
        mysqli_query($conn, "DELETE FROM saved_posts WHERE user_id=$uid AND post_id=$pid");
        echo json_encode(['ok' => true, 'is_saved' => false]);
    } else {
        mysqli_query($conn, "INSERT INTO saved_posts (user_id, post_id) VALUES ($uid, $pid)");
        echo json_encode(['ok' => true, 'is_saved' => true]);
    }
    exit;
}

// ── Action: Get Saved Posts ─────────────────────────────────────────────────
if ($action === 'get_saved') {
    $sql = "SELECT p.*, s.name as sub_name, u.username, u.display_name, u.custom_badge, u.avatar_data,
            COALESCE((SELECT SUM(vote_type) FROM user_votes WHERE target_type='post' AND target_id=p.id), 0) as score,
            (SELECT vote_type FROM user_votes WHERE target_type='post' AND target_id=p.id AND user_id=$uid) as user_vote,
            (SELECT COUNT(id) FROM comments WHERE post_id=p.id AND is_deleted=0) as comment_count
            FROM saved_posts sp
            JOIN posts p ON sp.post_id = p.id
            JOIN subbetters s ON p.subbetter_id = s.id
            JOIN users u ON p.user_id = u.id
            WHERE sp.user_id = $uid AND p.is_deleted = 0
            ORDER BY sp.created_at DESC";
    $res = mysqli_query($conn, $sql);
    $saved = [];
    while ($p = mysqli_fetch_assoc($res)) {
        $saved[] = [
            'id' => (int)$p['id'],
            'sub_name' => $p['sub_name'],
            'title' => $p['title'],
            'content' => $p['content'],
            'image_url' => $p['image_url'] ?: '',
            'link_url' => $p['link_url'] ?: '',
            'created_at' => $p['created_at'],
            'username' => $p['username'],
            'display_name' => $p['display_name'] ?: $p['username'],
            'custom_badge' => $p['custom_badge'] ?: '',
            'score' => (int)$p['score'],
            'user_vote' => $p['user_vote'] !== null ? (int)$p['user_vote'] : 0,
            'comment_count' => (int)$p['comment_count'],
            'is_saved' => true
        ];
    }
    echo json_encode(['ok' => true, 'posts' => $saved]);
    exit;
}

// ── Action: Create Subbetter ────────────────────────────────────────────────
if ($action === 'create_sub') {
    $name = trim($req['name'] ?? '');
    $desc = trim($req['description'] ?? '');
    $name_clean = preg_replace('/[^a-zA-Z0-9_-]/', '', $name);
    
    if (strlen($name_clean) < 3 || strlen($name_clean) > 30) {
        echo json_encode(['ok' => false, 'error' => 'Subbetter name must be between 3 and 30 alphanumeric characters.']);
        exit;
    }
    
    $name_safe = mysqli_real_escape_string($conn, $name_clean);
    $desc_safe = mysqli_real_escape_string($conn, $desc);
    
    $chk = mysqli_query($conn, "SELECT id FROM subbetters WHERE name='$name_safe'");
    if (mysqli_num_rows($chk) > 0) {
        echo json_encode(['ok' => false, 'error' => 'A subbetter with this name already exists.']);
        exit;
    }
    
    $ins = mysqli_query($conn, "INSERT INTO subbetters (name, description, created_by) VALUES ('$name_safe', '$desc_safe', '{$curr_user['username']}')");
    if ($ins) {
        echo json_encode(['ok' => true, 'name' => $name_clean]);
    } else {
        echo json_encode(['ok' => false, 'error' => 'Failed to create subbetter.']);
    }
    exit;
}

// ── Action: Get Profile ─────────────────────────────────────────────────────
if ($action === 'get_profile') {
    $target_u = trim($req['username'] ?? $curr_user['username']);
    $tu_safe = mysqli_real_escape_string($conn, $target_u);
    
    $u_res = mysqli_query($conn, "SELECT id, username, display_name, role, custom_badge, status_flair, avatar_data, bio, name_color, theme, created_at, is_admin, is_mod FROM users WHERE username='$tu_safe'");
    if (!$u_res || mysqli_num_rows($u_res) === 0) {
        echo json_encode(['ok' => false, 'error' => 'User not found']);
        exit;
    }
    $pu = mysqli_fetch_assoc($u_res);
    $p_uid = (int)$pu['id'];
    
    // Post karma
    $pk_q = mysqli_query($conn, "SELECT COALESCE(SUM(uv.vote_type), 0) as post_karma FROM user_votes uv JOIN posts p ON uv.target_id = p.id WHERE uv.target_type = 'post' AND p.user_id = $p_uid AND p.is_deleted = 0");
    $pk = $pk_q ? (int)mysqli_fetch_assoc($pk_q)['post_karma'] : 0;
    
    // Comment karma
    $ck_q = mysqli_query($conn, "SELECT COALESCE(SUM(uv.vote_type), 0) as comment_karma FROM user_votes uv JOIN comments c ON uv.target_id = c.id WHERE uv.target_type = 'comment' AND c.user_id = $p_uid AND c.is_deleted = 0");
    $ck = $ck_q ? (int)mysqli_fetch_assoc($ck_q)['comment_karma'] : 0;
    
    // Recent posts
    $posts_q = mysqli_query($conn, "SELECT p.*, s.name as sub_name,
               COALESCE((SELECT SUM(vote_type) FROM user_votes WHERE target_type='post' AND target_id=p.id), 0) as score,
               (SELECT COUNT(id) FROM comments WHERE post_id=p.id AND is_deleted=0) as comment_count
               FROM posts p
               JOIN subbetters s ON p.subbetter_id = s.id
               WHERE p.user_id = $p_uid AND p.is_deleted = 0
               ORDER BY p.created_at DESC LIMIT 20");
    $user_posts = [];
    while ($pr = mysqli_fetch_assoc($posts_q)) {
        $user_posts[] = [
            'id' => (int)$pr['id'],
            'sub_name' => $pr['sub_name'],
            'title' => $pr['title'],
            'content' => $pr['content'],
            'score' => (int)$pr['score'],
            'comment_count' => (int)$pr['comment_count'],
            'created_at' => $pr['created_at']
        ];
    }
    
    echo json_encode([
        'ok' => true,
        'profile' => [
            'id' => $p_uid,
            'username' => $pu['username'],
            'display_name' => $pu['display_name'] ?: $pu['username'],
            'role' => $pu['role'],
            'custom_badge' => $pu['custom_badge'] ?: '',
            'status_flair' => $pu['status_flair'] ?: '',
            'avatar_data' => $pu['avatar_data'] ?: '',
            'bio' => $pu['bio'] ?: '',
            'name_color' => $pu['name_color'] ?: '#94a3b8',
            'theme' => $pu['theme'] ?: 'dark',
            'created_at' => $pu['created_at'],
            'post_karma' => $pk,
            'comment_karma' => $ck,
            'total_karma' => $pk + $ck,
            'posts' => $user_posts
        ]
    ]);
    exit;
}

// ── Action: Update Profile ──────────────────────────────────────────────────
if ($action === 'update_profile') {
    $disp = trim($req['display_name'] ?? '');
    $bio = trim($req['bio'] ?? '');
    $avatar = trim($req['avatar_data'] ?? '');
    $status_flair = trim($req['status_flair'] ?? '');
    $theme = trim($req['theme'] ?? 'dark');
    
    $d_safe = mysqli_real_escape_string($conn, $disp ?: $curr_user['username']);
    $b_safe = mysqli_real_escape_string($conn, $bio);
    $a_safe = mysqli_real_escape_string($conn, $avatar);
    $s_safe = mysqli_real_escape_string($conn, $status_flair);
    $t_safe = mysqli_real_escape_string($conn, $theme);
    
    $update_sql = "UPDATE users SET display_name='$d_safe', bio='$b_safe', avatar_data='$a_safe', status_flair='$s_safe', theme='$t_safe' WHERE id=$uid";
    mysqli_query($conn, $update_sql);
    
    echo json_encode(['ok' => true]);
    exit;
}

// ── Action: Leaderboard ─────────────────────────────────────────────────────
if ($action === 'get_leaderboard') {
    $sql = "SELECT u.id, u.username, u.display_name, u.role, u.custom_badge, u.avatar_data, u.name_color,
            COALESCE((SELECT SUM(uv.vote_type) FROM user_votes uv JOIN posts p ON uv.target_id = p.id WHERE uv.target_type='post' AND p.user_id = u.id AND p.is_deleted=0), 0) +
            COALESCE((SELECT SUM(uv.vote_type) FROM user_votes uv JOIN comments c ON uv.target_id = c.id WHERE uv.target_type='comment' AND c.user_id = u.id AND c.is_deleted=0), 0) as total_karma,
            (SELECT COUNT(id) FROM posts WHERE user_id=u.id AND is_deleted=0) as post_count
            FROM users u
            WHERE u.is_shadowbanned = 0
            ORDER BY total_karma DESC
            LIMIT 50";
    $res = mysqli_query($conn, $sql);
    $board = [];
    while ($r = mysqli_fetch_assoc($res)) {
        $board[] = [
            'id' => (int)$r['id'],
            'username' => $r['username'],
            'display_name' => $r['display_name'] ?: $r['username'],
            'role' => $r['role'],
            'custom_badge' => $r['custom_badge'] ?: '',
            'avatar_data' => $r['avatar_data'] ?: '',
            'name_color' => $r['name_color'] ?: '#94a3b8',
            'total_karma' => (int)$r['total_karma'],
            'post_count' => (int)$r['post_count']
        ];
    }
    echo json_encode(['ok' => true, 'leaderboard' => $board]);
    exit;
}

// ── Action: Users Directory ─────────────────────────────────────────────────
if ($action === 'get_users') {
    $q = trim($req['q'] ?? '');
    $q_safe = mysqli_real_escape_string($conn, $q);
    $where = !empty($q) ? "WHERE (username LIKE '%$q_safe%' OR display_name LIKE '%$q_safe%') AND hide_from_search=0" : "WHERE hide_from_search=0";
    
    $res = mysqli_query($conn, "SELECT id, username, display_name, role, custom_badge, avatar_data, created_at FROM users $where ORDER BY id ASC LIMIT 60");
    $users = [];
    while ($r = mysqli_fetch_assoc($res)) {
        $users[] = [
            'id' => (int)$r['id'],
            'username' => $r['username'],
            'display_name' => $r['display_name'] ?: $r['username'],
            'role' => $r['role'],
            'custom_badge' => $r['custom_badge'] ?: '',
            'avatar_data' => $r['avatar_data'] ?: '',
            'created_at' => $r['created_at']
        ];
    }
    echo json_encode(['ok' => true, 'users' => $users]);
    exit;
}

// ── Action: Mod Tools / Actions ─────────────────────────────────────────────
if ($action === 'mod_action') {
    if (!$is_staff) {
        echo json_encode(['ok' => false, 'error' => 'Unauthorized: Moderator privileges required.']);
        exit;
    }
    
    $sub_act = trim($req['mod_act'] ?? '');
    
    if ($sub_act === 'ban_user') {
        $target = trim($req['target_username'] ?? '');
        $reason = trim($req['reason'] ?? 'Rule violation');
        if ($target) {
            $t_safe = mysqli_real_escape_string($conn, $target);
            $r_safe = mysqli_real_escape_string($conn, $reason);
            mysqli_query($conn, "INSERT INTO moderation_actions (target_username, action_type, status, reason, reviewed_by)
                                 VALUES ('$t_safe', 'BAN', 'APPROVED', '$r_safe', '{$curr_user['username']}')");
            echo json_encode(['ok' => true]);
            exit;
        }
    }
    
    if ($sub_act === 'unban_user') {
        $target = trim($req['target_username'] ?? '');
        if ($target) {
            $t_safe = mysqli_real_escape_string($conn, $target);
            mysqli_query($conn, "DELETE FROM moderation_actions WHERE target_username='$t_safe' AND action_type='BAN'");
            echo json_encode(['ok' => true]);
            exit;
        }
    }
    
    if ($sub_act === 'set_announcement' && $is_admin) {
        $msg = trim($req['announcement'] ?? '');
        $m_safe = mysqli_real_escape_string($conn, $msg);
        mysqli_query($conn, "UPDATE system_config SET announcement_banner='$m_safe' WHERE id=1");
        echo json_encode(['ok' => true]);
        exit;
    }
    
    if ($sub_act === 'toggle_maintenance' && $is_admin) {
        $val = (int)($req['maintenance'] ?? 0);
        $msg = trim($req['maintenance_msg'] ?? '');
        $m_safe = mysqli_real_escape_string($conn, $msg);
        mysqli_query($conn, "UPDATE system_config SET maintenance=$val, maintenance_msg='$m_safe' WHERE id=1");
        echo json_encode(['ok' => true]);
        exit;
    }
    
    if ($sub_act === 'pin_post') {
        $pid = (int)($req['id'] ?? 0);
        $val = (int)($req['val'] ?? 1);
        mysqli_query($conn, "UPDATE posts SET is_pinned=$val WHERE id=$pid");
        echo json_encode(['ok' => true]);
        exit;
    }
    
    if ($sub_act === 'lock_post') {
        $pid = (int)($req['id'] ?? 0);
        $val = (int)($req['val'] ?? 1);
        mysqli_query($conn, "UPDATE posts SET is_locked=$val WHERE id=$pid");
        echo json_encode(['ok' => true]);
        exit;
    }
    
    echo json_encode(['ok' => false, 'error' => 'Unknown mod action']);
    exit;
}

// ── Action: Admin / Staff Control Panel API ─────────────────────────────────
if ($action === 'admin_api' || isset($req['admin_api'])) {
    if (!$is_staff) {
        echo json_encode(['ok' => false, 'error' => 'Unauthorized: Staff privileges required.']);
        exit;
    }
    $api_act = trim($req['act'] ?? '');

    if ($api_act === 'get_users') {
        $q = trim($req['q'] ?? '');
        $q_safe = mysqli_real_escape_string($conn, $q);
        $where = !empty($q) ? "WHERE username LIKE '%$q_safe%' OR display_name LIKE '%$q_safe%' OR id = '$q_safe'" : "";
        $res = mysqli_query($conn, "SELECT id, username, display_name, role, custom_badge, status_flair, avatar_data, ip_address, is_admin, is_mod, is_vip, is_muted, is_shadowbanned, name_color, avatar_overlay, created_at, last_seen FROM users $where ORDER BY id ASC LIMIT 100");
        $users = [];
        while ($u = mysqli_fetch_assoc($res)) {
            $uname_chk = mysqli_real_escape_string($conn, $u['username']);
            $b_chk = mysqli_query($conn, "SELECT id, reason FROM moderation_actions WHERE target_username='$uname_chk' AND action_type='BAN' AND status='APPROVED' LIMIT 1");
            $u['is_banned'] = ($b_chk && mysqli_num_rows($b_chk) > 0);
            $u['ban_reason'] = $u['is_banned'] ? mysqli_fetch_assoc($b_chk)['reason'] : '';
            $u['is_owner'] = (strtolower($u['username']) === 'gollclock' || $u['role'] === 'OWNER');
            $users[] = $u;
        }
        echo json_encode(['ok' => true, 'users' => $users]);
        exit;
    }

    if ($api_act === 'get_bans') {
        $q = trim($req['q'] ?? '');
        $q_safe = mysqli_real_escape_string($conn, $q);
        $where = !empty($q) ? "AND target_username LIKE '%$q_safe%'" : "";
        $res = mysqli_query($conn, "SELECT id, action_type, target_username, reason, reviewed_by, created_at FROM moderation_actions WHERE action_type='BAN' AND status='APPROVED' $where ORDER BY id DESC LIMIT 100");
        $bans = [];
        while ($b = mysqli_fetch_assoc($res)) { $bans[] = $b; }
        echo json_encode(['ok' => true, 'bans' => $bans]);
        exit;
    }

    if ($api_act === 'get_maint_status') {
        $m_chk = mysqli_query($conn, "SELECT maintenance, maintenance_msg FROM system_config WHERE id=1");
        $m_r = mysqli_fetch_assoc($m_chk);
        echo json_encode([
            'ok' => true,
            'maintenance' => $m_r ? intval($m_r['maintenance']) : 0,
            'message' => $m_r ? $m_r['maintenance_msg'] : ''
        ]);
        exit;
    }

    if ($api_act === 'toggle_maint' && $is_admin) {
        $val = intval($req['val'] ?? 0);
        mysqli_query($conn, "UPDATE system_config SET maintenance=$val WHERE id=1");
        echo json_encode(['ok' => true, 'maintenance' => $val]);
        exit;
    }

    if ($api_act === 'save_maint_msg' && $is_admin) {
        $msg = trim($req['message'] ?? '');
        $msg_safe = mysqli_real_escape_string($conn, $msg);
        mysqli_query($conn, "UPDATE system_config SET maintenance_msg='$msg_safe' WHERE id=1");
        echo json_encode(['ok' => true, 'message' => $msg]);
        exit;
    }

    if ($api_act === 'admin_announce' && $is_admin) {
        $msg = trim($req['message'] ?? '');
        $msg_safe = mysqli_real_escape_string($conn, $msg);
        mysqli_query($conn, "UPDATE system_config SET announcement_banner='$msg_safe' WHERE id=1");
        echo json_encode(['ok' => true, 'announcement' => $msg]);
        exit;
    }

    if ($api_act === 'get_channels') {
        $res = mysqli_query($conn, "SELECT s.*, COUNT(p.id) as post_count FROM subbetters s LEFT JOIN posts p ON s.id=p.subbetter_id AND p.is_deleted=0 GROUP BY s.id ORDER BY s.name ASC");
        $channels = [];
        while ($c_row = mysqli_fetch_assoc($res)) { $channels[] = $c_row; }
        echo json_encode(['ok' => true, 'channels' => $channels]);
        exit;
    }

    if ($api_act === 'add_channel' && $is_staff) {
        $name = trim(strtolower($req['name'] ?? ''));
        $desc = trim($req['description'] ?? '');
        $name = preg_replace('/[^a-z0-9_]/', '', $name);
        if (strlen($name) < 2 || strlen($name) > 30) {
            echo json_encode(['ok' => false, 'error' => 'Community name must be 2-30 alphanumeric characters.']);
            exit;
        }
        $n_safe = mysqli_real_escape_string($conn, $name);
        $d_safe = mysqli_real_escape_string($conn, $desc);
        $by_safe = mysqli_real_escape_string($conn, $curr_user['username']);
        $chk = mysqli_query($conn, "SELECT id FROM subbetters WHERE name='$n_safe'");
        if (mysqli_num_rows($chk) > 0) {
            echo json_encode(['ok' => false, 'error' => 'Community already exists.']);
            exit;
        }
        mysqli_query($conn, "INSERT INTO subbetters (name, description, created_by) VALUES ('$n_safe', '$d_safe', '$by_safe')");
        echo json_encode(['ok' => true]);
        exit;
    }

    if ($api_act === 'delete_channel' && $is_admin) {
        $cid = intval($req['channel_id'] ?? 0);
        if ($cid > 0) { mysqli_query($conn, "DELETE FROM subbetters WHERE id=$cid"); }
        echo json_encode(['ok' => true]);
        exit;
    }

    if ($api_act === 'toggle_lock_channel' && $is_staff) {
        $cid = intval($req['channel_id'] ?? 0);
        if ($cid > 0) { mysqli_query($conn, "UPDATE subbetters SET is_locked = 1 - is_locked WHERE id=$cid"); }
        echo json_encode(['ok' => true]);
        exit;
    }

    if ($api_act === 'clear_channel' && $is_admin) {
        $cid = intval($req['channel_id'] ?? 0);
        if ($cid > 0) { mysqli_query($conn, "UPDATE posts SET is_deleted = 1 WHERE subbetter_id=$cid AND is_pinned=0"); }
        echo json_encode(['ok' => true]);
        exit;
    }

    if ($api_act === 'get_stats') {
        $u_cnt = mysqli_fetch_assoc(mysqli_query($conn, "SELECT COUNT(*) as c FROM users"))['c'];
        $p_cnt = mysqli_fetch_assoc(mysqli_query($conn, "SELECT COUNT(*) as c FROM posts WHERE is_deleted=0"))['c'];
        $c_cnt = mysqli_fetch_assoc(mysqli_query($conn, "SELECT COUNT(*) as c FROM comments WHERE is_deleted=0"))['c'];
        $s_cnt = mysqli_fetch_assoc(mysqli_query($conn, "SELECT COUNT(*) as c FROM subbetters"))['c'];
        $b_cnt = mysqli_fetch_assoc(mysqli_query($conn, "SELECT COUNT(*) as c FROM moderation_actions WHERE action_type='BAN' AND status='APPROVED'"))['c'];
        $m_cnt = mysqli_fetch_assoc(mysqli_query($conn, "SELECT COUNT(*) as c FROM motd_pool"))['c'];
        $h_cnt = mysqli_fetch_assoc(mysqli_query($conn, "SELECT hit_counter FROM system_config WHERE id=1"))['hit_counter'];
        echo json_encode([
            'ok' => true,
            'stats' => [
                'total_users' => intval($u_cnt),
                'total_posts' => intval($p_cnt),
                'total_comments' => intval($c_cnt),
                'total_channels' => intval($s_cnt),
                'total_bans' => intval($b_cnt),
                'total_motds' => intval($m_cnt),
                'hit_counter' => intval($h_cnt)
            ]
        ]);
        exit;
    }

    if ($api_act === 'admin_action') {
        $target_id = intval($req['target_user_id'] ?? 0);
        $sub_action = trim($req['sub_action'] ?? '');
        $t_res = mysqli_query($conn, "SELECT * FROM users WHERE id=$target_id");
        if (!$t_res || mysqli_num_rows($t_res) === 0) {
            echo json_encode(['ok' => false, 'error' => 'Target user not found.']);
            exit;
        }
        $target_user = mysqli_fetch_assoc($t_res);
        $t_name = $target_user['username'];
        $t_uname_safe = mysqli_real_escape_string($conn, $t_name);
        $is_target_gollclock = (strtolower($t_name) === 'gollclock');

        if ($is_target_gollclock && in_array($sub_action, ['remove_rank', 'promote_mod', 'promote_admin', 'ban_user', 'delete_user', 'shadowban', 'mute'])) {
            echo json_encode(['ok' => false, 'error' => 'gollclock always has Owner privileges and cannot be modified.']);
            exit;
        }

        if ($sub_action === 'promote_owner') {
            if (!$is_owner) { echo json_encode(['ok' => false, 'error' => 'Only Owners can grant the Owner role.']); exit; }
            mysqli_query($conn, "UPDATE users SET role='OWNER', custom_badge='Owner', is_admin=1, is_mod=1 WHERE id=$target_id");
            echo json_encode(['ok' => true, 'msg' => "User u/$t_name promoted to Owner!"]);
            exit;
        }
        if ($sub_action === 'promote_admin') {
            if (!$is_admin) { echo json_encode(['ok' => false, 'error' => 'Only Admins can promote users to Admin.']); exit; }
            mysqli_query($conn, "UPDATE users SET role='ADMIN', custom_badge='Admin', is_admin=1, is_mod=1 WHERE id=$target_id");
            echo json_encode(['ok' => true, 'msg' => "User u/$t_name promoted to Admin!"]);
            exit;
        }
        if ($sub_action === 'promote_mod') {
            if (!$is_admin) { echo json_encode(['ok' => false, 'error' => 'Only Admins can promote users to Mod.']); exit; }
            mysqli_query($conn, "UPDATE users SET role='MOD', custom_badge='Moderator', is_admin=0, is_mod=1 WHERE id=$target_id");
            echo json_encode(['ok' => true, 'msg' => "User u/$t_name promoted to Mod!"]);
            exit;
        }
        if ($sub_action === 'remove_rank') {
            if (!$is_admin) { echo json_encode(['ok' => false, 'error' => 'Only Admins can manage ranks.']); exit; }
            mysqli_query($conn, "UPDATE users SET role='USER', custom_badge='', is_admin=0, is_mod=0 WHERE id=$target_id");
            echo json_encode(['ok' => true, 'msg' => "User u/$t_name rank set to Regular User."]);
            exit;
        }
        if ($sub_action === 'set_custom_badge') {
            $badge = trim($req['badge'] ?? '');
            $b_safe = mysqli_real_escape_string($conn, $badge);
            mysqli_query($conn, "UPDATE users SET custom_badge='$b_safe' WHERE id=$target_id");
            echo json_encode(['ok' => true, 'msg' => "Custom badge updated for u/$t_name."]);
            exit;
        }
        if ($sub_action === 'set_status_flair') {
            $flair = trim($req['flair'] ?? '');
            $f_safe = mysqli_real_escape_string($conn, $flair);
            mysqli_query($conn, "UPDATE users SET status_flair='$f_safe' WHERE id=$target_id");
            echo json_encode(['ok' => true, 'msg' => "Status flair updated for u/$t_name."]);
            exit;
        }
        if ($sub_action === 'ban_user') {
            $reason = trim($req['reason'] ?? 'Violating forum rules');
            $r_safe = mysqli_real_escape_string($conn, $reason);
            $by_safe = mysqli_real_escape_string($conn, $curr_user['username']);
            mysqli_query($conn, "INSERT INTO moderation_actions (action_type, target_username, reason, status, reviewed_by) VALUES ('BAN', '$t_uname_safe', '$r_safe', 'APPROVED', '$by_safe')");
            echo json_encode(['ok' => true, 'msg' => "User u/$t_name has been banned."]);
            exit;
        }
        if ($sub_action === 'unban_user') {
            $by_safe = mysqli_real_escape_string($conn, $curr_user['username']);
            mysqli_query($conn, "UPDATE moderation_actions SET status='DISMISSED', reviewed_by='$by_safe' WHERE target_username='$t_uname_safe' AND action_type='BAN'");
            echo json_encode(['ok' => true, 'msg' => "User u/$t_name has been unbanned."]);
            exit;
        }
        if ($sub_action === 'shadowban') {
            mysqli_query($conn, "UPDATE users SET is_shadowbanned = 1 WHERE id=$target_id");
            echo json_encode(['ok' => true, 'msg' => "User u/$t_name is now shadowbanned."]);
            exit;
        }
        if ($sub_action === 'unshadowban') {
            mysqli_query($conn, "UPDATE users SET is_shadowbanned = 0 WHERE id=$target_id");
            echo json_encode(['ok' => true, 'msg' => "User u/$t_name shadowban lifted."]);
            exit;
        }
        if ($sub_action === 'mute') {
            mysqli_query($conn, "UPDATE users SET is_muted = 1 WHERE id=$target_id");
            echo json_encode(['ok' => true, 'msg' => "User u/$t_name muted."]);
            exit;
        }
        if ($sub_action === 'unmute') {
            mysqli_query($conn, "UPDATE users SET is_muted = 0 WHERE id=$target_id");
            echo json_encode(['ok' => true, 'msg' => "User u/$t_name unmuted."]);
            exit;
        }
        if ($sub_action === 'reset_password') {
            $new_pw = trim($req['new_password'] ?? '');
            if (strlen($new_pw) < 4) { echo json_encode(['ok' => false, 'error' => 'Password must be at least 4 characters.']); exit; }
            $phash = password_hash($new_pw, PASSWORD_DEFAULT);
            $phash_safe = mysqli_real_escape_string($conn, $phash);
            mysqli_query($conn, "UPDATE users SET password_hash='$phash_safe' WHERE id=$target_id");
            echo json_encode(['ok' => true, 'msg' => "Password reset for u/$t_name."]);
            exit;
        }
        if ($sub_action === 'reset_avatar') {
            mysqli_query($conn, "UPDATE users SET avatar_data='' WHERE id=$target_id");
            echo json_encode(['ok' => true, 'msg' => "Avatar reset for u/$t_name."]);
            exit;
        }
        if ($sub_action === 'purge_user') {
            mysqli_query($conn, "UPDATE posts SET is_deleted=1 WHERE user_id=$target_id");
            mysqli_query($conn, "UPDATE comments SET is_deleted=1 WHERE user_id=$target_id");
            echo json_encode(['ok' => true, 'msg' => "Purged content for u/$t_name."]);
            exit;
        }
        if ($sub_action === 'delete_user' && $is_admin) {
            mysqli_query($conn, "DELETE FROM users WHERE id=$target_id");
            mysqli_query($conn, "UPDATE posts SET is_deleted=1 WHERE user_id=$target_id");
            mysqli_query($conn, "UPDATE comments SET is_deleted=1 WHERE user_id=$target_id");
            echo json_encode(['ok' => true, 'msg' => "Deleted account u/$t_name."]);
            exit;
        }
    }

    if ($api_act === 'purge_user_id' && $is_staff) {
        $uid_to_purge = intval($req['user_id'] ?? 0);
        if ($uid_to_purge > 0) {
            mysqli_query($conn, "UPDATE posts SET is_deleted=1 WHERE user_id=$uid_to_purge");
            mysqli_query($conn, "UPDATE comments SET is_deleted=1 WHERE user_id=$uid_to_purge");
        }
        echo json_encode(['ok' => true, 'msg' => "Purged user content for #$uid_to_purge."]);
        exit;
    }

    if ($api_act === 'get_settings') {
        $s_chk = mysqli_query($conn, "SELECT site_settings FROM system_config WHERE id=1");
        $st = mysqli_fetch_assoc($s_chk);
        $settings_json = ($st && !empty($st['site_settings'])) ? json_decode($st['site_settings'], true) : [];
        echo json_encode(['ok' => true, 'settings' => $settings_json]);
        exit;
    }

    if ($api_act === 'save_settings' && $is_admin) {
        $settings_raw = $req['settings'] ?? '{}';
        $s_safe = mysqli_real_escape_string($conn, is_string($settings_raw) ? $settings_raw : json_encode($settings_raw));
        mysqli_query($conn, "UPDATE system_config SET site_settings='$s_safe' WHERE id=1");
        echo json_encode(['ok' => true]);
        exit;
    }

    if ($api_act === 'get_sessions') {
        $res = mysqli_query($conn, "SELECT id, username, ip_address, role, custom_badge, last_seen, created_at FROM users ORDER BY id DESC LIMIT 50");
        $sessions = [];
        while ($row = mysqli_fetch_assoc($res)) { $sessions[] = $row; }
        echo json_encode(['ok' => true, 'sessions' => $sessions]);
        exit;
    }

    if ($api_act === 'get_feedbacks') {
        $res = mysqli_query($conn, "SELECT * FROM feedbacks ORDER BY id DESC LIMIT 50");
        $feedbacks = [];
        if ($res) { while ($row = mysqli_fetch_assoc($res)) { $feedbacks[] = $row; } }
        echo json_encode(['ok' => true, 'feedbacks' => $feedbacks]);
        exit;
    }

    if ($api_act === 'get_ban_template') {
        $b_chk = mysqli_query($conn, "SELECT ban_templates FROM system_config WHERE id=1");
        $bt = mysqli_fetch_assoc($b_chk);
        echo json_encode(['ok' => true, 'template' => ($bt && !empty($bt['ban_templates'])) ? $bt['ban_templates'] : '']);
        exit;
    }

    if ($api_act === 'save_ban_template' && $is_admin) {
        $tpl = trim($req['template'] ?? '');
        $t_safe = mysqli_real_escape_string($conn, $tpl);
        mysqli_query($conn, "UPDATE system_config SET ban_templates='$t_safe' WHERE id=1");
        echo json_encode(['ok' => true]);
        exit;
    }

    if ($api_act === 'start_nitro_challenge' && $is_owner) {
        $word = trim($req['secret_word'] ?? '');
        $w_safe = mysqli_real_escape_string($conn, $word);
        mysqli_query($conn, "UPDATE system_config SET nitro_word='$w_safe' WHERE id=1");
        echo json_encode(['ok' => true, 'msg' => "Nitro Challenge started! Secret word saved."]);
        exit;
    }

    if ($api_act === 'get_roles') {
        $res = mysqli_query($conn, "SELECT * FROM roles ORDER BY id ASC");
        $roles = [];
        if ($res) { while ($row = mysqli_fetch_assoc($res)) { $roles[] = $row; } }
        echo json_encode(['ok' => true, 'roles' => $roles]);
        exit;
    }

    if ($api_act === 'create_role' && $is_owner) {
        $name = trim($req['name'] ?? '');
        $color = trim($req['color'] ?? '#38bdf8');
        $perms = $req['permissions'] ?? '[]';
        if (!empty($name)) {
            $n_safe = mysqli_real_escape_string($conn, $name);
            $c_safe = mysqli_real_escape_string($conn, $color);
            $p_safe = mysqli_real_escape_string($conn, is_array($perms) ? json_encode($perms) : $perms);
            mysqli_query($conn, "INSERT INTO roles (name, color, permissions) VALUES ('$n_safe', '$c_safe', '$p_safe')");
        }
        echo json_encode(['ok' => true]);
        exit;
    }

    if ($api_act === 'delete_role' && $is_owner) {
        $rid = intval($req['role_id'] ?? 0);
        if ($rid > 0) { mysqli_query($conn, "DELETE FROM roles WHERE id=$rid"); }
        echo json_encode(['ok' => true]);
        exit;
    }

    if ($api_act === 'set_avatar_overlay' && $is_owner) {
        $target_id = intval($req['target_user_id'] ?? 0);
        $ov_json = $req['overlay'] ?? '';
        $ov_safe = mysqli_real_escape_string($conn, is_string($ov_json) ? $ov_json : json_encode($ov_json));
        mysqli_query($conn, "UPDATE users SET avatar_overlay='$ov_safe' WHERE id=$target_id");
        echo json_encode(['ok' => true]);
        exit;
    }

    echo json_encode(['ok' => false, 'error' => 'Unknown admin action: ' . htmlspecialchars($api_act)]);
    exit;
}

echo json_encode(['ok' => false, 'error' => 'Unknown action: ' . htmlspecialchars($action)]);
