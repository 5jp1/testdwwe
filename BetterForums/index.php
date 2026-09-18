<?php
$page_start_time = microtime(true);
require_once __DIR__ . '/db.php';

if (!isset($_COOKIE['BF_AUTH_SAFE'])) {
    if (isset($_REQUEST['live_sync'])) {
        header('Content-Type: application/json');
        echo json_encode(['ok' => true, 'logged_out' => true]);
        exit;
    }
    header("Location: login.php");
    exit;
}

$decoded_auth = base64_decode($_COOKIE['BF_AUTH_SAFE']);
$auth_parts = explode(':', $decoded_auth, 2);
if (count($auth_parts) !== 2) {
    setcookie('BF_AUTH_SAFE', '', time() - 3600, '/');
    if (isset($_REQUEST['live_sync'])) {
        header('Content-Type: application/json');
        echo json_encode(['ok' => true, 'logged_out' => true]);
        exit;
    }
    header("Location: login.php");
    exit;
}

$auth_username = mysqli_real_escape_string($conn, $auth_parts[0]);
$auth_hash_md5 = $auth_parts[1];

$user_query = mysqli_query($conn, "SELECT * FROM users WHERE username = '$auth_username'");
if (!$user_query || mysqli_num_rows($user_query) === 0) {
    setcookie('BF_AUTH_SAFE', '', time() - 3600, '/');
    if (isset($_REQUEST['live_sync'])) {
        header('Content-Type: application/json');
        echo json_encode(['ok' => true, 'logged_out' => true]);
        exit;
    }
    header("Location: login.php");
    exit;
}

$curr_user = mysqli_fetch_assoc($user_query);
if (md5($curr_user['password_hash']) !== $auth_hash_md5) {
    setcookie('BF_AUTH_SAFE', '', time() - 3600, '/');
    if (isset($_REQUEST['live_sync'])) {
        header('Content-Type: application/json');
        echo json_encode(['ok' => true, 'logged_out' => true]);
        exit;
    }
    header("Location: login.php");
    exit;
}

if (!function_exists('get_real_client_ip')) {
    function get_real_client_ip() {
        $headers = [
            'HTTP_CF_CONNECTING_IP',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_REAL_IP',
            'HTTP_CLIENT_IP',
            'REMOTE_ADDR'
        ];
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
        return isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '127.0.0.1';
    }
}

$remote_ip = get_real_client_ip();
$rip_safe = mysqli_real_escape_string($conn, $remote_ip);

// Never ban loopback / internal proxy addresses
$is_loopback = in_array($remote_ip, ['127.0.0.1', '::1', '0.0.0.0', 'localhost']);
if (!$is_loopback && $curr_user['role'] !== 'OWNER') {
    $ip_ban_q = mysqli_query($conn, "SELECT id, reason FROM ip_bans WHERE ip_address='$rip_safe'");
    if ($ip_ban_q && mysqli_num_rows($ip_ban_q) > 0) {
        $ip_ban_row = mysqli_fetch_assoc($ip_ban_q);
        if (isset($_REQUEST['live_sync'])) {
            header('Content-Type: application/json');
            echo json_encode(['ok' => true, 'banned' => true, 'ban_reason' => $ip_ban_row['reason'] ? $ip_ban_row['reason'] : 'Your IP address has been banned']);
            exit;
        }
        setcookie('BF_AUTH_SAFE', '', time() - 3600, '/');
        header("Location: login.php");
        exit;
    }
}

if ($curr_user['role'] !== 'OWNER') {
    $ban_check = mysqli_query($conn, "SELECT id, reason FROM moderation_actions WHERE target_username = '{$curr_user['username']}' AND action_type = 'BAN' AND status = 'APPROVED'");
    if ($ban_check && mysqli_num_rows($ban_check) > 0) {
        $ban_row = mysqli_fetch_assoc($ban_check);
        if (isset($_REQUEST['live_sync'])) {
            header('Content-Type: application/json');
            echo json_encode(['ok' => true, 'banned' => true, 'ban_reason' => $ban_row['reason'] ? $ban_row['reason'] : 'Account suspended']);
            exit;
        }
        setcookie('BF_AUTH_SAFE', '', time() - 3600, '/');
        header("Location: login.php?error=banned");
        exit;
    }
}

if ($curr_user['ip_address'] !== $remote_ip) {
    mysqli_query($conn, "UPDATE users SET ip_address = '$rip_safe' WHERE id = " . intval($curr_user['id']));
    $curr_user['ip_address'] = $remote_ip;
}

mysqli_query($conn, "UPDATE system_config SET hit_counter = hit_counter + 1 WHERE id = 1");
$hc_res = mysqli_query($conn, "SELECT hit_counter, announcement_banner FROM system_config WHERE id = 1");
$cfg_data = mysqli_fetch_assoc($hc_res);
$hit_counter_val = $cfg_data ? $cfg_data['hit_counter'] : 1;
$announcement_banner = $cfg_data ? $cfg_data['announcement_banner'] : '';

$is_super_admin = (strtolower($curr_user['username']) === 'gollclock');
if ($is_super_admin) {
    if ($curr_user['role'] !== 'OWNER' || $curr_user['custom_badge'] !== 'Owner' || empty($curr_user['is_admin']) || empty($curr_user['is_mod'])) {
        mysqli_query($conn, "UPDATE users SET role = 'OWNER', custom_badge = 'Owner', is_admin = 1, is_mod = 1 WHERE id = " . intval($curr_user['id']));
    }
    $curr_user['role'] = 'OWNER';
    $curr_user['custom_badge'] = 'Owner';
    $curr_user['is_admin'] = 1;
    $curr_user['is_mod'] = 1;
}

$is_owner = ($curr_user['role'] === 'OWNER' || $is_super_admin);
$is_admin = ($curr_user['role'] === 'ADMIN' || !empty($curr_user['is_admin']) || $is_owner);
$is_mod = ($curr_user['role'] === 'MOD' || !empty($curr_user['is_mod']) || $is_admin);
$is_staff = $is_mod;

// Check maintenance mode
$maint_chk = mysqli_query($conn, "SELECT maintenance, maintenance_msg FROM system_config WHERE id=1");
$maint_data = mysqli_fetch_assoc($maint_chk);
$is_maint_active = $maint_data && intval($maint_data['maintenance']) === 1;
$maint_msg = ($maint_data && !empty($maint_data['maintenance_msg'])) ? $maint_data['maintenance_msg'] : 'BetterForums is currently undergoing scheduled maintenance. Please check back shortly.';

if ($is_maint_active && !$is_admin && !isset($_REQUEST['admin_api']) && !isset($_REQUEST['live_sync'])) {
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Maintenance Mode - BetterForums</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
        <style>
            body { background:#0f172a; color:#f8fafc; font-family:ui-sans-serif, system-ui, sans-serif; display:flex; align-items:center; justify-content:center; min-height:100vh; margin:0; padding:20px; }
            .maint-card { background:#1e293b; border:1px solid #334155; border-radius:14px; padding:36px; max-width:480px; text-align:center; box-shadow:0 25px 60px rgba(0,0,0,0.7); }
        </style>
    </head>
    <body>
        <div class="maint-card">
            <div style="width:60px; height:60px; background:rgba(234,179,8,0.15); border:1px solid rgba(234,179,8,0.3); border-radius:50%; display:flex; align-items:center; justify-content:center; margin:0 auto 16px; color:#fbbf24; font-size:24px;">
                <i class="fa-solid fa-wrench"></i>
            </div>
            <h2 style="font-size:20px; font-weight:bold; margin-bottom:10px; color:#f8fafc;">Maintenance Mode</h2>
            <p style="color:#94a3b8; font-size:13px; line-height:1.6; margin-bottom:20px;"><?php echo nl2br(htmlspecialchars($maint_msg, ENT_QUOTES, 'UTF-8')); ?></p>
            <div style="font-size:11px; color:#64748b;">BetterForums staff can bypass maintenance by logging into an Admin/Owner account.</div>
        </div>
    </body>
    </html>
    <?php
    exit;
}

if (isset($_REQUEST['admin_api'])) {
    header('Content-Type: application/json');
    if (!$is_staff) {
        echo json_encode(['ok' => false, 'error' => 'Unauthorized: Staff privileges required.']);
        exit;
    }
    $api_act = isset($_REQUEST['act']) ? trim($_REQUEST['act']) : '';
    
    if ($api_act === 'get_users') {
        $q = isset($_REQUEST['q']) ? trim($_REQUEST['q']) : '';
        $q_safe = mysqli_real_escape_string($conn, $q);
        $where = !empty($q) ? "WHERE username LIKE '%$q_safe%' OR display_name LIKE '%$q_safe%' OR id = '$q_safe'" : "";
        $res = mysqli_query($conn, "SELECT id, username, display_name, role, custom_badge, status_flair, avatar_data, ip_address, is_admin, is_mod, is_vip, is_muted, is_shadowbanned, name_color, avatar_overlay, created_at, last_seen FROM users $where ORDER BY id ASC LIMIT 100");
        $users = [];
        while ($u = mysqli_fetch_assoc($res)) {
            $uid = intval($u['id']);
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
        $q = isset($_REQUEST['q']) ? trim($_REQUEST['q']) : '';
        $q_safe = mysqli_real_escape_string($conn, $q);
        $where = !empty($q) ? "AND target_username LIKE '%$q_safe%'" : "";
        $res = mysqli_query($conn, "SELECT id, action_type, target_username, reason, reviewed_by, created_at FROM moderation_actions WHERE action_type='BAN' AND status='APPROVED' $where ORDER BY id DESC LIMIT 100");
        $bans = [];
        while ($b = mysqli_fetch_assoc($res)) {
            $bans[] = $b;
        }
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
        $val = isset($_REQUEST['val']) ? intval($_REQUEST['val']) : 0;
        mysqli_query($conn, "UPDATE system_config SET maintenance=$val WHERE id=1");
        echo json_encode(['ok' => true, 'maintenance' => $val]);
        exit;
    }

    if ($api_act === 'save_maint_msg' && $is_admin) {
        $msg = isset($_REQUEST['message']) ? trim($_REQUEST['message']) : '';
        $msg_safe = mysqli_real_escape_string($conn, $msg);
        mysqli_query($conn, "UPDATE system_config SET maintenance_msg='$msg_safe' WHERE id=1");
        echo json_encode(['ok' => true, 'message' => $msg]);
        exit;
    }

    if ($api_act === 'admin_announce' && $is_admin) {
        $msg = isset($_REQUEST['message']) ? trim($_REQUEST['message']) : '';
        $msg_safe = mysqli_real_escape_string($conn, $msg);
        mysqli_query($conn, "UPDATE system_config SET announcement_banner='$msg_safe' WHERE id=1");
        echo json_encode(['ok' => true, 'announcement' => $msg]);
        exit;
    }

    if ($api_act === 'get_channels') {
        $res = mysqli_query($conn, "SELECT s.*, COUNT(p.id) as post_count FROM subbetters s LEFT JOIN posts p ON s.id=p.subbetter_id AND p.is_deleted=0 GROUP BY s.id ORDER BY s.name ASC");
        $channels = [];
        while ($c_row = mysqli_fetch_assoc($res)) {
            $channels[] = $c_row;
        }
        echo json_encode(['ok' => true, 'channels' => $channels]);
        exit;
    }

    if ($api_act === 'add_channel' && $is_staff) {
        $name = isset($_REQUEST['name']) ? trim(strtolower($_REQUEST['name'])) : '';
        $desc = isset($_REQUEST['description']) ? trim($_REQUEST['description']) : '';
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
        $cid = isset($_REQUEST['channel_id']) ? intval($_REQUEST['channel_id']) : 0;
        if ($cid > 0) {
            mysqli_query($conn, "DELETE FROM subbetters WHERE id=$cid");
        }
        echo json_encode(['ok' => true]);
        exit;
    }

    if ($api_act === 'toggle_lock_channel' && $is_staff) {
        $cid = isset($_REQUEST['channel_id']) ? intval($_REQUEST['channel_id']) : 0;
        if ($cid > 0) {
            mysqli_query($conn, "UPDATE subbetters SET is_locked = 1 - is_locked WHERE id=$cid");
        }
        echo json_encode(['ok' => true]);
        exit;
    }

    if ($api_act === 'clear_channel' && $is_admin) {
        $cid = isset($_REQUEST['channel_id']) ? intval($_REQUEST['channel_id']) : 0;
        if ($cid > 0) {
            mysqli_query($conn, "UPDATE posts SET is_deleted = 1 WHERE subbetter_id=$cid AND is_pinned=0");
        }
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
        $target_id = isset($_REQUEST['target_user_id']) ? intval($_REQUEST['target_user_id']) : 0;
        $sub_action = isset($_REQUEST['sub_action']) ? trim($_REQUEST['sub_action']) : '';
        
        $t_res = mysqli_query($conn, "SELECT * FROM users WHERE id=$target_id");
        if (!$t_res || mysqli_num_rows($t_res) === 0) {
            echo json_encode(['ok' => false, 'error' => 'Target user not found.']);
            exit;
        }
        $target_user = mysqli_fetch_assoc($t_res);
        $t_name = $target_user['username'];
        $t_uname_safe = mysqli_real_escape_string($conn, $t_name);
        $is_target_gollclock = (strtolower($t_name) === 'gollclock');

        // Protect gollclock
        if ($is_target_gollclock && in_array($sub_action, ['remove_rank', 'promote_mod', 'promote_admin', 'ban_user', 'delete_user', 'shadowban', 'mute'])) {
            echo json_encode(['ok' => false, 'error' => 'gollclock always has Owner privileges and cannot be modified.']);
            exit;
        }

        if ($sub_action === 'promote_owner') {
            if (!$is_owner) {
                echo json_encode(['ok' => false, 'error' => 'Only Owners can grant the Owner role.']);
                exit;
            }
            mysqli_query($conn, "UPDATE users SET role='OWNER', custom_badge='Owner', is_admin=1, is_mod=1 WHERE id=$target_id");
            echo json_encode(['ok' => true, 'msg' => "User u/$t_name has been promoted to Owner!"]);
            exit;
        }

        if ($sub_action === 'promote_admin') {
            if (!$is_admin) {
                echo json_encode(['ok' => false, 'error' => 'Only Admins or Owners can promote users to Admin.']);
                exit;
            }
            mysqli_query($conn, "UPDATE users SET role='ADMIN', custom_badge='Admin', is_admin=1, is_mod=1 WHERE id=$target_id");
            echo json_encode(['ok' => true, 'msg' => "User u/$t_name has been promoted to Admin!"]);
            exit;
        }

        if ($sub_action === 'promote_mod') {
            if (!$is_admin) {
                echo json_encode(['ok' => false, 'error' => 'Only Admins or Owners can promote users to Moderator.']);
                exit;
            }
            mysqli_query($conn, "UPDATE users SET role='MOD', custom_badge='Moderator', is_admin=0, is_mod=1 WHERE id=$target_id");
            echo json_encode(['ok' => true, 'msg' => "User u/$t_name has been promoted to Moderator!"]);
            exit;
        }

        if ($sub_action === 'remove_rank') {
            if (!$is_admin) {
                echo json_encode(['ok' => false, 'error' => 'Only Admins or Owners can manage ranks.']);
                exit;
            }
            mysqli_query($conn, "UPDATE users SET role='USER', custom_badge='', is_admin=0, is_mod=0 WHERE id=$target_id");
            echo json_encode(['ok' => true, 'msg' => "User u/$t_name rank removed (Regular User)."]);
            exit;
        }

        if ($sub_action === 'set_custom_badge') {
            $badge = isset($_REQUEST['badge']) ? trim($_REQUEST['badge']) : '';
            $b_safe = mysqli_real_escape_string($conn, $badge);
            mysqli_query($conn, "UPDATE users SET custom_badge='$b_safe' WHERE id=$target_id");
            echo json_encode(['ok' => true, 'msg' => "Custom badge updated for u/$t_name."]);
            exit;
        }

        if ($sub_action === 'set_status_flair') {
            $flair = isset($_REQUEST['flair']) ? trim($_REQUEST['flair']) : '';
            $f_safe = mysqli_real_escape_string($conn, $flair);
            mysqli_query($conn, "UPDATE users SET status_flair='$f_safe' WHERE id=$target_id");
            echo json_encode(['ok' => true, 'msg' => "Status flair updated for u/$t_name."]);
            exit;
        }

        if ($sub_action === 'ban_user') {
            $reason = isset($_REQUEST['reason']) ? trim($_REQUEST['reason']) : 'Violating forum rules';
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
            echo json_encode(['ok' => true, 'msg' => "User u/$t_name has been muted."]);
            exit;
        }

        if ($sub_action === 'unmute') {
            mysqli_query($conn, "UPDATE users SET is_muted = 0 WHERE id=$target_id");
            echo json_encode(['ok' => true, 'msg' => "User u/$t_name unmuted."]);
            exit;
        }

        if ($sub_action === 'reset_password') {
            $new_pw = isset($_REQUEST['new_password']) ? trim($_REQUEST['new_password']) : '';
            if (strlen($new_pw) < 4) {
                echo json_encode(['ok' => false, 'error' => 'Password must be at least 4 characters.']);
                exit;
            }
            $phash = password_hash($new_pw, PASSWORD_DEFAULT);
            $phash_safe = mysqli_real_escape_string($conn, $phash);
            mysqli_query($conn, "UPDATE users SET password_hash='$phash_safe' WHERE id=$target_id");
            echo json_encode(['ok' => true, 'msg' => "Password for u/$t_name reset successfully."]);
            exit;
        }

        if ($sub_action === 'reset_avatar') {
            mysqli_query($conn, "UPDATE users SET avatar_data='' WHERE id=$target_id");
            echo json_encode(['ok' => true, 'msg' => "Avatar for u/$t_name reset to default initials."]);
            exit;
        }

        if ($sub_action === 'purge_user') {
            mysqli_query($conn, "UPDATE posts SET is_deleted=1 WHERE user_id=$target_id");
            mysqli_query($conn, "UPDATE comments SET is_deleted=1 WHERE user_id=$target_id");
            echo json_encode(['ok' => true, 'msg' => "All posts and comments by u/$t_name purged."]);
            exit;
        }

        if ($sub_action === 'delete_user' && $is_admin) {
            mysqli_query($conn, "DELETE FROM users WHERE id=$target_id");
            mysqli_query($conn, "UPDATE posts SET is_deleted=1 WHERE user_id=$target_id");
            mysqli_query($conn, "UPDATE comments SET is_deleted=1 WHERE user_id=$target_id");
            echo json_encode(['ok' => true, 'msg' => "User account u/$t_name deleted."]);
            exit;
        }
    }

    if ($api_act === 'purge_user_id' && $is_staff) {
        $uid = isset($_REQUEST['user_id']) ? intval($_REQUEST['user_id']) : 0;
        if ($uid > 0) {
            mysqli_query($conn, "UPDATE posts SET is_deleted=1 WHERE user_id=$uid");
            mysqli_query($conn, "UPDATE comments SET is_deleted=1 WHERE user_id=$uid");
        }
        echo json_encode(['ok' => true, 'msg' => "Purged user messages and posts."]);
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
        $settings_raw = isset($_REQUEST['settings']) ? $_REQUEST['settings'] : '{}';
        $s_safe = mysqli_real_escape_string($conn, is_string($settings_raw) ? $settings_raw : json_encode($settings_raw));
        mysqli_query($conn, "UPDATE system_config SET site_settings='$s_safe' WHERE id=1");
        echo json_encode(['ok' => true]);
        exit;
    }

    if ($api_act === 'get_sessions') {
        $res = mysqli_query($conn, "SELECT id, username, ip_address, role, custom_badge, last_seen, created_at FROM users ORDER BY id DESC LIMIT 50");
        $sessions = [];
        while ($row = mysqli_fetch_assoc($res)) {
            $sessions[] = $row;
        }
        echo json_encode(['ok' => true, 'sessions' => $sessions]);
        exit;
    }

    if ($api_act === 'get_feedbacks') {
        $res = mysqli_query($conn, "SELECT * FROM feedbacks ORDER BY id DESC LIMIT 50");
        $feedbacks = [];
        if ($res) {
            while ($row = mysqli_fetch_assoc($res)) {
                $feedbacks[] = $row;
            }
        }
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
        $tpl = isset($_REQUEST['template']) ? trim($_REQUEST['template']) : '';
        $t_safe = mysqli_real_escape_string($conn, $tpl);
        mysqli_query($conn, "UPDATE system_config SET ban_templates='$t_safe' WHERE id=1");
        echo json_encode(['ok' => true]);
        exit;
    }

    if ($api_act === 'start_nitro_challenge' && $is_owner) {
        $word = isset($_REQUEST['secret_word']) ? trim($_REQUEST['secret_word']) : '';
        $w_safe = mysqli_real_escape_string($conn, $word);
        mysqli_query($conn, "UPDATE system_config SET nitro_word='$w_safe' WHERE id=1");
        echo json_encode(['ok' => true, 'msg' => "Nitro Challenge started! Secret word saved."]);
        exit;
    }

    if ($api_act === 'get_roles') {
        $res = mysqli_query($conn, "SELECT * FROM roles ORDER BY id ASC");
        $roles = [];
        if ($res) {
            while ($row = mysqli_fetch_assoc($res)) {
                $roles[] = $row;
            }
        }
        echo json_encode(['ok' => true, 'roles' => $roles]);
        exit;
    }

    if ($api_act === 'create_role' && $is_owner) {
        $name = isset($_REQUEST['name']) ? trim($_REQUEST['name']) : '';
        $color = isset($_REQUEST['color']) ? trim($_REQUEST['color']) : '#38bdf8';
        $perms = isset($_REQUEST['permissions']) ? (is_array($_REQUEST['permissions']) ? json_encode($_REQUEST['permissions']) : trim($_REQUEST['permissions'])) : '[]';
        if (!empty($name)) {
            $n_safe = mysqli_real_escape_string($conn, $name);
            $c_safe = mysqli_real_escape_string($conn, $color);
            $p_safe = mysqli_real_escape_string($conn, $perms);
            mysqli_query($conn, "INSERT INTO roles (name, color, permissions) VALUES ('$n_safe', '$c_safe', '$p_safe')");
        }
        echo json_encode(['ok' => true]);
        exit;
    }

    if ($api_act === 'delete_role' && $is_owner) {
        $rid = isset($_REQUEST['role_id']) ? intval($_REQUEST['role_id']) : 0;
        if ($rid > 0) {
            mysqli_query($conn, "DELETE FROM roles WHERE id=$rid");
        }
        echo json_encode(['ok' => true]);
        exit;
    }

    if ($api_act === 'set_avatar_overlay' && $is_owner) {
        $target_id = isset($_REQUEST['target_user_id']) ? intval($_REQUEST['target_user_id']) : 0;
        $ov_json = isset($_REQUEST['overlay']) ? $_REQUEST['overlay'] : '';
        $ov_safe = mysqli_real_escape_string($conn, is_string($ov_json) ? $ov_json : json_encode($ov_json));
        mysqli_query($conn, "UPDATE users SET avatar_overlay='$ov_safe' WHERE id=$target_id");
        echo json_encode(['ok' => true]);
        exit;
    }

    echo json_encode(['ok' => false, 'error' => 'Unknown action.']);
    exit;
}

if (isset($_REQUEST['live_sync'])) {
    header('Content-Type: application/json');
    $is_banned = false;
    $ban_reason = '';
    
    // Check ban status in real time
    if ($curr_user['role'] !== 'OWNER') {
        $bc = mysqli_query($conn, "SELECT id, reason FROM moderation_actions WHERE target_username='{$curr_user['username']}' AND action_type='BAN' AND status='APPROVED' LIMIT 1");
        if ($bc && mysqli_num_rows($bc) > 0) {
            $is_banned = true;
            $brow = mysqli_fetch_assoc($bc);
            $ban_reason = $brow['reason'];
        }
    }

    // Refresh user state in real time
    $u_refresh = mysqli_query($conn, "SELECT id, username, role, is_admin, is_mod, custom_badge, avatar_data FROM users WHERE id=" . intval($curr_user['id']));
    $u_fresh = $u_refresh ? mysqli_fetch_assoc($u_refresh) : $curr_user;
    $k_fresh = get_user_karma_details($curr_user['id'], $conn);

    // Refresh system state (maintenance, announcement, hit counter)
    $sys_res = mysqli_query($conn, "SELECT maintenance, maintenance_msg, announcement_banner, hit_counter FROM system_config WHERE id=1");
    $sys_row = mysqli_fetch_assoc($sys_res);
    $live_maint_active = $sys_row && intval($sys_row['maintenance']) === 1;
    $live_maint_msg = ($sys_row && !empty($sys_row['maintenance_msg'])) ? $sys_row['maintenance_msg'] : 'BetterForums is currently undergoing scheduled maintenance. Please check back shortly.';
    $live_announcement = $sys_row ? $sys_row['announcement_banner'] : '';
    $live_hits = $sys_row ? intval($sys_row['hit_counter']) : $hit_counter_val;

    $response = [
        'ok' => true,
        'banned' => $is_banned,
        'ban_reason' => $ban_reason,
        'maintenance' => ($live_maint_active && !$is_admin),
        'maintenance_msg' => $live_maint_msg,
        'announcement' => $live_announcement,
        'motd' => get_active_motd($conn),
        'hit_counter' => $live_hits,
        'user' => [
            'username' => $u_fresh['username'],
            'role' => $u_fresh['role'],
            'badge' => $u_fresh['custom_badge'],
            'karma' => $k_fresh['total'],
            'badge_html' => render_role_tag($u_fresh)
        ]
    ];

    // If on a specific post page, return latest comment stream
    $check_post_id = isset($_REQUEST['post_id']) ? intval($_REQUEST['post_id']) : 0;
    if ($check_post_id > 0) {
        $last_cid = isset($_REQUEST['last_comment_id']) ? intval($_REQUEST['last_comment_id']) : 0;
        $new_comm_q = mysqli_query($conn, "SELECT c.*, u.username, u.custom_badge, u.avatar_data, u.role, u.is_admin, u.is_mod FROM comments c JOIN users u ON c.user_id=u.id WHERE c.post_id=$check_post_id AND c.id > $last_cid AND c.is_deleted=0 ORDER BY c.id ASC");
        $new_comments = [];
        if ($new_comm_q) {
            while ($nc = mysqli_fetch_assoc($new_comm_q)) {
                $nc['score'] = get_target_score('comment', $nc['id'], $conn);
                $nc['time_str'] = time_ago_str($nc['created_at']);
                $nc['parsed_content'] = parse_custom_markdown($nc['content']);
                $nc['content_html'] = $nc['parsed_content'];
                $nc['avatar_html'] = render_avatar_img($nc, 14);
                $nc['role_tag'] = render_role_tag($nc);
                $new_comments[] = $nc;
            }
        }
        $p_score = get_target_score('post', $check_post_id, $conn);
        $t_c_q = mysqli_query($conn, "SELECT COUNT(*) as c FROM comments WHERE post_id=$check_post_id AND is_deleted=0");
        $total_comms = ($t_c_r = mysqli_fetch_assoc($t_c_q)) ? intval($t_c_r['c']) : 0;
        $response['post'] = [
            'id' => $check_post_id,
            'score' => $p_score,
            'comment_count' => $total_comms,
            'new_comments' => $new_comments
        ];
    }

    echo json_encode($response);
    exit;
}

function get_user_karma_details($uid, $c) {
    $uid = intval($uid);
    $q_posts = mysqli_query($c, "SELECT COUNT(*) as c FROM posts WHERE user_id=$uid AND is_deleted=0");
    $posts_cnt = ($r = mysqli_fetch_assoc($q_posts)) ? intval($r['c']) : 0;
    
    $q_comments = mysqli_query($c, "SELECT COUNT(*) as c FROM comments WHERE user_id=$uid AND is_deleted=0");
    $comments_cnt = ($r = mysqli_fetch_assoc($q_comments)) ? intval($r['c']) : 0;
    
    $q_up_posts = mysqli_query($c, "SELECT COUNT(*) as c FROM user_votes v JOIN posts p ON v.target_id=p.id AND v.target_type='post' WHERE p.user_id=$uid AND p.is_deleted=0 AND v.vote_type=1");
    $up_posts = ($r = mysqli_fetch_assoc($q_up_posts)) ? intval($r['c']) : 0;
    
    $q_dn_posts = mysqli_query($c, "SELECT COUNT(*) as c FROM user_votes v JOIN posts p ON v.target_id=p.id AND v.target_type='post' WHERE p.user_id=$uid AND p.is_deleted=0 AND v.vote_type=-1");
    $dn_posts = ($r = mysqli_fetch_assoc($q_dn_posts)) ? intval($r['c']) : 0;
    
    $q_up_comm = mysqli_query($c, "SELECT COUNT(*) as c FROM user_votes v JOIN comments cm ON v.target_id=cm.id AND v.target_type='comment' WHERE cm.user_id=$uid AND cm.is_deleted=0 AND v.vote_type=1");
    $up_comm = ($r = mysqli_fetch_assoc($q_up_comm)) ? intval($r['c']) : 0;
    
    $q_dn_comm = mysqli_query($c, "SELECT COUNT(*) as c FROM user_votes v JOIN comments cm ON v.target_id=cm.id AND v.target_type='comment' WHERE cm.user_id=$uid AND cm.is_deleted=0 AND v.vote_type=-1");
    $dn_comm = ($r = mysqli_fetch_assoc($q_dn_comm)) ? intval($r['c']) : 0;
    
    $post_karma = max(1, 1 + $up_posts - $dn_posts);
    $comment_karma = max(1, 1 + $up_comm - $dn_comm);
    $total = $post_karma + $comment_karma;
    return [
        'total' => $total,
        'posts_cnt' => $posts_cnt,
        'comments_cnt' => $comments_cnt,
        'post_karma' => $post_karma,
        'comment_karma' => $comment_karma
    ];
}

function get_target_score($type, $id, $c) {
    $id = intval($id);
    $type = mysqli_real_escape_string($c, $type);
    $q = mysqli_query($c, "SELECT SUM(vote_type) as s FROM user_votes WHERE target_type='$type' AND target_id=$id");
    $r = mysqli_fetch_assoc($q);
    return ($r && $r['s'] !== null) ? intval($r['s']) : 0;
}

function get_active_motd($c) {
    $res = mysqli_query($c, "SELECT id, message_text, weight_percent FROM motd_pool ORDER BY id ASC");
    if (!$res || mysqli_num_rows($res) === 0) {
        return "Welcome to BetterForums - The Front Page of the Web!";
    }
    $motds = [];
    $total_weight = 0.0;
    while ($row = mysqli_fetch_assoc($res)) {
        $w = floatval($row['weight_percent']);
        if ($w <= 0) $w = 1.0;
        $total_weight += $w;
        $motds[] = [
            'id' => $row['id'],
            'text' => $row['message_text'],
            'acc_weight' => $total_weight
        ];
    }
    if ($total_weight <= 0) {
        return $motds[0]['text'];
    }
    $rand = (mt_rand() / mt_getrandmax()) * $total_weight;
    foreach ($motds as $m) {
        if ($rand <= $m['acc_weight']) {
            return $m['text'];
        }
    }
    return $motds[count($motds) - 1]['text'];
}

function render_avatar_img($user_row, $size = 28) {
    $size = intval($size);
    $avatar_data = isset($user_row['avatar_data']) ? trim($user_row['avatar_data']) : '';
    $raw_username = isset($user_row['username']) && !empty($user_row['username']) ? $user_row['username'] : 'user';
    $u_name = htmlspecialchars($raw_username, ENT_QUOTES, 'UTF-8');
    
    if (!empty($avatar_data)) {
        $safe_src = htmlspecialchars($avatar_data, ENT_QUOTES, 'UTF-8');
    } else {
        $seed = urlencode($raw_username);
        $safe_src = "https://api.dicebear.com/10.x/initials/svg?seed={$seed}&chars=2&textColor=ffffff";
    }
    return "<img src='{$safe_src}' alt='{$u_name}' class='user-avatar-circle' style='width:{$size}px; height:{$size}px; object-fit:cover; border-radius:50%; border:1px solid #334155; vertical-align:middle; display:inline-block; margin-right:5px; background:#0f172a;'>";
}

function render_role_tag($user_data) {
    if (!$user_data) return '';
    $username = is_array($user_data) ? (isset($user_data['username']) ? strtolower($user_data['username']) : '') : strtolower((string)$user_data);
    $role = is_array($user_data) && isset($user_data['role']) ? strtoupper($user_data['role']) : '';
    $badge = is_array($user_data) && isset($user_data['custom_badge']) ? trim($user_data['custom_badge']) : '';
    $is_admin = is_array($user_data) && !empty($user_data['is_admin']);
    $is_mod = is_array($user_data) && !empty($user_data['is_mod']);

    // Owner tag: Yellow tag with crown icon (Old BetterChat style)
    if ($username === 'gollclock' || $role === 'OWNER' || strtolower($badge) === 'owner') {
        return '<span class="role-badge role-badge-owner" style="background:rgba(234,179,8,0.2) !important; color:#fbbf24 !important; border:1px solid rgba(234,179,8,0.5) !important; font-size:10px !important; font-weight:700 !important; border-radius:4px !important; padding:1px 5px !important; margin-left:4px !important; display:inline-flex !important; align-items:center !important; gap:3px !important; text-shadow:0 0 8px rgba(250,204,21,0.4);"><i class="fa-solid fa-crown" style="font-size:9px;"></i> OWNER</span>';
    }

    // Admin tag: Red tag with shield icon (Old BetterChat style)
    if ($role === 'ADMIN' || $is_admin || strtolower($badge) === 'admin') {
        return '<span class="role-badge role-badge-admin" style="background:rgba(239,68,68,0.2) !important; color:#f87171 !important; border:1px solid rgba(239,68,68,0.5) !important; font-size:10px !important; font-weight:700 !important; border-radius:4px !important; padding:1px 5px !important; margin-left:4px !important; display:inline-flex !important; align-items:center !important; gap:3px !important; text-shadow:0 0 8px rgba(248,113,113,0.4);"><i class="fa-solid fa-shield-halved" style="font-size:9px;"></i> ADMIN</span>';
    }

    // Mod tag: Green tag with gavel icon
    if ($role === 'MOD' || $is_mod || strtolower($badge) === 'moderator' || strtolower($badge) === 'mod') {
        return '<span class="role-badge role-badge-mod" style="background:rgba(16,185,129,0.2) !important; color:#34d399 !important; border:1px solid rgba(16,185,129,0.5) !important; font-size:10px !important; font-weight:700 !important; border-radius:4px !important; padding:1px 5px !important; margin-left:4px !important; display:inline-flex !important; align-items:center !important; gap:3px !important;"><i class="fa-solid fa-gavel" style="font-size:9px;"></i> MOD</span>';
    }

    // Custom assigned badge/flair
    if (!empty($badge)) {
        return '<span class="role-badge" style="background:rgba(148,163,184,0.15) !important; color:#cbd5e1 !important; border:1px solid rgba(148,163,184,0.3) !important; font-size:10px !important; font-weight:600 !important; border-radius:4px !important; padding:1px 5px !important; margin-left:4px !important; display:inline-flex !important; align-items:center !important;">' . htmlspecialchars($badge, ENT_QUOTES, 'UTF-8') . '</span>';
    }

    return '';
}

function parse_custom_markdown($raw) {
    $text = htmlspecialchars($raw, ENT_QUOTES, 'UTF-8');
    
    $text = preg_replace('/\[2x\](.*?)\[\/2x\]/s', '<span style="font-size:2em; font-weight:bold; line-height:1.25; display:inline-block;">$1</span>', $text);
    $text = preg_replace('/\+\+(.*?)\+\+/s', '<span style="font-size:2em; font-weight:bold; line-height:1.25; display:inline-block;">$1</span>', $text);
    $text = preg_replace('/^#\s+(.*?)$/m', '<span style="font-size:2em; font-weight:bold; line-height:1.25; display:block; margin:4px 0;">$1</span>', $text);
    $text = preg_replace('/^##\s+(.*?)$/m', '<span style="font-size:1.5em; font-weight:bold; line-height:1.25; display:block; margin:4px 0;">$1</span>', $text);
    
    $text = preg_replace('/!\[(.*?)\]\((https?:\/\/[^\s\)\"\']+|data:image\/[a-zA-Z0-9\+\-\.]+;base64,[^\s\)\"\']+|\/\/[^\s\)\"\']+)\)/i', '<div style="margin:8px 0;"><img src="$2" alt="$1" referrerpolicy="no-referrer" loading="lazy" style="max-width:100%; max-height:420px; border-radius:6px; border:1px solid #334155; display:block;" onerror="this.parentElement.style.display=\'none\'"></div>', $text);
    $text = preg_replace('/!\[(.*?)\]\([^\)]*\)/i', '', $text);
    $text = preg_replace('/!\[(.*?)\]/i', '', $text);
    $text = preg_replace('/\[(.*?)\]\((https?:\/\/[^\s\)\"\']+)\)/i', '<a href="$2" target="_blank" rel="noopener" style="color:#38bdf8; text-decoration:underline;">$1</a>', $text);
    $text = preg_replace('/\[(.*?)\]\([^\)]*\)/i', '$1', $text);
    $text = preg_replace('/\*\*(.*?)\*\*/s', '<strong>$1</strong>', $text);
    $text = preg_replace('/\*([^\*]+)\*/s', '<em>$1</em>', $text);
    $text = preg_replace('/~~(.*?)~~/s', '<del>$1</del>', $text);
    $text = preg_replace('/`([^`]+)`/', '<code style="background:#0f172a; color:#38bdf8; padding:2px 6px; font-family:monospace; font-size:11px; border:1px solid #334155; border-radius:4px;">$1</code>', $text);
    $text = preg_replace('/^&gt;\s?(.*?)$/m', '<blockquote style="border-left:3px solid #3b82f6; margin:6px 0; padding:4px 10px; color:#cbd5e1; background:rgba(59,130,246,0.1); border-radius:0 4px 4px 0;">$1</blockquote>', $text);
    return nl2br($text);
}

function time_ago_str($timestamp) {
    $diff = time() - strtotime($timestamp);
    if ($diff < 60) return 'just now';
    if ($diff < 3600) return floor($diff / 60) . ' minutes ago';
    if ($diff < 86400) return floor($diff / 3600) . ' hours ago';
    if ($diff < 2592000) return floor($diff / 86400) . ' days ago';
    return date('M j, Y', strtotime($timestamp));
}

$user_karma_info = get_user_karma_details($curr_user['id'], $conn);
$user_karma = $user_karma_info['total'];

$action = isset($_GET['action']) ? $_GET['action'] : (isset($_POST['action']) ? $_POST['action'] : '');
$flash_msg = '';
$flash_err = '';

if ($action === 'logout') {
    setcookie('BF_AUTH_SAFE', '', time() - 3600, '/');
    header("Location: login.php");
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if ($action === 'vote') {
        $v_type = isset($_POST['type']) ? trim($_POST['type']) : '';
        $v_id = isset($_POST['id']) ? intval($_POST['id']) : 0;
        $v_val = (isset($_POST['v']) && intval($_POST['v']) === -1) ? -1 : 1;
        $redirect = isset($_POST['redirect']) ? $_POST['redirect'] : 'index.php';
        
        if (in_array($v_type, ['post', 'comment']) && $v_id > 0) {
            $u_id = intval($curr_user['id']);
            $vt_safe = mysqli_real_escape_string($conn, $v_type);
            $chk = mysqli_query($conn, "SELECT id, vote_type FROM user_votes WHERE user_id=$u_id AND target_type='$vt_safe' AND target_id=$v_id");
            if (mysqli_num_rows($chk) > 0) {
                $row = mysqli_fetch_assoc($chk);
                if (intval($row['vote_type']) === $v_val) {
                    mysqli_query($conn, "DELETE FROM user_votes WHERE id=" . intval($row['id']));
                } else {
                    mysqli_query($conn, "UPDATE user_votes SET vote_type=$v_val WHERE id=" . intval($row['id']));
                }
            } else {
                mysqli_query($conn, "INSERT INTO user_votes (user_id, target_type, target_id, vote_type) VALUES ($u_id, '$vt_safe', $v_id, $v_val)");
            }
        }
        header("Location: " . $redirect);
        exit;
    }

    if ($action === 'save_post') {
        $post_id = isset($_POST['post_id']) ? intval($_POST['post_id']) : 0;
        $redirect = isset($_POST['redirect']) ? $_POST['redirect'] : 'index.php';
        if ($post_id > 0) {
            $u_id = intval($curr_user['id']);
            $chk = mysqli_query($conn, "SELECT id FROM saved_posts WHERE user_id=$u_id AND post_id=$post_id");
            if (mysqli_num_rows($chk) > 0) {
                mysqli_query($conn, "DELETE FROM saved_posts WHERE user_id=$u_id AND post_id=$post_id");
            } else {
                mysqli_query($conn, "INSERT INTO saved_posts (user_id, post_id) VALUES ($u_id, $post_id)");
            }
        }
        header("Location: " . $redirect);
        exit;
    }

    if ($action === 'toggle_sub') {
        $sub_id = isset($_POST['sub_id']) ? intval($_POST['sub_id']) : 0;
        $redirect = isset($_POST['redirect']) ? $_POST['redirect'] : 'index.php';
        if ($sub_id > 0) {
            $u_id = intval($curr_user['id']);
            $chk = mysqli_query($conn, "SELECT id FROM subscriptions WHERE user_id=$u_id AND subbetter_id=$sub_id");
            if (mysqli_num_rows($chk) > 0) {
                mysqli_query($conn, "DELETE FROM subscriptions WHERE user_id=$u_id AND subbetter_id=$sub_id");
            } else {
                mysqli_query($conn, "INSERT INTO subscriptions (user_id, subbetter_id) VALUES ($u_id, $sub_id)");
            }
        }
        header("Location: " . $redirect);
        exit;
    }

    if ($action === 'new_post') {
        $sub_id = isset($_POST['subbetter_id']) ? intval($_POST['subbetter_id']) : 0;
        $title = isset($_POST['title']) ? trim($_POST['title']) : '';
        $content = isset($_POST['content']) ? trim($_POST['content']) : '';
        $flair = isset($_POST['flair']) ? trim($_POST['flair']) : '';
        $link_url = isset($_POST['link_url']) ? trim($_POST['link_url']) : '';
        $img_attached = isset($_POST['image_url']) ? trim($_POST['image_url']) : '';
        
        if (isset($_FILES['image_file']) && $_FILES['image_file']['error'] === UPLOAD_ERR_OK) {
            $tmp_path = $_FILES['image_file']['tmp_name'];
            $mime = mime_content_type($tmp_path);
            if (strpos($mime, 'image/') === 0) {
                $raw_data = file_get_contents($tmp_path);
                if (strlen($raw_data) <= 3145728) {
                    $img_attached = 'data:' . $mime . ';base64,' . base64_encode($raw_data);
                }
            }
        }

        $t_len = mb_strlen($title);
        $is_sub_muted = false;
        $is_sub_locked = false;
        if ($sub_id > 0) {
            $sb_info = mysqli_query($conn, "SELECT is_locked FROM subbetters WHERE id=$sub_id");
            if ($sbr = mysqli_fetch_assoc($sb_info)) {
                if (intval($sbr['is_locked']) === 1 && !$is_staff) {
                    $is_sub_locked = true;
                }
            }
            if (!$is_owner) {
                $u_chk = mysqli_real_escape_string($conn, $curr_user['username']);
                $mq = mysqli_query($conn, "SELECT id FROM moderation_actions WHERE target_username='$u_chk' AND (subbetter_id=$sub_id OR subbetter_id IS NULL) AND action_type IN ('MUTE','SUB_BAN') AND status='APPROVED'");
                if ($mq && mysqli_num_rows($mq) > 0) $is_sub_muted = true;
            }
        }

        if ($is_sub_locked) {
            $flash_err = 'This community is locked by moderators.';
        } elseif ($is_sub_muted) {
            $flash_err = 'You are currently muted from posting in this community.';
        } elseif ($t_len < 3 || $t_len > 250) {
            $flash_err = 'Post title length must be between 3 and 250 characters.';
        } else {
            $t_safe = mysqli_real_escape_string($conn, $title);
            $c_safe = mysqli_real_escape_string($conn, $content);
            $img_safe = mysqli_real_escape_string($conn, $img_attached);
            $flair_safe = mysqli_real_escape_string($conn, $flair);
            $link_safe = mysqli_real_escape_string($conn, $link_url);
            $u_id = intval($curr_user['id']);
            $ip_safe = mysqli_real_escape_string($conn, $remote_ip);
            
            $ins = mysqli_query($conn, "INSERT INTO posts (subbetter_id, user_id, title, content, image_url, flair, link_url, ip_address, is_deleted) VALUES ($sub_id, $u_id, '$t_safe', '$c_safe', '$img_safe', '$flair_safe', '$link_safe', '$ip_safe', 0)");
            if ($ins) {
                $pid = mysqli_insert_id($conn);
                mysqli_query($conn, "INSERT INTO user_votes (user_id, target_type, target_id, vote_type) VALUES ($u_id, 'post', $pid, 1)");
                header("Location: index.php?post=$pid");
                exit;
            } else {
                $flash_err = 'Error creating post: ' . mysqli_error($conn);
            }
        }
    }

    if ($action === 'new_comment') {
        $post_id = isset($_POST['post_id']) ? intval($_POST['post_id']) : 0;
        $parent_id = (isset($_POST['parent_id']) && intval($_POST['parent_id']) > 0) ? intval($_POST['parent_id']) : "NULL";
        $content = isset($_POST['content']) ? trim($_POST['content']) : '';
        $redirect = isset($_POST['redirect']) ? $_POST['redirect'] : ("index.php?post=" . $post_id);
        $c_len = mb_strlen($content);

        $p_info = mysqli_query($conn, "SELECT subbetter_id, is_locked FROM posts WHERE id=$post_id");
        $p_row = mysqli_fetch_assoc($p_info);
        $sub_id = $p_row ? intval($p_row['subbetter_id']) : 0;
        $p_locked = $p_row ? (intval($p_row['is_locked']) === 1) : false;

        $is_sub_muted = false;
        if (!$is_owner && $sub_id > 0) {
            $u_chk = mysqli_real_escape_string($conn, $curr_user['username']);
            $mq = mysqli_query($conn, "SELECT id FROM moderation_actions WHERE target_username='$u_chk' AND (subbetter_id=$sub_id OR subbetter_id IS NULL) AND action_type IN ('MUTE','SUB_BAN') AND status='APPROVED'");
            if ($mq && mysqli_num_rows($mq) > 0) $is_sub_muted = true;
        }

        if ($p_locked && !$is_staff) {
            $flash_err = 'This thread has been locked. New comments are disabled.';
        } elseif ($is_sub_muted) {
            $flash_err = 'You are currently muted from commenting in this community.';
        } elseif ($c_len < 1 || $c_len > 2000) {
            $flash_err = 'Comment content must be between 1 and 2000 characters.';
        } else {
            $c_safe = mysqli_real_escape_string($conn, $content);
            $u_id = intval($curr_user['id']);
            $ip_safe = mysqli_real_escape_string($conn, $remote_ip);
            mysqli_query($conn, "INSERT INTO comments (post_id, parent_id, user_id, content, ip_address, is_deleted) VALUES ($post_id, $parent_id, $u_id, '$c_safe', '$ip_safe', 0)");
            $new_cid = mysqli_insert_id($conn);
            mysqli_query($conn, "INSERT INTO user_votes (user_id, target_type, target_id, vote_type) VALUES ($u_id, 'comment', $new_cid, 1)");
            header("Location: " . $redirect);
            exit;
        }
    }

    if ($action === 'create_community') {
        $name = isset($_POST['name']) ? trim(strtolower($_POST['name'])) : '';
        $desc = isset($_POST['description']) ? trim($_POST['description']) : '';
        $name = preg_replace('/[^a-z0-9_]/', '', $name);
        if (strlen($name) < 2 || strlen($name) > 30) {
            $flash_err = 'Community name must be 2 to 30 alphanumeric characters.';
        } else {
            $n_safe = mysqli_real_escape_string($conn, $name);
            $d_safe = mysqli_real_escape_string($conn, $desc);
            $by_safe = mysqli_real_escape_string($conn, $curr_user['username']);
            $chk = mysqli_query($conn, "SELECT id FROM subbetters WHERE name='$n_safe'");
            if (mysqli_num_rows($chk) > 0) {
                $flash_err = 'A community with that name already exists.';
            } else {
                $ins = mysqli_query($conn, "INSERT INTO subbetters (name, description, created_by) VALUES ('$n_safe', '$d_safe', '$by_safe')");
                if ($ins) {
                    $new_sub_id = mysqli_insert_id($conn);
                    mysqli_query($conn, "INSERT INTO subscriptions (user_id, subbetter_id) VALUES ({$curr_user['id']}, $new_sub_id)");
                    header("Location: index.php?b=" . urlencode($name));
                    exit;
                } else {
                    $flash_err = 'Database error: ' . mysqli_error($conn);
                }
            }
        }
    }

    if ($action === 'update_profile') {
        $display_name = isset($_POST['display_name']) ? trim($_POST['display_name']) : '';
        $bio = isset($_POST['bio']) ? trim($_POST['bio']) : '';
        $status_flair = isset($_POST['status_flair']) ? trim($_POST['status_flair']) : '';
        $avatar_url = isset($_POST['avatar_url']) ? trim($_POST['avatar_url']) : '';
        $theme = (isset($_POST['theme']) && $_POST['theme'] === 'night') ? 'night' : 'light';
        $hide_search = (isset($_POST['hide_from_search']) && intval($_POST['hide_from_search']) === 1) ? 1 : 0;
        
        $final_avatar = $avatar_url;
        if (isset($_FILES['avatar_file']) && $_FILES['avatar_file']['error'] === UPLOAD_ERR_OK) {
            $tmp_path = $_FILES['avatar_file']['tmp_name'];
            $mime = mime_content_type($tmp_path);
            if (strpos($mime, 'image/') === 0) {
                $raw_data = file_get_contents($tmp_path);
                if (strlen($raw_data) <= 1572864) {
                    $final_avatar = 'data:' . $mime . ';base64,' . base64_encode($raw_data);
                }
            }
        }

        $dn_safe = mysqli_real_escape_string($conn, $display_name);
        $bio_safe = mysqli_real_escape_string($conn, $bio);
        $flair_safe = mysqli_real_escape_string($conn, $status_flair);
        $av_safe = mysqli_real_escape_string($conn, $final_avatar);
        $th_safe = mysqli_real_escape_string($conn, $theme);
        $u_id = intval($curr_user['id']);

        $upd = mysqli_query($conn, "UPDATE users SET display_name='$dn_safe', bio='$bio_safe', status_flair='$flair_safe', avatar_data='$av_safe', theme='$th_safe', hide_from_search=$hide_search WHERE id=$u_id");
        if ($upd) {
            $curr_user['display_name'] = $display_name;
            $curr_user['bio'] = $bio;
            $curr_user['status_flair'] = $status_flair;
            $curr_user['avatar_data'] = $final_avatar;
            $curr_user['theme'] = $theme;
            $curr_user['hide_from_search'] = $hide_search;
            $flash_msg = 'Profile settings updated successfully.';
        } else {
            $flash_err = 'Failed to update profile: ' . mysqli_error($conn);
        }
    }

    if ($action === 'report') {
        $target_user = isset($_POST['target_user']) ? trim($_POST['target_user']) : '';
        $reason = isset($_POST['reason']) ? trim($_POST['reason']) : '';
        $sub_id = isset($_POST['sub_id']) ? intval($_POST['sub_id']) : "NULL";
        if (!empty($target_user) && !empty($reason)) {
            $tu_safe = mysqli_real_escape_string($conn, $target_user);
            $r_safe = mysqli_real_escape_string($conn, $reason);
            $by_safe = mysqli_real_escape_string($conn, $curr_user['username']);
            mysqli_query($conn, "INSERT INTO moderation_actions (action_type, target_username, subbetter_id, reason, status, reporter_username) VALUES ('REPORT', '$tu_safe', $sub_id, '$r_safe', 'PENDING', '$by_safe')");
            $flash_msg = 'Thank you. Your report has been submitted to moderators.';
        }
    }

    if ($is_staff) {
        if ($action === 'pin_post') {
            $pid = isset($_POST['post_id']) ? intval($_POST['post_id']) : 0;
            $pin_val = (isset($_POST['val']) && intval($_POST['val']) === 1) ? 1 : 0;
            mysqli_query($conn, "UPDATE posts SET is_pinned=$pin_val WHERE id=$pid");
            header("Location: " . (isset($_POST['redirect']) ? $_POST['redirect'] : 'index.php'));
            exit;
        }

        if ($action === 'lock_post') {
            $pid = isset($_POST['post_id']) ? intval($_POST['post_id']) : 0;
            $lock_val = (isset($_POST['val']) && intval($_POST['val']) === 1) ? 1 : 0;
            mysqli_query($conn, "UPDATE posts SET is_locked=$lock_val WHERE id=$pid");
            header("Location: " . (isset($_POST['redirect']) ? $_POST['redirect'] : 'index.php'));
            exit;
        }

        if ($action === 'delete_post') {
            $pid = isset($_POST['post_id']) ? intval($_POST['post_id']) : 0;
            mysqli_query($conn, "UPDATE posts SET is_deleted=1 WHERE id=$pid");
            header("Location: index.php");
            exit;
        }

        if ($action === 'delete_comment') {
            $cid = isset($_POST['comment_id']) ? intval($_POST['comment_id']) : 0;
            mysqli_query($conn, "UPDATE comments SET is_deleted=1 WHERE id=$cid");
            header("Location: " . (isset($_POST['redirect']) ? $_POST['redirect'] : 'index.php'));
            exit;
        }

        if ($action === 'mod_decision') {
            $mod_id = isset($_POST['mod_id']) ? intval($_POST['mod_id']) : 0;
            $decision = (isset($_POST['decision']) && $_POST['decision'] === 'APPROVED') ? 'APPROVED' : 'DISMISSED';
            $by_safe = mysqli_real_escape_string($conn, $curr_user['username']);
            mysqli_query($conn, "UPDATE moderation_actions SET status='$decision', reviewed_by='$by_safe' WHERE id=$mod_id");
            $flash_msg = 'Moderation action ' . strtolower($decision) . '.';
        }

        if ($action === 'ban_user') {
            $target = isset($_POST['target_user']) ? trim($_POST['target_user']) : '';
            $reason = isset($_POST['reason']) ? trim($_POST['reason']) : 'Rule violation';
            if (!empty($target) && strtolower($target) !== strtolower($curr_user['username'])) {
                $t_safe = mysqli_real_escape_string($conn, $target);
                $r_safe = mysqli_real_escape_string($conn, $reason);
                $by_safe = mysqli_real_escape_string($conn, $curr_user['username']);
                mysqli_query($conn, "INSERT INTO moderation_actions (action_type, target_username, reason, status, reviewed_by) VALUES ('BAN', '$t_safe', '$r_safe', 'APPROVED', '$by_safe')");
                $flash_msg = 'User u/' . htmlspecialchars($target, ENT_QUOTES, 'UTF-8') . ' has been banned.';
            }
        }

        if ($action === 'unban_user') {
            $target = isset($_POST['target_user']) ? trim($_POST['target_user']) : '';
            if (!empty($target)) {
                $t_safe = mysqli_real_escape_string($conn, $target);
                $by_safe = mysqli_real_escape_string($conn, $curr_user['username']);
                mysqli_query($conn, "UPDATE moderation_actions SET status='DISMISSED', reviewed_by='$by_safe' WHERE target_username='$t_safe' AND action_type='BAN'");
                $flash_msg = 'User u/' . htmlspecialchars($target, ENT_QUOTES, 'UTF-8') . ' has been unbanned.';
            }
        }

        if ($action === 'set_custom_badge') {
            $target = isset($_POST['target_user']) ? trim($_POST['target_user']) : '';
            $badge = isset($_POST['badge']) ? trim($_POST['badge']) : '';
            if (!empty($target)) {
                $t_safe = mysqli_real_escape_string($conn, $target);
                $b_safe = mysqli_real_escape_string($conn, $badge);
                mysqli_query($conn, "UPDATE users SET custom_badge='$b_safe' WHERE username='$t_safe'");
                $flash_msg = 'Custom badge/flair updated for u/' . htmlspecialchars($target, ENT_QUOTES, 'UTF-8') . '.';
            }
        }

        if ($action === 'reset_user_avatar') {
            $target = isset($_POST['target_user']) ? trim($_POST['target_user']) : '';
            if (!empty($target)) {
                $t_safe = mysqli_real_escape_string($conn, $target);
                mysqli_query($conn, "UPDATE users SET avatar_data='', bio='' WHERE username='$t_safe'");
                $flash_msg = 'Avatar and bio reset for u/' . htmlspecialchars($target, ENT_QUOTES, 'UTF-8') . '.';
            }
        }

        if ($action === 'add_motd' && $is_staff) {
            $msg = isset($_POST['motd_message']) ? trim($_POST['motd_message']) : '';
            $weight = isset($_POST['motd_weight']) ? floatval($_POST['motd_weight']) : 100.0;
            if ($weight <= 0) $weight = 10.0;
            if (!empty($msg)) {
                $m_safe = mysqli_real_escape_string($conn, $msg);
                mysqli_query($conn, "INSERT INTO motd_pool (message_text, weight_percent) VALUES ('$m_safe', $weight)");
                $flash_msg = 'New MOTD message added to the pool.';
            }
        }

        if ($action === 'delete_motd' && $is_staff) {
            $mid = isset($_POST['motd_id']) ? intval($_POST['motd_id']) : 0;
            if ($mid > 0) {
                mysqli_query($conn, "DELETE FROM motd_pool WHERE id=$mid");
                $flash_msg = 'MOTD message removed from the pool.';
            }
        }

        if ($action === 'update_announcement' && $is_admin) {
            $ann_text = isset($_POST['announcement_text']) ? trim($_POST['announcement_text']) : '';
            $ann_safe = mysqli_real_escape_string($conn, $ann_text);
            mysqli_query($conn, "UPDATE system_config SET announcement_banner='$ann_safe' WHERE id=1");
            $announcement_banner = $ann_text;
            $flash_msg = 'Announcement banner updated.';
        }

        if ($action === 'change_role' && $is_owner) {
            $target = isset($_POST['target_user']) ? trim($_POST['target_user']) : '';
            $new_role = isset($_POST['new_role']) ? trim($_POST['new_role']) : 'USER';
            if (in_array($new_role, ['USER', 'MOD', 'ADMIN', 'OWNER']) && !empty($target)) {
                $t_safe = mysqli_real_escape_string($conn, $target);
                $badge = ($new_role === 'OWNER') ? 'Owner' : (($new_role === 'ADMIN') ? 'Admin' : (($new_role === 'MOD') ? 'Moderator' : ''));
                mysqli_query($conn, "UPDATE users SET role='$new_role', custom_badge='$badge' WHERE username='$t_safe'");
                $flash_msg = 'Role for u/' . htmlspecialchars($target, ENT_QUOTES, 'UTF-8') . ' updated to ' . $new_role . '.';
            }
        }
    }
}

$sub_filter = isset($_GET['b']) ? trim($_GET['b']) : (isset($_GET['r']) ? trim($_GET['r']) : '');
$view_post_id = isset($_GET['post']) ? intval($_GET['post']) : 0;
$view_user = isset($_GET['u']) ? trim($_GET['u']) : '';
$view_tab = isset($_GET['tab']) ? trim($_GET['tab']) : 'posts';
$search_q = isset($_GET['q']) ? trim($_GET['q']) : '';
$sort_mode = isset($_GET['sort']) ? trim($_GET['sort']) : 'hot';
$feed_mode = isset($_GET['feed']) ? trim($_GET['feed']) : 'all';

$current_sub = null;
if (!empty($sub_filter) && $sub_filter !== 'all' && $sub_filter !== 'popular') {
    $sb_safe = mysqli_real_escape_string($conn, $sub_filter);
    $sq = mysqli_query($conn, "SELECT * FROM subbetters WHERE name='$sb_safe'");
    if ($sq && mysqli_num_rows($sq) > 0) {
        $current_sub = mysqli_fetch_assoc($sq);
    }
}

$all_subs_q = mysqli_query($conn, "SELECT * FROM subbetters ORDER BY name ASC");
$all_subs = [];
while ($sb_row = mysqli_fetch_assoc($all_subs_q)) {
    $all_subs[] = $sb_row;
}

$user_subs_q = mysqli_query($conn, "SELECT subbetter_id FROM subscriptions WHERE user_id={$curr_user['id']}");
$my_sub_ids = [];
while ($usr_sbr = mysqli_fetch_assoc($user_subs_q)) {
    $my_sub_ids[] = intval($usr_sbr['subbetter_id']);
}

$user_saved_q = mysqli_query($conn, "SELECT post_id FROM saved_posts WHERE user_id={$curr_user['id']}");
$my_saved_pids = [];
while ($sv_row = mysqli_fetch_assoc($user_saved_q)) {
    $my_saved_pids[] = intval($sv_row['post_id']);
}

$user_votes_q = mysqli_query($conn, "SELECT target_type, target_id, vote_type FROM user_votes WHERE user_id={$curr_user['id']}");
$my_votes = ['post' => [], 'comment' => []];
while ($vr = mysqli_fetch_assoc($user_votes_q)) {
    $my_votes[$vr['target_type']][intval($vr['target_id'])] = intval($vr['vote_type']);
}

$is_night = ($curr_user['theme'] === 'night');
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title><?php 
if ($view_post_id > 0) {
    echo "Post on BetterForums";
} elseif ($current_sub) {
    echo "r/" . htmlspecialchars($current_sub['name'], ENT_QUOTES, 'UTF-8') . " - BetterForums";
} elseif (!empty($view_user)) {
    echo "u/" . htmlspecialchars($view_user, ENT_QUOTES, 'UTF-8') . "'s profile";
} else {
    echo "BetterForums: the front page of the internet";
}
?></title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: #0f172a; }
::-webkit-scrollbar-thumb { background: #1e293b; border-radius: 4px; }
::-webkit-scrollbar-thumb:hover { background: #334155; }

/* Control Panel Modals & Components */
.modal-bg { position: fixed; inset: 0; background: rgba(0,0,0,0.75); backdrop-filter: blur(6px); display: flex; align-items: center; justify-content: center; z-index: 1000; opacity: 0; pointer-events: none; transition: opacity .2s; }
.modal-bg.open { opacity: 1; pointer-events: all; }
.modal-box { background: #0f172a; border: 1px solid #1e293b; border-radius: 12px; padding: 24px; min-width: 360px; max-width: 520px; width: 100%; max-height: 90vh; overflow-y: auto; transform: translateY(16px); transition: transform .25s cubic-bezier(.16,1,.3,1); box-shadow: 0 25px 60px rgba(0,0,0,.8); color: #f8fafc; }
.modal-bg.open .modal-box { transform: none; }
#admin-modal .modal-box { min-width: 680px; max-width: 840px; }

.admin-tabs-nav { display: flex; flex-wrap: wrap; background: #090d16; border: 1px solid #1e293b; border-radius: 8px; padding: 4px; gap: 4px; margin-bottom: 18px; }
.admin-tab-btn { flex: 1; min-width: 75px; padding: 6px 8px; border-radius: 6px; font-size: 11px; font-weight: 600; text-align: center; color: #94a3b8; background: transparent; border: none; cursor: pointer; transition: all 0.15s ease; white-space: nowrap; }
.admin-tab-btn:hover { color: #ffffff; background: rgba(255,255,255,0.05); }
.admin-tab-btn.active { background: rgba(239,68,68,0.2); color: #f87171; border: 1px solid rgba(239,68,68,0.3); }

.admin-section { display: none; }
.admin-section.active { display: block; }

.user-table-row { display: flex; align-items: center; gap: 10px; padding: 8px 12px; border-radius: 8px; border: 1px solid #1e293b; background: rgba(15, 23, 42, 0.6); margin-bottom: 6px; transition: all 0.15s ease; }
.user-table-row:hover { background: rgba(30, 41, 59, 0.6); border-color: #334155; }

.toast-container { position: fixed; bottom: 24px; right: 24px; z-index: 9999; display: flex; flex-direction: column; gap: 8px; pointer-events: none; }
.toast-msg { background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 10px 16px; font-size: 12px; color: #f8fafc; box-shadow: 0 8px 24px rgba(0,0,0,0.6); animation: toastSlideIn .2s ease forwards; pointer-events: auto; display: flex; align-items: center; gap: 8px; }
.toast-msg.success { border-color: #10b981; color: #34d399; }
.toast-msg.error { border-color: #ef4444; color: #f87171; }
@keyframes toastSlideIn { from { opacity: 0; transform: translateX(20px); } to { opacity: 1; transform: none; } }

.switch-toggle { position: relative; display: inline-block; width: 44px; height: 24px; vertical-align: middle; }
.switch-toggle input { opacity: 0; width: 0; height: 0; }
.switch-slider { position: absolute; cursor: pointer; inset: 0; background-color: #334155; transition: .3s; border-radius: 24px; }
.switch-slider:before { position: absolute; content: ""; height: 18px; width: 18px; left: 3px; bottom: 3px; background-color: white; transition: .3s; border-radius: 50%; }
.switch-toggle input:checked + .switch-slider { background-color: #ef4444; }
.switch-toggle input:checked + .switch-slider:before { transform: translateX(20px); }

.stat-grid-box { display: grid; grid-template-columns: repeat(auto-fill, minmax(130px, 1fr)); gap: 10px; margin-bottom: 15px; }
.stat-card { background: #090d16; border: 1px solid #1e293b; border-radius: 8px; padding: 12px; text-align: center; }
.stat-card-num { font-size: 18px; font-weight: bold; color: #38bdf8; margin-bottom: 4px; }
.stat-card-lbl { font-size: 10px; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.5px; }

body {
    font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    font-size: 12px;
    background-color: <?php echo $is_night ? '#090d16' : '#0f172a'; ?>;
    color: <?php echo $is_night ? '#cbd5e1' : '#f8fafc'; ?>;
    min-height: 100vh;
}
a { color: #38bdf8; text-decoration: none; transition: color 0.15s ease; }
a:hover { color: #60a5fa; text-decoration: underline; }

.gradient-text {
    background: linear-gradient(to right, #3b82f6, #06b6d4);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}

.sr-header-bar {
    background-color: #090d16;
    border-bottom: 1px solid #1e293b;
    font-size: 10px;
    padding: 5px 12px;
    color: #94a3b8;
    overflow-x: auto;
    white-space: nowrap;
    display: flex;
    align-items: center;
    gap: 8px;
}
.sr-header-bar strong {
    color: #cbd5e1;
    font-size: 10px;
    letter-spacing: 0.5px;
}
.sr-header-bar a {
    color: #94a3b8;
    text-transform: uppercase;
    font-weight: 500;
    font-size: 10px;
}
.sr-header-bar a:hover { color: #38bdf8; }
.sr-separator { color: #334155; }

.main-header {
    background-color: #0f172a;
    border-bottom: 1px solid #1e293b;
    padding: 10px 16px 0 16px;
    display: flex;
    align-items: flex-end;
    justify-content: space-between;
}
.header-left {
    display: flex;
    align-items: flex-end;
    gap: 12px;
}
.site-logo {
    display: flex;
    align-items: center;
    gap: 8px;
    text-decoration: none !important;
    padding-bottom: 6px;
}
.site-logo-icon {
    width: 26px;
    height: 26px;
    background: linear-gradient(135deg, #3b82f6, #06b6d4);
    border-radius: 6px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    color: #ffffff;
    font-weight: 800;
    font-size: 13px;
    box-shadow: 0 2px 8px rgba(59, 130, 246, 0.4);
}
.site-title {
    font-size: 19px;
    font-weight: 800;
    letter-spacing: -0.5px;
    background: linear-gradient(to right, #3b82f6, #06b6d4);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}
.sub-nav-tabs {
    display: flex;
    align-items: flex-end;
    gap: 4px;
    margin-left: 10px;
}
.nav-tab {
    padding: 6px 12px;
    font-size: 11px;
    font-weight: 600;
    border: 1px solid #1e293b;
    border-bottom: none;
    background-color: #1e293b;
    color: #94a3b8;
    border-radius: 6px 6px 0 0;
    text-decoration: none;
    text-transform: capitalize;
    transition: all 0.15s ease;
}
.nav-tab:hover {
    color: #f8fafc;
    background-color: #334155;
}
.nav-tab.active {
    background-color: #0f172a;
    color: #38bdf8;
    border: 1px solid #334155;
    border-bottom: 1px solid #0f172a;
    border-top: 2px solid #38bdf8;
    padding-top: 5px;
    font-weight: bold;
}

.header-user-bar {
    background-color: #1e293b;
    border: 1px solid #334155;
    border-bottom: none;
    border-radius: 6px 6px 0 0;
    padding: 5px 12px;
    font-size: 11px;
    display: flex;
    align-items: center;
    gap: 8px;
    color: #cbd5e1;
}
.karma-badge { font-weight: 600; color: #94a3b8; }
.role-badge {
    background: linear-gradient(135deg, #3b82f6, #06b6d4);
    color: #ffffff;
    font-size: 9px;
    padding: 2px 6px;
    border-radius: 4px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.page-wrapper {
    max-width: 1240px;
    margin: 0 auto;
    padding: 14px 16px;
    display: flex;
    gap: 16px;
}
.main-content {
    flex: 1;
    min-width: 0;
    background-color: #1e293b;
    border: 1px solid #334155;
    border-radius: 8px;
    padding: 16px;
    box-shadow: 0 4px 20px rgba(0,0,0,0.25);
}
.sidebar {
    width: 310px;
    flex-shrink: 0;
    display: flex;
    flex-direction: column;
    gap: 12px;
}
.sidebar-box {
    background-color: #1e293b;
    border: 1px solid #334155;
    border-radius: 8px;
    padding: 14px;
    font-size: 11px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.2);
}
.sidebar-title {
    font-size: 13px;
    font-weight: 700;
    color: #f8fafc;
    margin-bottom: 10px;
    padding-bottom: 6px;
    border-bottom: 1px solid #334155;
    display: flex;
    align-items: center;
    justify-content: space-between;
}

.btn-reddit {
    display: block;
    width: 100%;
    text-align: center;
    background-color: #0f172a;
    color: #f8fafc;
    border: 1px solid #334155;
    padding: 7px 12px;
    font-size: 11px;
    font-weight: 600;
    border-radius: 6px;
    cursor: pointer;
    text-decoration: none !important;
    transition: all 0.15s ease;
}
.btn-reddit:hover {
    background-color: #334155;
    border-color: #475569;
    color: #38bdf8;
}
.btn-reddit-primary {
    background: linear-gradient(135deg, #2563eb, #3b82f6);
    color: #ffffff !important;
    border: 1px solid #3b82f6;
    box-shadow: 0 2px 8px rgba(37, 99, 235, 0.35);
}
.btn-reddit-primary:hover {
    background: linear-gradient(135deg, #1d4ed8, #2563eb);
    border-color: #60a5fa;
}

.sort-bar {
    background-color: #0f172a;
    border: 1px solid #334155;
    padding: 6px 12px;
    border-radius: 6px;
    margin-bottom: 14px;
    display: flex;
    align-items: center;
    justify-content: space-between;
}
.sort-links {
    display: flex;
    align-items: center;
    gap: 8px;
}
.sort-link {
    font-weight: 600;
    padding: 4px 8px;
    border-radius: 4px;
    color: #94a3b8;
    transition: all 0.15s ease;
}
.sort-link:hover {
    color: #f8fafc;
    background-color: #1e293b;
    text-decoration: none;
}
.sort-link.active {
    background-color: #2563eb;
    color: #ffffff !important;
}

.post-item {
    display: flex;
    align-items: flex-start;
    padding: 12px 6px;
    border-bottom: 1px solid #334155;
    gap: 10px;
    transition: background 0.15s ease;
}
.post-item:hover {
    background-color: rgba(255, 255, 255, 0.02);
}
.post-item:last-child { border-bottom: none; }
.post-item.is-pinned {
    background-color: rgba(16, 185, 129, 0.08);
    border-left: 3px solid #10b981;
    padding-left: 8px;
    border-radius: 0 6px 6px 0;
}

.vote-box {
    width: 34px;
    display: flex;
    flex-direction: column;
    align-items: center;
    flex-shrink: 0;
    background: #0f172a;
    border: 1px solid #334155;
    border-radius: 6px;
    padding: 4px 0;
}
.vote-btn {
    background: none;
    border: none;
    font-size: 14px;
    cursor: pointer;
    color: #64748b;
    padding: 0;
    line-height: 1;
    transition: color 0.15s ease;
}
.vote-btn:hover { color: #38bdf8; }
.vote-btn.up.active { color: #38bdf8; font-weight: bold; }
.vote-btn.down.active { color: #818cf8; font-weight: bold; }
.vote-score {
    font-size: 11px;
    font-weight: 700;
    margin: 3px 0;
    color: #cbd5e1;
}
.vote-score.upvoted { color: #38bdf8; }
.vote-score.downvoted { color: #818cf8; }

.post-body-col {
    flex: 1;
    min-width: 0;
}
.post-title-link {
    font-size: 14px;
    font-weight: 600;
    color: #f8fafc;
    line-height: 1.4;
}
.post-title-link:hover {
    text-decoration: underline;
    color: #38bdf8;
}
.post-title-link:visited {
    color: #cbd5e1;
}
.post-domain {
    font-size: 11px;
    color: #94a3b8;
    margin-left: 6px;
}
.post-flair {
    display: inline-block;
    background-color: #0f172a;
    color: #38bdf8;
    border: 1px solid #334155;
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 10px;
    font-weight: 600;
    margin-right: 6px;
}
.post-meta {
    font-size: 11px;
    color: #94a3b8;
    margin: 4px 0 6px 0;
}
.post-meta a { color: #94a3b8; }
.post-meta a:hover { color: #38bdf8; }
.post-actions {
    display: flex;
    align-items: center;
    gap: 12px;
    font-size: 11px;
    font-weight: 600;
    color: #94a3b8;
}
.post-actions a, .post-actions button {
    color: #94a3b8;
    background: none;
    border: none;
    font-size: 11px;
    font-weight: 600;
    cursor: pointer;
    padding: 0;
    transition: color 0.15s ease;
}
.post-actions a:hover, .post-actions button:hover {
    color: #38bdf8;
    text-decoration: underline;
}

.motd-top-ticker-bar {
    background: #090d16;
    border-bottom: 1px solid #1e293b;
    width: 100%;
    height: 28px;
    line-height: 28px;
    overflow: hidden;
    position: relative;
    z-index: 100;
    box-sizing: border-box;
    user-select: none;
    -webkit-user-select: none;
    -moz-user-select: none;
    -ms-user-select: none;
}
.motd-ticker-marquee {
    font-family: "Comic Sans MS", "Comic Sans", cursive, sans-serif !important;
    font-size: 12px;
    font-weight: bold;
    color: #38bdf8;
    line-height: 28px;
    display: block;
    width: 100%;
    margin: 0;
    padding: 0;
    cursor: default;
    user-select: none;
    -webkit-user-select: none;
    -moz-user-select: none;
    -ms-user-select: none;
    -webkit-touch-callout: none;
}
.motd-ticker-marquee:hover {
    color: #7dd3fc;
}
.announcement-banner {
    background: linear-gradient(to right, rgba(234, 179, 8, 0.12), transparent);
    border: 1px solid rgba(234, 179, 8, 0.25);
    padding: 8px 12px;
    border-radius: 6px;
    margin-bottom: 12px;
    font-size: 12px;
    color: #fbbf24;
    user-select: none;
    -webkit-user-select: none;
}
.notice-banner {
    background: #0f172a;
    border: 1px solid #334155;
    padding: 8px 12px;
    border-radius: 6px;
    margin-bottom: 12px;
    font-size: 12px;
    color: #cbd5e1;
    user-select: none;
}
.alert-box {
    padding: 8px 12px;
    border-radius: 6px;
    margin-bottom: 12px;
    font-size: 12px;
}
.alert-success { background: rgba(16, 185, 129, 0.15); border: 1px solid #10b981; color: #6ee7b7; }
.alert-error { background: rgba(239, 68, 68, 0.15); border: 1px solid #ef4444; color: #fca5a5; }

.form-group { margin-bottom: 12px; }
.form-group label { display: block; font-weight: 600; margin-bottom: 4px; font-size: 11px; color: #cbd5e1; }
.input-text, select, textarea {
    width: 100%;
    padding: 7px 10px;
    border: 1px solid #334155;
    background-color: #0f172a;
    color: #f8fafc;
    border-radius: 6px;
    font-family: inherit;
    font-size: 12px;
    transition: border-color 0.15s ease;
}
.input-text:focus, select:focus, textarea:focus {
    outline: none;
    border-color: #3b82f6;
    box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.25);
}

.editor-toolbar {
    background-color: #0f172a;
    border: 1px solid #334155;
    border-bottom: none;
    padding: 6px 8px;
    display: flex;
    gap: 6px;
    border-radius: 6px 6px 0 0;
}
.tool-btn {
    background: #1e293b;
    border: 1px solid #334155;
    padding: 3px 8px;
    font-size: 11px;
    font-weight: 600;
    cursor: pointer;
    color: #cbd5e1;
    border-radius: 4px;
    transition: all 0.15s ease;
}
.tool-btn:hover {
    background-color: #334155;
    color: #38bdf8;
}

.comment-block {
    margin-top: 10px;
    padding-left: 12px;
    border-left: 2px solid #334155;
}
.comment-meta {
    font-size: 11px;
    color: #94a3b8;
    margin-bottom: 4px;
}
.comment-text {
    font-size: 12px;
    line-height: 1.5;
    margin-bottom: 8px;
    color: #f8fafc;
}

.tab-nav {
    display: flex;
    border-bottom: 1px solid #334155;
    margin-bottom: 14px;
    gap: 6px;
}
.tab-nav a {
    padding: 6px 12px;
    font-weight: 600;
    color: #94a3b8;
    border: 1px solid #334155;
    border-bottom: none;
    background: #0f172a;
    border-radius: 6px 6px 0 0;
    text-decoration: none;
    font-size: 11px;
    transition: all 0.15s ease;
}
.tab-nav a:hover {
    color: #f8fafc;
    background: #334155;
}
.tab-nav a.active {
    background-color: #1e293b;
    border-color: #334155;
    border-top: 2px solid #38bdf8;
    color: #38bdf8;
}

/* Circle profile avatars */
.user-avatar-circle, img[src*="avatar"], .avatar-circle {
    border-radius: 50% !important;
}

/* Mod Action Styles */
.btn-mod-toggle {
    display: inline-flex !important;
    align-items: center !important;
    gap: 3px !important;
    background: rgba(56, 189, 248, 0.12) !important;
    border: 1px solid rgba(56, 189, 248, 0.35) !important;
    color: #38bdf8 !important;
    font-size: 10px !important;
    font-weight: 700 !important;
    padding: 2px 6px !important;
    border-radius: 4px !important;
    cursor: pointer !important;
    transition: all 0.15s ease !important;
    vertical-align: middle !important;
    line-height: 1 !important;
    text-decoration: none !important;
}
.btn-mod-toggle:hover {
    background: rgba(56, 189, 248, 0.25) !important;
    border-color: #38bdf8 !important;
    color: #ffffff !important;
    text-decoration: none !important;
}
.mod-action-row {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px;
    margin-top: 8px;
    padding: 7px 10px;
    background: #090d16;
    border: 1px solid #1e293b;
    border-left: 3px solid #38bdf8;
    border-radius: 4px;
    font-size: 11px;
}
.mod-row-label {
    font-weight: 700;
    font-size: 10px;
    color: #38bdf8;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-right: 4px;
    display: inline-flex;
    align-items: center;
    gap: 4px;
}
.mod-btn-action {
    background: #1e293b;
    border: 1px solid #334155;
    color: #cbd5e1;
    font-size: 10px;
    padding: 3px 8px;
    border-radius: 3px;
    cursor: pointer;
    font-weight: 600;
    transition: all 0.15s ease;
    display: inline-flex;
    align-items: center;
    gap: 4px;
    text-decoration: none;
}
.mod-btn-action:hover {
    background: #334155;
    color: #f8fafc;
    text-decoration: none;
}
.mod-btn-danger {
    background: rgba(239, 68, 68, 0.15) !important;
    border-color: #ef4444 !important;
    color: #fca5a5 !important;
}
.mod-btn-danger:hover {
    background: #ef4444 !important;
    color: #ffffff !important;
}
.mod-btn-success {
    background: rgba(16, 185, 129, 0.15) !important;
    border-color: #10b981 !important;
    color: #6ee7b7 !important;
}
.mod-btn-success:hover {
    background: #10b981 !important;
    color: #ffffff !important;
}
.mod-btn-warning {
    background: rgba(245, 158, 11, 0.15) !important;
    border-color: #f59e0b !important;
    color: #fde68a !important;
}
.mod-btn-warning:hover {
    background: #f59e0b !important;
    color: #ffffff !important;
}
</style>
<script>
function toggleModRow(rowId) {
    const el = document.getElementById(rowId);
    if (!el) return;
    if (el.style.display === 'none' || el.style.display === '') {
        el.style.display = 'flex';
    } else {
        el.style.display = 'none';
    }
}

function replyToComment(username) {
    const editor = document.getElementById('comment_editor');
    if (editor) {
        editor.value = `@${username} ` + editor.value;
        editor.focus();
        if (typeof updateLivePreview === 'function') {
            updateLivePreview('comment_editor', 'comment_preview_box');
        }
        editor.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
}
function insertFormat(tagStart, tagEnd, targetId = 'markdown_editor') {
    const area = document.getElementById(targetId);
    if (!area) return;
    const start = area.selectionStart;
    const end = area.selectionEnd;
    const text = area.value;
    const selected = text.substring(start, end);
    const defaultText = tagStart.includes('![') ? 'https://example.com/image.png' : (tagStart.includes('[Link](') || tagStart === '[' ? 'https://example.com' : 'text');
    const replacement = tagStart + (selected || defaultText) + tagEnd;
    area.value = text.substring(0, start) + replacement + text.substring(end);
    area.focus();
    area.selectionStart = start + tagStart.length;
    area.selectionEnd = start + tagStart.length + (selected ? selected.length : 4);
    updateLivePreview(targetId);
}

function renderMarkdownClient(raw) {
    if (!raw || !raw.trim()) return '<em style="color:#94a3b8;">Live preview will render here automatically as you type...</em>';
    let text = raw.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
    
    text = text.replace(/\[2x\](.*?)\[\/2x\]/gs, '<span style="font-size:2em; font-weight:bold; line-height:1.25; display:inline-block;">$1</span>');
    text = text.replace(/\+\+(.*?)\+\+/gs, '<span style="font-size:2em; font-weight:bold; line-height:1.25; display:inline-block;">$1</span>');
    text = text.replace(/^#\s+(.*?)$/gm, '<span style="font-size:2em; font-weight:bold; line-height:1.25; display:block; margin:4px 0;">$1</span>');
    text = text.replace(/^##\s+(.*?)$/gm, '<span style="font-size:1.5em; font-weight:bold; line-height:1.25; display:block; margin:4px 0;">$1</span>');
    
    text = text.replace(/!\[(.*?)\]\((https?:\/\/[^\s\)\"\']+|data:image\/[a-zA-Z0-9\+\-\.]+;base64,[^\s\)\"\']+|\/\/[^\s\)\"\']+)\)/gi, '<div style="margin:8px 0;"><img src="$2" alt="$1" referrerpolicy="no-referrer" loading="lazy" style="max-width:100%; max-height:420px; border-radius:6px; border:1px solid #334155; display:block;" onerror="this.parentElement.style.display=\'none\'"></div>');
    text = text.replace(/!\[(.*?)\]\([^\)]*\)/gi, '');
    text = text.replace(/!\[(.*?)\]/gi, '');
    text = text.replace(/\[(.*?)\]\((https?:\/\/[^\s\)\"\']+)\)/gi, '<a href="$2" target="_blank" rel="noopener" style="color:#38bdf8; text-decoration:underline;">$1</a>');
    text = text.replace(/\[(.*?)\]\([^\)]*\)/gi, '$1');
    text = text.replace(/\*\*(.*?)\*\*/gs, '<strong>$1</strong>');
    text = text.replace(/\*([^\*]+)\*/gs, '<em>$1</em>');
    text = text.replace(/~~(.*?)~~/gs, '<del>$1</del>');
    text = text.replace(/`([^`]+)`/g, '<code style="background:#0f172a; color:#38bdf8; padding:2px 6px; font-family:monospace; font-size:11px; border:1px solid #334155; border-radius:4px;">$1</code>');
    text = text.replace(/^&gt;\s?(.*?)$/gm, '<blockquote style="border-left:3px solid #3b82f6; margin:6px 0; padding:4px 10px; color:#cbd5e1; background:rgba(59,130,246,0.1); border-radius:0 4px 4px 0;">$1</blockquote>');
    
    return text.replace(/\n/g, '<br>');
}

function updateLivePreview(targetId = 'markdown_editor', previewId = 'live_preview_box') {
    const area = document.getElementById(targetId);
    const preview = document.getElementById(previewId);
    if (area && preview) {
        preview.innerHTML = renderMarkdownClient(area.value);
    }
}

function copyPostLink(url) {
    navigator.clipboard.writeText(url).then(() => {
        alert('Link copied to clipboard!');
    }).catch(() => {
        prompt('Copy this link:', url);
    });
}
</script>
</head>
<body>

<?php
$motd_pool_q = mysqli_query($conn, "SELECT message_text FROM motd_pool ORDER BY id ASC");
$motd_texts = [];
if ($motd_pool_q && mysqli_num_rows($motd_pool_q) > 0) {
    while ($mp_row = mysqli_fetch_assoc($motd_pool_q)) {
        if (!empty(trim($mp_row['message_text']))) {
            $motd_texts[] = htmlspecialchars($mp_row['message_text'], ENT_QUOTES, 'UTF-8');
        }
    }
}
$active_motd = get_active_motd($conn);
if (empty($motd_texts) && !empty($active_motd)) {
    $motd_texts[] = htmlspecialchars($active_motd, ENT_QUOTES, 'UTF-8');
}
?>
<?php if (!empty($motd_texts)): ?>
<div class="motd-top-ticker-bar" unselectable="on" onselectstart="return false;" oncopy="return false;" oncontextmenu="return false;">
    <marquee class="motd-ticker-marquee" behavior="scroll" direction="left" scrollamount="5" unselectable="on" onselectstart="return false;" oncopy="return false;">
        <?php echo implode(' &nbsp;&nbsp;&bull;&nbsp;&nbsp; ', $motd_texts); ?>
    </marquee>
</div>
<?php endif; ?>

<div class="sr-header-bar">
    <strong>MY COMMUNITIES:</strong>
    <a href="index.php?feed=home" style="<?php echo ($feed_mode === 'home' && empty($sub_filter)) ? 'color:#38bdf8;font-weight:bold;' : ''; ?>">Home</a>
    <span class="sr-separator">|</span>
    <a href="index.php?feed=popular" style="<?php echo ($feed_mode === 'popular' || $sub_filter === 'popular') ? 'color:#38bdf8;font-weight:bold;' : ''; ?>">Popular</a>
    <span class="sr-separator">|</span>
    <a href="index.php?feed=all" style="<?php echo ($feed_mode === 'all' && empty($sub_filter)) ? 'color:#38bdf8;font-weight:bold;' : ''; ?>">All</a>
    <span class="sr-separator">|</span>
    <?php foreach ($all_subs as $idx => $sb): ?>
        <a href="index.php?b=<?php echo urlencode($sb['name']); ?>" style="<?php echo ($sub_filter === $sb['name']) ? 'color:#38bdf8;font-weight:bold;' : ''; ?>">
            r/<?php echo htmlspecialchars($sb['name'], ENT_QUOTES, 'UTF-8'); ?>
        </a>
        <?php if ($idx < count($all_subs) - 1): ?><span class="sr-separator">-</span><?php endif; ?>
    <?php endforeach; ?>
</div>

<div class="main-header">
    <div class="header-left">
        <a href="index.php" class="site-logo">
            <span class="site-logo-icon">&#9679;</span>
            <span class="site-title">BetterForums</span>
        </a>
        <div class="sub-nav-tabs">
            <a href="index.php?feed=home" class="nav-tab <?php echo ($feed_mode === 'home' && empty($sub_filter) && empty($action)) ? 'active' : ''; ?>">home</a>
            <a href="index.php?feed=popular" class="nav-tab <?php echo ($feed_mode === 'popular' || $sub_filter === 'popular') ? 'active' : ''; ?>">popular</a>
            <a href="index.php?feed=all" class="nav-tab <?php echo ($feed_mode === 'all' && empty($sub_filter) && empty($action)) ? 'active' : ''; ?>">all</a>
            <a href="index.php?action=leaderboard" class="nav-tab <?php echo ($action === 'leaderboard') ? 'active' : ''; ?>"><i class="fa-solid fa-trophy" style="color:#fbbf24; font-size:10px;"></i> leaderboard</a>
            <a href="index.php?action=users" class="nav-tab <?php echo ($action === 'users') ? 'active' : ''; ?>"><i class="fa-solid fa-users" style="color:#38bdf8; font-size:10px;"></i> users</a>
            <?php if ($current_sub): ?>
                <a href="index.php?b=<?php echo urlencode($current_sub['name']); ?>" class="nav-tab active">r/<?php echo htmlspecialchars($current_sub['name'], ENT_QUOTES, 'UTF-8'); ?></a>
            <?php endif; ?>
        </div>
    </div>
    <div class="header-user-bar" id="header_user_bar">
        <?php echo render_avatar_img($curr_user, 18); ?>
        <a href="index.php?u=<?php echo urlencode($curr_user['username']); ?>"><strong>u/<?php echo htmlspecialchars($curr_user['username'], ENT_QUOTES, 'UTF-8'); ?></strong></a>
        <span class="karma-badge" id="header_user_karma">(<?php echo number_format($user_karma); ?> karma)</span>
        <span id="header_role_tag_container"><?php echo render_role_tag($curr_user); ?></span>
        <span class="sr-separator">|</span>
        <a href="index.php?action=leaderboard" style="color:#fbbf24;"><i class="fa-solid fa-trophy"></i> leaderboard</a>
        <span class="sr-separator">|</span>
        <a href="index.php?action=users" style="color:#38bdf8;"><i class="fa-solid fa-users"></i> users</a>
        <span class="sr-separator">|</span>
        <a href="index.php?action=saved">saved</a>
        <span class="sr-separator">|</span>
        <a href="index.php?action=settings">preferences</a>
        <?php if ($is_staff): ?>
            <span class="sr-separator">|</span>
            <button type="button" onclick="openAdminPanel()" class="admin-cp-btn" style="background:rgba(239,68,68,0.15); border:1px solid rgba(239,68,68,0.35); color:#f87171; border-radius:4px; padding:2px 7px; font-size:11px; font-weight:600; cursor:pointer; display:inline-flex; align-items:center; gap:4px; transition:all 0.15s ease;" onmouseover="this.style.background='rgba(239,68,68,0.25)'" onmouseout="this.style.background='rgba(239,68,68,0.15)'">
                <i class="fa-solid fa-shield-halved"></i> Control Panel
            </button>
            <span class="sr-separator">|</span>
            <a href="index.php?action=mod_tools" style="color:#38bdf8; font-weight:bold;">mod tools</a>
        <?php endif; ?>
        <span class="sr-separator">|</span>
        <a href="index.php?action=logout">log out</a>
    </div>
</div>

<div class="page-wrapper">
    <div class="main-content">
        <?php if (!empty($flash_msg)): ?>
            <div class="alert-box alert-success"><?php echo htmlspecialchars($flash_msg, ENT_QUOTES, 'UTF-8'); ?></div>
        <?php endif; ?>
        <?php if (!empty($flash_err)): ?>
            <div class="alert-box alert-error"><?php echo htmlspecialchars($flash_err, ENT_QUOTES, 'UTF-8'); ?></div>
        <?php endif; ?>
        <div id="live_announcement_banner_container">
            <?php if (!empty($announcement_banner)): ?>
                <div class="announcement-banner">
                    <strong>Community Announcement:</strong> <span><?php echo htmlspecialchars($announcement_banner, ENT_QUOTES, 'UTF-8'); ?></span>
                </div>
            <?php endif; ?>
        </div>

        <?php if ($action === 'submit'): ?>
            <div style="font-size:14px; font-weight:bold; margin-bottom:12px; border-bottom:1px solid var(--bf-border); padding-bottom:6px; color:var(--bf-text);">
                Create a Post
            </div>
            <form method="POST" action="index.php" enctype="multipart/form-data">
                <input type="hidden" name="action" value="new_post">
                <div class="form-group">
                    <label>Choose a Community:</label>
                    <select name="subbetter_id" required>
                        <?php foreach ($all_subs as $sb): ?>
                            <option value="<?php echo $sb['id']; ?>" <?php echo ($current_sub && $current_sub['id'] == $sb['id']) ? 'selected' : ''; ?>>
                                r/<?php echo htmlspecialchars($sb['name'], ENT_QUOTES, 'UTF-8'); ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="form-group">
                    <label>Post Title:</label>
                    <input type="text" name="title" class="input-text" placeholder="Title (required)" required maxlength="250">
                </div>
                <div class="form-group">
                    <label>Post Flair (Optional):</label>
                    <select name="flair">
                        <option value="">No Flair</option>
                        <option value="Discussion">Discussion</option>
                        <option value="News">News</option>
                        <option value="Question">Question</option>
                        <option value="OC">OC (Original Content)</option>
                        <option value="Meme">Meme</option>
                        <option value="Help">Help / Support</option>
                        <option value="Tutorial">Tutorial / Guide</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Link URL (Optional - for link posts):</label>
                    <input type="url" name="link_url" class="input-text" placeholder="https://example.com">
                </div>
                <div class="form-group">
                    <label>Post Text & Formatting:</label>
                    <div class="editor-toolbar">
                        <button type="button" class="tool-btn" onclick="insertFormat('**', '**')"><strong>B</strong></button>
                        <button type="button" class="tool-btn" onclick="insertFormat('*', '*')"><em>I</em></button>
                        <button type="button" class="tool-btn" onclick="insertFormat('[2x]', '[/2x]')" style="color:#38bdf8; font-weight:bold;" title="Scale text 2X size">2X Size</button>
                        <button type="button" class="tool-btn" onclick="insertFormat('~~', '~~')"><del>S</del></button>
                        <button type="button" class="tool-btn" onclick="insertFormat('`', '`')">Code</button>
                        <button type="button" class="tool-btn" onclick="insertFormat('> ', '')">Quote</button>
                        <button type="button" class="tool-btn" onclick="insertFormat('[', '](https://)')">Link</button>
                        <button type="button" class="tool-btn" onclick="insertFormat('![Image Description](', ')')">Image Embed</button>
                    </div>
                    <textarea id="markdown_editor" name="content" rows="8" placeholder="What are your thoughts? You can select text and click formatting buttons above." oninput="updateLivePreview('markdown_editor', 'live_preview_box')"></textarea>
                    
                    <div style="margin-top:8px;">
                        <div style="font-weight:bold; font-size:11px; color:#94a3b8; margin-bottom:4px; display:flex; align-items:center; justify-content:space-between;">
                            <span>Live Real Preview:</span>
                            <span style="font-size:10px; font-weight:normal; color:#64748b;">(Shows rendered formatting in real time)</span>
                        </div>
                        <div id="live_preview_box" style="min-height:60px; max-height:240px; overflow-y:auto; background:#0f172a; border:1px dashed #334155; padding:10px; border-radius:6px; font-size:11px; line-height:1.45;">
                            <em style="color:#64748b;">Live preview will render here automatically as you type...</em>
                        </div>
                    </div>
                </div>
                <div class="form-group">
                    <label>Attach Image (Direct Upload or Image URL):</label>
                    <input type="file" name="image_file" accept="image/*" style="margin-bottom:6px;">
                    <input type="text" name="image_url" class="input-text" placeholder="Or enter direct Image URL (https://...)">
                </div>
                <div style="margin-top:14px;">
                    <button type="submit" class="btn-reddit btn-reddit-primary" style="width:auto; padding:6px 20px; display:inline-block;">Submit Post</button>
                    <a href="index.php" style="margin-left:10px;">Cancel</a>
                </div>
            </form>

        <?php elseif ($action === 'create_community_page'): ?>
            <div style="font-size:14px; font-weight:bold; margin-bottom:12px; border-bottom:1px solid var(--bf-border); padding-bottom:6px; color:var(--bf-text);">
                Create a Community
            </div>
            <form method="POST" action="index.php">
                <input type="hidden" name="action" value="create_community">
                <div class="form-group">
                    <label>Community Name (e.g. technology, gaming, science):</label>
                    <div style="display:flex; align-items:center; gap:4px;">
                        <span style="font-weight:bold; font-size:13px; color:#38bdf8;">r/</span>
                        <input type="text" name="name" class="input-text" placeholder="community_name" required maxlength="30">
                    </div>
                </div>
                <div class="form-group">
                    <label>Description:</label>
                    <textarea name="description" rows="4" placeholder="Describe what this community is about..."></textarea>
                </div>
                <div style="margin-top:14px;">
                    <button type="submit" class="btn-reddit btn-reddit-primary" style="width:auto; padding:6px 20px; display:inline-block;">Create Community</button>
                    <a href="index.php" style="margin-left:10px;">Cancel</a>
                </div>
            </form>

        <?php elseif ($action === 'settings'): ?>
            <div style="font-size:14px; font-weight:bold; margin-bottom:12px; border-bottom:1px solid var(--bf-border); padding-bottom:6px; color:var(--bf-text);">
                User Preferences & Profile Customization
            </div>
            <form method="POST" action="index.php" enctype="multipart/form-data">
                <input type="hidden" name="action" value="update_profile">
                <div class="form-group">
                    <label>Display Name:</label>
                    <input type="text" name="display_name" class="input-text" value="<?php echo htmlspecialchars($curr_user['display_name'], ENT_QUOTES, 'UTF-8'); ?>" maxlength="100">
                </div>
                <div class="form-group">
                    <label>About You (Bio):</label>
                    <textarea name="bio" rows="4"><?php echo htmlspecialchars($curr_user['bio'], ENT_QUOTES, 'UTF-8'); ?></textarea>
                </div>
                <div class="form-group">
                    <label>Status Flair / Tagline:</label>
                    <input type="text" name="status_flair" class="input-text" value="<?php echo htmlspecialchars($curr_user['status_flair'], ENT_QUOTES, 'UTF-8'); ?>" placeholder="e.g. Web Developer & Linux Fan" maxlength="100">
                </div>
                <div class="form-group">
                    <label>Profile Avatar:</label>
                    <div style="margin-bottom:6px; display:flex; align-items:center; gap:8px;">
                        <?php echo render_avatar_img($curr_user, 48); ?>
                        <span style="font-size:10px; color:#94a3b8;">Current avatar preview</span>
                    </div>
                    <input type="file" name="avatar_file" accept="image/*" style="margin-bottom:6px;">
                    <input type="text" name="avatar_url" class="input-text" placeholder="Or enter direct Image URL (https://...)" value="<?php echo (strpos($curr_user['avatar_data'], 'data:image') === false) ? htmlspecialchars($curr_user['avatar_data'], ENT_QUOTES, 'UTF-8') : ''; ?>">
                </div>
                <div class="form-group">
                    <label>Interface Theme:</label>
                    <select name="theme">
                        <option value="night" <?php echo ($curr_user['theme'] === 'night' || $curr_user['theme'] === 'light') ? 'selected' : ''; ?>>Night Mode (BetterChat Dark)</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>
                        <input type="checkbox" name="hide_from_search" value="1" <?php echo (intval($curr_user['hide_from_search']) === 1) ? 'checked' : ''; ?>>
                        Hide my profile from public user lists
                    </label>
                </div>
                <div style="margin-top:14px;">
                    <button type="submit" class="btn-reddit btn-reddit-primary" style="width:auto; padding:6px 20px; display:inline-block;">Save Preferences</button>
                    <a href="index.php" style="margin-left:10px;">Cancel</a>
                </div>
            </form>

        <?php elseif ($action === 'mod_tools' && $is_staff): ?>
            <div style="font-size:14px; font-weight:bold; margin-bottom:12px; border-bottom:1px solid var(--bf-border); padding-bottom:6px; color:var(--bf-text);">
                Moderator Tools & Community Management
            </div>
            
            <div class="tab-nav">
                <a href="#reports" class="active">Pending Reports</a>
                <a href="#motd">MOTD Pool</a>
                <a href="#announcements">Announcement Banner</a>
                <?php if ($is_owner): ?><a href="#roles">Manage Roles</a><?php endif; ?>
            </div>

            <div style="margin-bottom:20px;">
                <h4 style="margin-bottom:8px;">Pending Reports</h4>
                <?php
                $reports_q = mysqli_query($conn, "SELECT m.*, s.name as sub_name FROM moderation_actions m LEFT JOIN subbetters s ON m.subbetter_id=s.id WHERE m.action_type='REPORT' AND m.status='PENDING' ORDER BY m.id DESC");
                if (mysqli_num_rows($reports_q) === 0):
                ?>
                    <p style="color:#94a3b8; font-style:italic;">No pending reports. The queue is clean!</p>
                <?php else: ?>
                    <table style="width:100%; border-collapse:collapse; font-size:11px; margin-bottom:14px;">
                        <thead>
                            <tr style="background:#0f172a; text-align:left; color:#94a3b8;">
                                <th style="padding:6px; border:1px solid #334155;">Reported User</th>
                                <th style="padding:6px; border:1px solid #334155;">Community</th>
                                <th style="padding:6px; border:1px solid #334155;">Reason</th>
                                <th style="padding:6px; border:1px solid #334155;">Reported By</th>
                                <th style="padding:6px; border:1px solid #334155;">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php while ($rep = mysqli_fetch_assoc($reports_q)): ?>
                                <tr>
                                    <td style="padding:6px; border:1px solid #334155;"><strong>u/<?php echo htmlspecialchars($rep['target_username'], ENT_QUOTES, 'UTF-8'); ?></strong></td>
                                    <td style="padding:6px; border:1px solid #334155;">r/<?php echo htmlspecialchars($rep['sub_name'] ? $rep['sub_name'] : 'all', ENT_QUOTES, 'UTF-8'); ?></td>
                                    <td style="padding:6px; border:1px solid #334155;"><?php echo htmlspecialchars($rep['reason'], ENT_QUOTES, 'UTF-8'); ?></td>
                                    <td style="padding:6px; border:1px solid #334155;">u/<?php echo htmlspecialchars($rep['reporter_username'], ENT_QUOTES, 'UTF-8'); ?></td>
                                    <td style="padding:6px; border:1px solid #334155; display:flex; gap:4px;">
                                        <form method="POST" action="index.php" style="display:inline;">
                                            <input type="hidden" name="action" value="mod_decision">
                                            <input type="hidden" name="mod_id" value="<?php echo $rep['id']; ?>">
                                            <input type="hidden" name="decision" value="APPROVED">
                                            <button type="submit" style="background:rgba(16,185,129,0.2); border:1px solid #10b981; color:#34d399; cursor:pointer; padding:2px 6px; border-radius:4px;">Approve & Take Action</button>
                                        </form>
                                        <form method="POST" action="index.php" style="display:inline;">
                                            <input type="hidden" name="action" value="mod_decision">
                                            <input type="hidden" name="mod_id" value="<?php echo $rep['id']; ?>">
                                            <input type="hidden" name="decision" value="DISMISSED">
                                            <button type="submit" style="background:rgba(239,68,68,0.2); border:1px solid #ef4444; color:#f87171; cursor:pointer; padding:2px 6px; border-radius:4px;">Dismiss</button>
                                        </form>
                                    </td>
                                </tr>
                            <?php endwhile; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
            </div>

            <div style="margin-bottom:20px; border-top:1px solid #334155; padding-top:14px;" id="motd">
                <h4 style="margin-bottom:8px; color:#f8fafc;">Manage Message of the Day (MOTD) Pool</h4>
                <p style="color:#94a3b8; font-size:11px; margin-bottom:10px;">The active MOTD banner is picked from this pool based on weight percentages.</p>
                <?php
                $motd_rows_q = mysqli_query($conn, "SELECT * FROM motd_pool ORDER BY id DESC");
                if ($motd_rows_q && mysqli_num_rows($motd_rows_q) > 0):
                ?>
                    <table style="width:100%; border-collapse:collapse; font-size:11px; margin-bottom:14px;">
                        <thead>
                            <tr style="background:#0f172a; text-align:left; color:#94a3b8;">
                                <th style="padding:6px; border:1px solid #334155;">ID</th>
                                <th style="padding:6px; border:1px solid #334155;">Message Text</th>
                                <th style="padding:6px; border:1px solid #334155;">Weight (%)</th>
                                <th style="padding:6px; border:1px solid #334155;">Created</th>
                                <th style="padding:6px; border:1px solid #334155;">Action</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php while ($mrow = mysqli_fetch_assoc($motd_rows_q)): ?>
                                <tr>
                                    <td style="padding:6px; border:1px solid #334155;">#<?php echo $mrow['id']; ?></td>
                                    <td style="padding:6px; border:1px solid #334155;"><strong><?php echo htmlspecialchars($mrow['message_text'], ENT_QUOTES, 'UTF-8'); ?></strong></td>
                                    <td style="padding:6px; border:1px solid #334155;"><?php echo number_format($mrow['weight_percent'], 1); ?>%</td>
                                    <td style="padding:6px; border:1px solid #334155; color:#94a3b8;"><?php echo date('M j, Y', strtotime($mrow['created_at'])); ?></td>
                                    <td style="padding:6px; border:1px solid #334155;">
                                        <form method="POST" action="index.php" style="display:inline;" onsubmit="return confirm('Delete this MOTD?');">
                                            <input type="hidden" name="action" value="delete_motd">
                                            <input type="hidden" name="motd_id" value="<?php echo $mrow['id']; ?>">
                                            <button type="submit" style="background:rgba(239,68,68,0.2); border:1px solid #ef4444; color:#f87171; cursor:pointer; padding:2px 6px; border-radius:4px; font-size:10px;">Delete</button>
                                        </form>
                                    </td>
                                </tr>
                            <?php endwhile; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
                
                <form method="POST" action="index.php" style="background:#0f172a; border:1px solid #334155; padding:12px; border-radius:6px;">
                    <input type="hidden" name="action" value="add_motd">
                    <div style="font-weight:bold; font-size:11px; margin-bottom:6px; color:#f8fafc;">Add New MOTD Message</div>
                    <div style="display:flex; gap:8px; align-items:flex-end;">
                        <div style="flex:1;">
                            <label style="font-size:10px; font-weight:bold; display:block; margin-bottom:2px;">Message Text:</label>
                            <input type="text" name="motd_message" class="input-text" placeholder="e.g. Welcome to BetterForums! Check out r/general" required>
                        </div>
                        <div style="width:120px;">
                            <label style="font-size:10px; font-weight:bold; display:block; margin-bottom:2px;">Weight %:</label>
                            <input type="number" name="motd_weight" class="input-text" step="0.1" value="100" min="0.1" max="1000" required>
                        </div>
                        <button type="submit" class="btn-reddit btn-reddit-primary" style="width:auto; padding:5px 14px; white-space:nowrap;">Add to Pool</button>
                    </div>
                </form>
            </div>

            <?php if ($is_admin): ?>
                <div style="margin-bottom:20px; border-top:1px solid #334155; padding-top:14px;" id="announcements">
                    <h4 style="margin-bottom:8px; color:#f8fafc;">Set Community Announcement Banner</h4>
                    <form method="POST" action="index.php">
                        <input type="hidden" name="action" value="update_announcement">
                        <div class="form-group">
                            <textarea name="announcement_text" rows="2" placeholder="Leave empty to remove announcement"><?php echo htmlspecialchars($announcement_banner, ENT_QUOTES, 'UTF-8'); ?></textarea>
                        </div>
                        <button type="submit" class="btn-reddit btn-reddit-primary" style="width:auto; padding:6px 16px; display:inline-block;">Save Announcement</button>
                    </form>
                </div>
            <?php endif; ?>

            <?php if ($is_owner): ?>
                <div style="margin-bottom:20px; border-top:1px solid #334155; padding-top:14px;" id="roles">
                    <h4 style="margin-bottom:8px; color:#f8fafc;">Manage User Roles</h4>
                    <form method="POST" action="index.php" style="display:flex; gap:8px; align-items:flex-end;">
                        <input type="hidden" name="action" value="change_role">
                        <div>
                            <label>Username:</label>
                            <input type="text" name="target_user" class="input-text" placeholder="Username" required>
                        </div>
                        <div>
                            <label>New Role:</label>
                            <select name="new_role">
                                <option value="USER">User (Regular)</option>
                                <option value="MOD">Moderator</option>
                                <option value="ADMIN">Administrator</option>
                                <option value="OWNER">Owner</option>
                            </select>
                        </div>
                        <button type="submit" class="btn-reddit btn-reddit-primary" style="width:auto; padding:6px 16px;">Update Role</button>
                    </form>
                </div>
            <?php endif; ?>

        <?php elseif ($action === 'leaderboard'): ?>
            <div style="font-size:14px; font-weight:bold; margin-bottom:12px; border-bottom:1px solid var(--bf-border); padding-bottom:6px; color:var(--bf-text); display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:8px;">
                <span style="display:flex; align-items:center; gap:6px;">
                    <i class="fa-solid fa-trophy" style="color:#fbbf24;"></i> BetterForums Karma Leaderboard
                </span>
                <span style="font-size:11px; font-weight:normal; color:#94a3b8;">Ranked by total community karma</span>
            </div>

            <?php
            $all_users_q = mysqli_query($conn, "SELECT id, username, display_name, role, is_admin, is_mod, custom_badge, status_flair, avatar_data, created_at FROM users ORDER BY id ASC");
            $leaderboard = [];
            if ($all_users_q) {
                while ($u_row = mysqli_fetch_assoc($all_users_q)) {
                    $k_data = get_user_karma_details($u_row['id'], $conn);
                    $leaderboard[] = array_merge($u_row, $k_data);
                }
            }
            usort($leaderboard, function($a, $b) {
                if ($b['total'] === $a['total']) {
                    return $b['posts_cnt'] - $a['posts_cnt'];
                }
                return $b['total'] - $a['total'];
            });
            ?>

            <!-- Top 3 Podium Cards -->
            <?php if (!empty($leaderboard)): ?>
            <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(180px, 1fr)); gap:12px; margin-bottom:20px;">
                <?php 
                $podium_borders = [1 => 'border:2px solid #eab308; background:rgba(234,179,8,0.08);', 2 => 'border:2px solid #94a3b8; background:rgba(148,163,184,0.08);', 3 => 'border:2px solid #b45309; background:rgba(180,83,9,0.08);'];
                $medal_icons = [1 => '🥇 1st Place', 2 => '🥈 2nd Place', 3 => '🥉 3rd Place'];
                for ($podium_idx = 0; $podium_idx < min(3, count($leaderboard)); $podium_idx++): 
                    $p_user = $leaderboard[$podium_idx];
                    $rank_num = $podium_idx + 1;
                ?>
                    <div style="border-radius:8px; padding:14px 10px; text-align:center; <?php echo $podium_borders[$rank_num]; ?>">
                        <div style="font-size:11px; font-weight:bold; margin-bottom:6px; color:#f8fafc;"><?php echo $medal_icons[$rank_num]; ?></div>
                        <div style="margin-bottom:6px;"><?php echo render_avatar_img($p_user, 48); ?></div>
                        <a href="index.php?u=<?php echo urlencode($p_user['username']); ?>" style="font-weight:bold; font-size:13px; color:#38bdf8; display:block; margin-bottom:4px;">u/<?php echo htmlspecialchars($p_user['username'], ENT_QUOTES, 'UTF-8'); ?></a>
                        <div style="margin:4px 0;"><?php echo render_role_tag($p_user); ?></div>
                        <div style="font-size:16px; font-weight:800; color:#f8fafc; margin-top:6px;"><?php echo number_format($p_user['total']); ?> <span style="font-size:11px; font-weight:normal; color:#94a3b8;">karma</span></div>
                        <div style="font-size:10px; color:#94a3b8; margin-top:4px;"><?php echo $p_user['posts_cnt']; ?> posts &bull; <?php echo $p_user['comments_cnt']; ?> comments</div>
                    </div>
                <?php endfor; ?>
            </div>
            <?php endif; ?>

            <!-- Full Leaderboard Table -->
            <div style="background:#0f172a; border:1px solid #334155; border-radius:6px; overflow:hidden;">
                <table style="width:100%; border-collapse:collapse; font-size:11px;">
                    <thead>
                        <tr style="background:#1e293b; color:#94a3b8; text-align:left; border-bottom:1px solid #334155;">
                            <th style="padding:8px 10px; width:40px; text-align:center;">#</th>
                            <th style="padding:8px 10px;">User</th>
                            <th style="padding:8px 10px;">Role & Status</th>
                            <th style="padding:8px 10px; text-align:right;">Post Karma</th>
                            <th style="padding:8px 10px; text-align:right;">Comment Karma</th>
                            <th style="padding:8px 10px; text-align:right;">Total Karma</th>
                            <th style="padding:8px 10px; text-align:center;">Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($leaderboard as $l_rank => $l_row): 
                            $curr_rank = $l_rank + 1;
                        ?>
                            <tr style="border-bottom:1px solid #1e293b; <?php echo ($l_row['username'] === $curr_user['username']) ? 'background:rgba(56,189,248,0.08);' : ''; ?>">
                                <td style="padding:8px 10px; text-align:center; font-weight:bold; color:<?php echo ($curr_rank === 1) ? '#fbbf24' : (($curr_rank === 2) ? '#cbd5e1' : (($curr_rank === 3) ? '#f59e0b' : '#64748b')); ?>;">
                                    <?php echo $curr_rank; ?>
                                </td>
                                <td style="padding:8px 10px;">
                                    <div style="display:flex; align-items:center; gap:6px;">
                                        <?php echo render_avatar_img($l_row, 22); ?>
                                        <a href="index.php?u=<?php echo urlencode($l_row['username']); ?>" style="font-weight:600; color:#f8fafc;">u/<?php echo htmlspecialchars($l_row['username'], ENT_QUOTES, 'UTF-8'); ?></a>
                                    </div>
                                </td>
                                <td style="padding:8px 10px;">
                                    <?php echo render_role_tag($l_row); ?>
                                </td>
                                <td style="padding:8px 10px; text-align:right; color:#94a3b8;">
                                    <?php echo number_format($l_row['post_karma']); ?>
                                </td>
                                <td style="padding:8px 10px; text-align:right; color:#94a3b8;">
                                    <?php echo number_format($l_row['comment_karma']); ?>
                                </td>
                                <td style="padding:8px 10px; text-align:right; font-weight:bold; color:#38bdf8;">
                                    <?php echo number_format($l_row['total']); ?>
                                </td>
                                <td style="padding:8px 10px; text-align:center;">
                                    <a href="index.php?u=<?php echo urlencode($l_row['username']); ?>" style="color:#94a3b8; font-size:10px; text-decoration:none; padding:2px 6px; background:#1e293b; border-radius:4px; border:1px solid #334155;">View Profile</a>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>

        <?php elseif ($action === 'users'): ?>
            <?php
            $u_search = isset($_GET['uq']) ? trim($_GET['uq']) : '';
            $role_filter = isset($_GET['role']) ? trim($_GET['role']) : '';
            $user_sort = isset($_GET['usort']) ? trim($_GET['usort']) : 'karma_desc';

            $where_u = ["1=1"];
            if (!empty($u_search)) {
                $u_safe = mysqli_real_escape_string($conn, $u_search);
                $where_u[] = "(username LIKE '%$u_safe%' OR display_name LIKE '%$u_safe%' OR bio LIKE '%$u_safe%' OR status_flair LIKE '%$u_safe%')";
            }
            if (!empty($role_filter)) {
                if ($role_filter === 'OWNER') {
                    $where_u[] = "(role='OWNER' OR username='gollclock')";
                } elseif ($role_filter === 'ADMIN') {
                    $where_u[] = "(role='ADMIN' OR is_admin=1)";
                } elseif ($role_filter === 'MOD') {
                    $where_u[] = "(role='MOD' OR is_mod=1)";
                } elseif ($role_filter === 'USER') {
                    $where_u[] = "(role='USER' AND username!='gollclock' AND is_admin=0 AND is_mod=0)";
                }
            }

            $where_u_sql = implode(' AND ', $where_u);
            $users_raw_q = mysqli_query($conn, "SELECT id, username, display_name, role, is_admin, is_mod, custom_badge, status_flair, bio, avatar_data, created_at FROM users WHERE $where_u_sql");
            $user_list = [];
            if ($users_raw_q) {
                while ($u_row = mysqli_fetch_assoc($users_raw_q)) {
                    $k_data = get_user_karma_details($u_row['id'], $conn);
                    $user_list[] = array_merge($u_row, $k_data);
                }
            }

            usort($user_list, function($a, $b) use ($user_sort) {
                if ($user_sort === 'karma_desc') return $b['total'] - $a['total'];
                if ($user_sort === 'karma_asc') return $a['total'] - $b['total'];
                if ($user_sort === 'newest') return strtotime($b['created_at']) - strtotime($a['created_at']);
                if ($user_sort === 'oldest') return strtotime($a['created_at']) - strtotime($b['created_at']);
                if ($user_sort === 'alpha') return strcasecmp($a['username'], $b['username']);
                if ($user_sort === 'posts') return $b['posts_cnt'] - $a['posts_cnt'];
                return $b['total'] - $a['total'];
            });
            ?>
            <div style="font-size:14px; font-weight:bold; margin-bottom:12px; border-bottom:1px solid var(--bf-border); padding-bottom:6px; color:var(--bf-text); display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:8px;">
                <span style="display:flex; align-items:center; gap:6px;">
                    <i class="fa-solid fa-users" style="color:#38bdf8;"></i> User Search & Community Directory
                </span>
                <span style="font-size:11px; font-weight:normal; color:#94a3b8;">Found <?php echo count($user_list); ?> members</span>
            </div>

            <!-- Search & Filter Controls -->
            <div style="background:#0f172a; border:1px solid #334155; border-radius:6px; padding:12px; margin-bottom:16px;">
                <form method="GET" action="index.php" style="display:flex; gap:8px; flex-wrap:wrap; align-items:flex-end;">
                    <input type="hidden" name="action" value="users">
                    <div style="flex:2; min-width:180px;">
                        <label style="font-size:10px; font-weight:bold; display:block; margin-bottom:3px; color:#94a3b8;">Search username, bio, flair:</label>
                        <input type="text" name="uq" class="input-text" placeholder="Type username or keyword..." value="<?php echo htmlspecialchars($u_search, ENT_QUOTES, 'UTF-8'); ?>">
                    </div>
                    <div style="flex:1; min-width:130px;">
                        <label style="font-size:10px; font-weight:bold; display:block; margin-bottom:3px; color:#94a3b8;">Filter by Role:</label>
                        <select name="role" class="input-text" style="padding:5px 8px;">
                            <option value="">All Roles</option>
                            <option value="OWNER" <?php echo ($role_filter === 'OWNER') ? 'selected' : ''; ?>>Owner</option>
                            <option value="ADMIN" <?php echo ($role_filter === 'ADMIN') ? 'selected' : ''; ?>>Admin</option>
                            <option value="MOD" <?php echo ($role_filter === 'MOD') ? 'selected' : ''; ?>>Moderator</option>
                            <option value="USER" <?php echo ($role_filter === 'USER') ? 'selected' : ''; ?>>Regular Members</option>
                        </select>
                    </div>
                    <div style="flex:1; min-width:140px;">
                        <label style="font-size:10px; font-weight:bold; display:block; margin-bottom:3px; color:#94a3b8;">Sort by:</label>
                        <select name="usort" class="input-text" style="padding:5px 8px;">
                            <option value="karma_desc" <?php echo ($user_sort === 'karma_desc') ? 'selected' : ''; ?>>Highest Karma</option>
                            <option value="karma_asc" <?php echo ($user_sort === 'karma_asc') ? 'selected' : ''; ?>>Lowest Karma</option>
                            <option value="newest" <?php echo ($user_sort === 'newest') ? 'selected' : ''; ?>>Newest Joined</option>
                            <option value="oldest" <?php echo ($user_sort === 'oldest') ? 'selected' : ''; ?>>Oldest Joined</option>
                            <option value="alpha" <?php echo ($user_sort === 'alpha') ? 'selected' : ''; ?>>Username (A-Z)</option>
                            <option value="posts" <?php echo ($user_sort === 'posts') ? 'selected' : ''; ?>>Most Posts</option>
                        </select>
                    </div>
                    <div style="display:flex; gap:6px;">
                        <button type="submit" class="btn-reddit btn-reddit-primary" style="width:auto; padding:5px 14px;">Filter</button>
                        <a href="index.php?action=users" class="btn-reddit" style="width:auto; padding:5px 10px; text-decoration:none;">Reset</a>
                    </div>
                </form>
            </div>

            <!-- User Grid -->
            <?php if (empty($user_list)): ?>
                <p style="color:#94a3b8; text-align:center; padding:20px; font-style:italic;">No users found matching your search filter criteria.</p>
            <?php else: ?>
                <div style="display:grid; grid-template-columns:repeat(auto-fill, minmax(240px, 1fr)); gap:12px;">
                    <?php foreach ($user_list as $u): ?>
                        <div style="background:#0f172a; border:1px solid #334155; border-radius:6px; padding:12px; display:flex; flex-direction:column; justify-content:space-between;">
                            <div>
                                <div style="display:flex; align-items:center; gap:8px; margin-bottom:8px;">
                                    <?php echo render_avatar_img($u, 36); ?>
                                    <div style="flex:1; min-width:0;">
                                        <a href="index.php?u=<?php echo urlencode($u['username']); ?>" style="font-weight:bold; color:#f8fafc; font-size:12px; display:block; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">
                                            u/<?php echo htmlspecialchars($u['username'], ENT_QUOTES, 'UTF-8'); ?>
                                        </a>
                                        <?php if (!empty($u['display_name']) && $u['display_name'] !== $u['username']): ?>
                                            <div style="font-size:10px; color:#94a3b8; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;"><?php echo htmlspecialchars($u['display_name'], ENT_QUOTES, 'UTF-8'); ?></div>
                                        <?php endif; ?>
                                    </div>
                                </div>
                                <div style="margin-bottom:6px;"><?php echo render_role_tag($u); ?></div>
                                <?php if (!empty($u['status_flair'])): ?>
                                    <div style="font-size:10px; color:#38bdf8; font-weight:600; margin-bottom:4px;"><?php echo htmlspecialchars($u['status_flair'], ENT_QUOTES, 'UTF-8'); ?></div>
                                <?php endif; ?>
                                <?php if (!empty($u['bio'])): ?>
                                    <div style="font-size:10px; color:#cbd5e1; line-height:1.35; margin-bottom:6px; max-height:40px; overflow:hidden; text-overflow:ellipsis;"><?php echo htmlspecialchars($u['bio'], ENT_QUOTES, 'UTF-8'); ?></div>
                                <?php endif; ?>
                            </div>
                            <div style="border-top:1px solid #1e293b; padding-top:8px; margin-top:8px; display:flex; align-items:center; justify-content:space-between; font-size:10px; color:#94a3b8;">
                                <span><strong><?php echo number_format($u['total']); ?></strong> karma</span>
                                <div style="display:flex; gap:4px;">
                                    <a href="index.php?u=<?php echo urlencode($u['username']); ?>" style="color:#38bdf8; font-weight:600; text-decoration:none;">Profile &rarr;</a>
                                    <?php if ($is_staff): ?>
                                        <button type="button" onclick="openUserActionModal({id:<?php echo $u['id']; ?>, username:'<?php echo htmlspecialchars(addslashes($u['username']), ENT_QUOTES, 'UTF-8'); ?>', role:'<?php echo $u['role']; ?>', is_admin:<?php echo $u['is_admin'] ? 1 : 0; ?>, is_mod:<?php echo $u['is_mod'] ? 1 : 0; ?>, badge:'<?php echo htmlspecialchars(addslashes($u['custom_badge']), ENT_QUOTES, 'UTF-8'); ?>', avatar_data:'<?php echo htmlspecialchars(addslashes($u['avatar_data']), ENT_QUOTES, 'UTF-8'); ?>'})" style="background:#1e293b; border:1px solid #475569; color:#f8fafc; font-size:9px; padding:1px 5px; border-radius:3px; cursor:pointer;">🛡️</button>
                                    <?php endif; ?>
                                </div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>

        <?php elseif (!empty($view_user)): ?>
            <?php
            $vu_safe = mysqli_real_escape_string($conn, $view_user);
            $profile_q = mysqli_query($conn, "SELECT * FROM users WHERE username='$vu_safe'");
            $profile_user = mysqli_fetch_assoc($profile_q);
            if (!$profile_user):
            ?>
                <p style="color:#f87171;">User not found.</p>
            <?php else: 
                $p_karma = get_user_karma_details($profile_user['id'], $conn);
            ?>
                <div style="display:flex; gap:14px; align-items:flex-start; margin-bottom:14px; border-bottom:1px solid var(--bf-border); padding-bottom:14px;">
                    <?php echo render_avatar_img($profile_user, 64); ?>
                    <div style="flex:1;">
                        <div style="display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:8px;">
                            <h2 style="font-size:16px; color:var(--bf-text); margin:0; display:flex; align-items:center; gap:6px;">
                                u/<?php echo htmlspecialchars($profile_user['username'], ENT_QUOTES, 'UTF-8'); ?>
                                <?php if (!empty($profile_user['display_name']) && $profile_user['display_name'] !== $profile_user['username']): ?>
                                    <span style="font-size:12px; font-weight:normal; color:var(--bf-text-muted);">(<?php echo htmlspecialchars($profile_user['display_name'], ENT_QUOTES, 'UTF-8'); ?>)</span>
                                <?php endif; ?>
                                <?php echo render_role_tag($profile_user); ?>
                            </h2>
                            <?php if ($is_staff): ?>
                                <button type="button" class="btn-mod-toggle" onclick="toggleModRow('mod_row_profile_<?php echo $profile_user['id']; ?>')">🛡️ mod</button>
                            <?php endif; ?>
                        </div>
                        <?php if (!empty($profile_user['status_flair'])): ?>
                            <div style="font-size:11px; font-weight:bold; color:var(--bf-link); margin:2px 0;"><?php echo htmlspecialchars($profile_user['status_flair'], ENT_QUOTES, 'UTF-8'); ?></div>
                        <?php endif; ?>
                        <?php if (!empty($profile_user['bio'])): ?>
                            <div style="font-size:11px; color:var(--bf-text); margin:4px 0;"><?php echo nl2br(htmlspecialchars($profile_user['bio'], ENT_QUOTES, 'UTF-8')); ?></div>
                        <?php endif; ?>
                        <div style="font-size:11px; color:var(--bf-text-muted); margin-top:4px;">
                            <strong><?php echo number_format($p_karma['post_karma']); ?></strong> post karma &bull;
                            <strong><?php echo number_format($p_karma['comment_karma']); ?></strong> comment karma &bull;
                            Member since <?php echo date('M j, Y', strtotime($profile_user['created_at'])); ?>
                        </div>
                    </div>
                </div>

                <?php if ($is_staff): 
                    $is_user_banned_q = mysqli_query($conn, "SELECT id FROM moderation_actions WHERE target_username='{$profile_user['username']}' AND action_type='BAN' AND status='APPROVED'");
                    $is_user_banned = ($is_user_banned_q && mysqli_num_rows($is_user_banned_q) > 0);
                ?>
                <div id="mod_row_profile_<?php echo $profile_user['id']; ?>" class="mod-action-row" style="display:none; margin-bottom:14px;">
                    <span class="mod-row-label">🛡️ Profile Moderation:</span>
                    <?php if ($is_user_banned): ?>
                        <form method="POST" action="index.php" style="display:inline;">
                            <input type="hidden" name="action" value="unban_user">
                            <input type="hidden" name="target_user" value="<?php echo htmlspecialchars($profile_user['username'], ENT_QUOTES, 'UTF-8'); ?>">
                            <input type="hidden" name="redirect" value="<?php echo htmlspecialchars($_SERVER['REQUEST_URI'], ENT_QUOTES, 'UTF-8'); ?>">
                            <button type="submit" class="mod-btn-action mod-btn-success">✅ Unban User</button>
                        </form>
                    <?php else: ?>
                        <form method="POST" action="index.php" style="display:inline;" onsubmit="return confirm('Ban u/<?php echo htmlspecialchars($profile_user['username'], ENT_QUOTES, 'UTF-8'); ?> from BetterForums?');">
                            <input type="hidden" name="action" value="ban_user">
                            <input type="hidden" name="target_user" value="<?php echo htmlspecialchars($profile_user['username'], ENT_QUOTES, 'UTF-8'); ?>">
                            <input type="hidden" name="reason" value="Banned via profile moderation">
                            <input type="hidden" name="redirect" value="<?php echo htmlspecialchars($_SERVER['REQUEST_URI'], ENT_QUOTES, 'UTF-8'); ?>">
                            <button type="submit" class="mod-btn-action mod-btn-danger">🚫 Ban User</button>
                        </form>
                    <?php endif; ?>

                    <form method="POST" action="index.php" style="display:inline; display:flex; align-items:center; gap:4px;">
                        <input type="hidden" name="action" value="set_custom_badge">
                        <input type="hidden" name="target_user" value="<?php echo htmlspecialchars($profile_user['username'], ENT_QUOTES, 'UTF-8'); ?>">
                        <input type="hidden" name="redirect" value="<?php echo htmlspecialchars($_SERVER['REQUEST_URI'], ENT_QUOTES, 'UTF-8'); ?>">
                        <input type="text" name="badge" class="input-text" placeholder="Badge/flair" value="<?php echo htmlspecialchars($profile_user['custom_badge'], ENT_QUOTES, 'UTF-8'); ?>" style="padding:2px 6px; font-size:10px; width:100px;">
                        <button type="submit" class="mod-btn-action">🏷️ Set Badge</button>
                    </form>

                    <form method="POST" action="index.php" style="display:inline;" onsubmit="return confirm('Reset this user avatar and bio?');">
                        <input type="hidden" name="action" value="reset_user_avatar">
                        <input type="hidden" name="target_user" value="<?php echo htmlspecialchars($profile_user['username'], ENT_QUOTES, 'UTF-8'); ?>">
                        <input type="hidden" name="redirect" value="<?php echo htmlspecialchars($_SERVER['REQUEST_URI'], ENT_QUOTES, 'UTF-8'); ?>">
                        <button type="submit" class="mod-btn-action mod-btn-warning">🧹 Reset Avatar/Bio</button>
                    </form>
                </div>
                <?php endif; ?>

                <div class="tab-nav">
                    <a href="index.php?u=<?php echo urlencode($view_user); ?>&tab=posts" class="<?php echo ($view_tab === 'posts') ? 'active' : ''; ?>">Submitted Posts (<?php echo $p_karma['posts_cnt']; ?>)</a>
                    <a href="index.php?u=<?php echo urlencode($view_user); ?>&tab=comments" class="<?php echo ($view_tab === 'comments') ? 'active' : ''; ?>">Comments (<?php echo $p_karma['comments_cnt']; ?>)</a>
                </div>

                <?php
                if ($view_tab === 'comments') {
                    $u_comm_q = mysqli_query($conn, "SELECT c.*, p.title as post_title, p.id as post_id, s.name as sub_name FROM comments c JOIN posts p ON c.post_id=p.id JOIN subbetters s ON p.subbetter_id=s.id WHERE c.user_id={$profile_user['id']} AND c.is_deleted=0 ORDER BY c.id DESC");
                    if (mysqli_num_rows($u_comm_q) === 0) {
                        echo "<p style='color:#94a3b8; padding:10px;'>No comments submitted yet.</p>";
                    } else {
                        while ($cm = mysqli_fetch_assoc($u_comm_q)) {
                            $c_score = get_target_score('comment', $cm['id'], $conn);
                            echo "<div style='padding:8px; border-bottom:1px solid #334155;'>";
                            echo "<div style='font-size:10px; color:#94a3b8; margin-bottom:4px;'>Comment on <a href='index.php?post={$cm['post_id']}'><strong>" . htmlspecialchars($cm['post_title'], ENT_QUOTES, 'UTF-8') . "</strong></a> in <a href='index.php?b=" . urlencode($cm['sub_name']) . "'>r/{$cm['sub_name']}</a> &bull; {$c_score} points &bull; " . time_ago_str($cm['created_at']) . "</div>";
                            echo "<div style='font-size:11px;'>" . parse_custom_markdown($cm['content']) . "</div>";
                            echo "</div>";
                        }
                    }
                } else {
                    $u_posts_q = mysqli_query($conn, "SELECT p.*, s.name as sub_name, u.username, u.custom_badge, u.avatar_data FROM posts p JOIN subbetters s ON p.subbetter_id=s.id JOIN users u ON p.user_id=u.id WHERE p.user_id={$profile_user['id']} AND p.is_deleted=0 ORDER BY p.id DESC");
                    if (mysqli_num_rows($u_posts_q) === 0) {
                        echo "<p style='color:#94a3b8; padding:10px;'>No posts submitted yet.</p>";
                    } else {
                        while ($post = mysqli_fetch_assoc($u_posts_q)) {
                            $score = get_target_score('post', $post['id'], $conn);
                            $user_vote = isset($my_votes['post'][$post['id']]) ? $my_votes['post'][$post['id']] : 0;
                            $comm_cnt_q = mysqli_query($conn, "SELECT COUNT(*) as c FROM comments WHERE post_id={$post['id']} AND is_deleted=0");
                            $comm_cnt = ($cr = mysqli_fetch_assoc($comm_cnt_q)) ? intval($cr['c']) : 0;
                            $is_saved = in_array(intval($post['id']), $my_saved_pids);
                            ?>
                            <div class="post-item">
                                <div class="vote-box">
                                    <form method="POST" action="index.php">
                                        <input type="hidden" name="action" value="vote">
                                        <input type="hidden" name="type" value="post">
                                        <input type="hidden" name="id" value="<?php echo $post['id']; ?>">
                                        <input type="hidden" name="v" value="1">
                                        <input type="hidden" name="redirect" value="<?php echo htmlspecialchars($_SERVER['REQUEST_URI'], ENT_QUOTES, 'UTF-8'); ?>">
                                        <button type="submit" class="vote-btn up <?php echo ($user_vote === 1) ? 'active' : ''; ?>">&#9650;</button>
                                    </form>
                                    <span class="vote-score <?php echo ($user_vote === 1) ? 'upvoted' : (($user_vote === -1) ? 'downvoted' : ''); ?>"><?php echo $score; ?></span>
                                    <form method="POST" action="index.php">
                                        <input type="hidden" name="action" value="vote">
                                        <input type="hidden" name="type" value="post">
                                        <input type="hidden" name="id" value="<?php echo $post['id']; ?>">
                                        <input type="hidden" name="v" value="-1">
                                        <input type="hidden" name="redirect" value="<?php echo htmlspecialchars($_SERVER['REQUEST_URI'], ENT_QUOTES, 'UTF-8'); ?>">
                                        <button type="submit" class="vote-btn down <?php echo ($user_vote === -1) ? 'active' : ''; ?>">&#9660;</button>
                                    </form>
                                </div>
                                <div class="post-body-col">
                                    <?php if (!empty($post['flair'])): ?>
                                        <span class="post-flair"><?php echo htmlspecialchars($post['flair'], ENT_QUOTES, 'UTF-8'); ?></span>
                                    <?php endif; ?>
                                    <a href="index.php?post=<?php echo $post['id']; ?>" class="post-title-link"><?php echo htmlspecialchars($post['title'], ENT_QUOTES, 'UTF-8'); ?></a>
                                    <?php if (!empty($post['link_url'])): ?>
                                        <a href="<?php echo htmlspecialchars($post['link_url'], ENT_QUOTES, 'UTF-8'); ?>" target="_blank" rel="noopener" class="post-domain">(<?php echo parse_url($post['link_url'], PHP_URL_HOST); ?>)</a>
                                    <?php endif; ?>
                                    <div class="post-meta">
                                        submitted <?php echo time_ago_str($post['created_at']); ?> by
                                        <a href="index.php?u=<?php echo urlencode($post['username']); ?>">u/<?php echo htmlspecialchars($post['username'], ENT_QUOTES, 'UTF-8'); ?></a>
                                        to <a href="index.php?b=<?php echo urlencode($post['sub_name']); ?>">r/<?php echo htmlspecialchars($post['sub_name'], ENT_QUOTES, 'UTF-8'); ?></a>
                                    </div>
                                    <div class="post-actions">
                                        <a href="index.php?post=<?php echo $post['id']; ?>"><?php echo $comm_cnt; ?> comments</a>
                                        <a href="javascript:void(0)" onclick="copyPostLink(window.location.origin + window.location.pathname + '?post=<?php echo $post['id']; ?>')">share</a>
                                        <form method="POST" action="index.php" style="display:inline;">
                                            <input type="hidden" name="action" value="save_post">
                                            <input type="hidden" name="post_id" value="<?php echo $post['id']; ?>">
                                            <input type="hidden" name="redirect" value="<?php echo htmlspecialchars($_SERVER['REQUEST_URI'], ENT_QUOTES, 'UTF-8'); ?>">
                                            <button type="submit"><?php echo $is_saved ? 'unsave' : 'save'; ?></button>
                                        </form>
                                        <?php if ($is_staff): ?>
                                            <button type="button" class="btn-mod-toggle" onclick="toggleModRow('mod_row_prof_post_<?php echo $post['id']; ?>')">🛡️ mod</button>
                                        <?php endif; ?>
                                    </div>
                                    <?php if ($is_staff): ?>
                                    <div id="mod_row_prof_post_<?php echo $post['id']; ?>" class="mod-action-row" style="display:none;">
                                        <span class="mod-row-label">🛡️ Mod:</span>
                                        <form method="POST" action="index.php" style="display:inline;">
                                            <input type="hidden" name="action" value="pin_post">
                                            <input type="hidden" name="post_id" value="<?php echo $post['id']; ?>">
                                            <input type="hidden" name="val" value="<?php echo (intval($post['is_pinned']) === 1) ? 0 : 1; ?>">
                                            <input type="hidden" name="redirect" value="<?php echo htmlspecialchars($_SERVER['REQUEST_URI'], ENT_QUOTES, 'UTF-8'); ?>">
                                            <button type="submit" class="mod-btn-action <?php echo (intval($post['is_pinned']) === 1) ? 'mod-btn-warning' : 'mod-btn-success'; ?>"><?php echo (intval($post['is_pinned']) === 1) ? '📌 Unpin' : '📌 Pin'; ?></button>
                                        </form>
                                        <form method="POST" action="index.php" style="display:inline;">
                                            <input type="hidden" name="action" value="lock_post">
                                            <input type="hidden" name="post_id" value="<?php echo $post['id']; ?>">
                                            <input type="hidden" name="val" value="<?php echo (intval($post['is_locked']) === 1) ? 0 : 1; ?>">
                                            <input type="hidden" name="redirect" value="<?php echo htmlspecialchars($_SERVER['REQUEST_URI'], ENT_QUOTES, 'UTF-8'); ?>">
                                            <button type="submit" class="mod-btn-action"><?php echo (intval($post['is_locked']) === 1) ? '🔓 Unlock' : '🔒 Lock'; ?></button>
                                        </form>
                                        <form method="POST" action="index.php" style="display:inline;" onsubmit="return confirm('Delete this post?');">
                                            <input type="hidden" name="action" value="delete_post">
                                            <input type="hidden" name="post_id" value="<?php echo $post['id']; ?>">
                                            <button type="submit" class="mod-btn-action mod-btn-danger">🗑️ Delete</button>
                                        </form>
                                    </div>
                                    <?php endif; ?>
                                </div>
                            </div>
                            <?php
                        }
                    }
                }
            endif; ?>

        <?php elseif ($view_post_id > 0): ?>
            <?php
            $post_q = mysqli_query($conn, "SELECT p.*, s.name as sub_name, s.description as sub_desc, u.username, u.display_name, u.role, u.is_admin, u.is_mod, u.custom_badge, u.avatar_data FROM posts p JOIN subbetters s ON p.subbetter_id=s.id JOIN users u ON p.user_id=u.id WHERE p.id=$view_post_id");
            $post = mysqli_fetch_assoc($post_q);
            if (!$post || intval($post['is_deleted']) === 1):
            ?>
                <p style="color:#f87171; padding:10px;">This post has been removed or does not exist.</p>
            <?php else: 
                $score = get_target_score('post', $post['id'], $conn);
                $user_vote = isset($my_votes['post'][$post['id']]) ? $my_votes['post'][$post['id']] : 0;
                $is_saved = in_array(intval($post['id']), $my_saved_pids);
            ?>
                <div style="margin-bottom:10px; font-size:11px;">
                    <a href="index.php">&larr; Back to all posts</a> &bull;
                    <a href="index.php?b=<?php echo urlencode($post['sub_name']); ?>">r/<?php echo htmlspecialchars($post['sub_name'], ENT_QUOTES, 'UTF-8'); ?></a>
                </div>

                <div class="post-item" style="border-bottom:none; margin-bottom:14px;">
                    <div class="vote-box">
                        <form method="POST" action="index.php" class="ajax-vote-form">
                            <input type="hidden" name="action" value="vote">
                            <input type="hidden" name="type" value="post">
                            <input type="hidden" name="id" value="<?php echo $post['id']; ?>">
                            <input type="hidden" name="v" value="1">
                            <button type="submit" class="vote-btn up <?php echo ($user_vote === 1) ? 'active' : ''; ?>">&#9650;</button>
                        </form>
                        <span class="vote-score <?php echo ($user_vote === 1) ? 'upvoted' : (($user_vote === -1) ? 'downvoted' : ''); ?>"><?php echo $score; ?></span>
                        <form method="POST" action="index.php" class="ajax-vote-form">
                            <input type="hidden" name="action" value="vote">
                            <input type="hidden" name="type" value="post">
                            <input type="hidden" name="id" value="<?php echo $post['id']; ?>">
                            <input type="hidden" name="v" value="-1">
                            <button type="submit" class="vote-btn down <?php echo ($user_vote === -1) ? 'active' : ''; ?>">&#9660;</button>
                        </form>
                    </div>
                    <div class="post-body-col">
                        <?php if (!empty($post['flair'])): ?>
                            <span class="post-flair"><?php echo htmlspecialchars($post['flair'], ENT_QUOTES, 'UTF-8'); ?></span>
                        <?php endif; ?>
                        <h1 style="font-size:16px; font-weight:bold; color:#f8fafc; margin-bottom:4px;">
                            <?php echo htmlspecialchars($post['title'], ENT_QUOTES, 'UTF-8'); ?>
                            <?php if (!empty($post['link_url'])): ?>
                                <a href="<?php echo htmlspecialchars($post['link_url'], ENT_QUOTES, 'UTF-8'); ?>" target="_blank" rel="noopener" class="post-domain">(<?php echo parse_url($post['link_url'], PHP_URL_HOST); ?>) &#x2197;</a>
                            <?php endif; ?>
                        </h1>
                        <div class="post-meta">
                            submitted <?php echo time_ago_str($post['created_at']); ?> by
                            <?php echo render_avatar_img($post, 14); ?>
                            <a href="index.php?u=<?php echo urlencode($post['username']); ?>">u/<?php echo htmlspecialchars($post['username'], ENT_QUOTES, 'UTF-8'); ?></a>
                            <?php echo render_role_tag($post); ?>
                            to <a href="index.php?b=<?php echo urlencode($post['sub_name']); ?>">r/<?php echo htmlspecialchars($post['sub_name'], ENT_QUOTES, 'UTF-8'); ?></a>
                            <?php if (intval($post['is_pinned']) === 1): ?><strong style="color:#34d399; margin-left:6px;">[Pinned Announcement]</strong><?php endif; ?>
                            <?php if (intval($post['is_locked']) === 1): ?><strong style="color:#f87171; margin-left:6px;">[Locked Thread]</strong><?php endif; ?>
                        </div>

                        <?php if (!empty($post['content'])): ?>
                            <div style="font-size:11px; line-height:1.45; margin:12px 0; background:#0f172a; padding:12px; border:1px solid #334155; border-radius:6px;">
                                <?php echo parse_custom_markdown($post['content']); ?>
                            </div>
                        <?php endif; ?>

                        <?php if (!empty($post['image_url'])): ?>
                            <div style="margin:12px 0; max-width:100%;">
                                <img src="<?php echo htmlspecialchars($post['image_url'], ENT_QUOTES, 'UTF-8'); ?>" alt="Post image" style="max-width:100%; max-height:560px; border-radius:6px; border:1px solid #334155; display:block;">
                            </div>
                        <?php endif; ?>

                        <div class="post-actions" style="margin-top:10px;">
                            <a href="javascript:void(0)" onclick="copyPostLink(window.location.href)">share link</a>
                            <form method="POST" action="index.php" style="display:inline;">
                                <input type="hidden" name="action" value="save_post">
                                <input type="hidden" name="post_id" value="<?php echo $post['id']; ?>">
                                <input type="hidden" name="redirect" value="<?php echo htmlspecialchars($_SERVER['REQUEST_URI'], ENT_QUOTES, 'UTF-8'); ?>">
                                <button type="submit"><?php echo $is_saved ? 'unsave' : 'save'; ?></button>
                            </form>
                            <a href="#report_modal" onclick="document.getElementById('report_box').style.display='block';">report</a>
                            <?php if ($is_staff): ?>
                                <button type="button" class="btn-mod-toggle" onclick="toggleModRow('mod_row_single_post_<?php echo $post['id']; ?>')">🛡️ mod</button>
                            <?php endif; ?>
                        </div>

                        <?php if ($is_staff): ?>
                        <div id="mod_row_single_post_<?php echo $post['id']; ?>" class="mod-action-row" style="display:none;">
                            <span class="mod-row-label">🛡️ Post Moderation:</span>
                            <form method="POST" action="index.php" style="display:inline;">
                                <input type="hidden" name="action" value="pin_post">
                                <input type="hidden" name="post_id" value="<?php echo $post['id']; ?>">
                                <input type="hidden" name="val" value="<?php echo (intval($post['is_pinned']) === 1) ? 0 : 1; ?>">
                                <input type="hidden" name="redirect" value="<?php echo htmlspecialchars($_SERVER['REQUEST_URI'], ENT_QUOTES, 'UTF-8'); ?>">
                                <button type="submit" class="mod-btn-action <?php echo (intval($post['is_pinned']) === 1) ? 'mod-btn-warning' : 'mod-btn-success'; ?>"><?php echo (intval($post['is_pinned']) === 1) ? '📌 Unpin Post' : '📌 Pin Post'; ?></button>
                            </form>
                            <form method="POST" action="index.php" style="display:inline;">
                                <input type="hidden" name="action" value="lock_post">
                                <input type="hidden" name="post_id" value="<?php echo $post['id']; ?>">
                                <input type="hidden" name="val" value="<?php echo (intval($post['is_locked']) === 1) ? 0 : 1; ?>">
                                <input type="hidden" name="redirect" value="<?php echo htmlspecialchars($_SERVER['REQUEST_URI'], ENT_QUOTES, 'UTF-8'); ?>">
                                <button type="submit" class="mod-btn-action <?php echo (intval($post['is_locked']) === 1) ? 'mod-btn-warning' : 'mod-btn-action'; ?>"><?php echo (intval($post['is_locked']) === 1) ? '🔓 Unlock Thread' : '🔒 Lock Thread'; ?></button>
                            </form>
                            <form method="POST" action="index.php" style="display:inline;" onsubmit="return confirm('Delete this post?');">
                                <input type="hidden" name="action" value="delete_post">
                                <input type="hidden" name="post_id" value="<?php echo $post['id']; ?>">
                                <button type="submit" class="mod-btn-action mod-btn-danger">🗑️ Delete Post</button>
                            </form>
                            <form method="POST" action="index.php" style="display:inline;" onsubmit="return confirm('Ban user u/<?php echo htmlspecialchars($post['username'], ENT_QUOTES, 'UTF-8'); ?>?');">
                                <input type="hidden" name="action" value="ban_user">
                                <input type="hidden" name="target_user" value="<?php echo htmlspecialchars($post['username'], ENT_QUOTES, 'UTF-8'); ?>">
                                <input type="hidden" name="reason" value="Banned via post moderation">
                                <button type="submit" class="mod-btn-action mod-btn-danger">🚫 Ban Author</button>
                            </form>
                            <a href="index.php?u=<?php echo urlencode($post['username']); ?>" class="mod-btn-action">👤 Author Profile</a>
                        </div>
                        <?php endif; ?>

                        <div id="report_box" style="display:none; margin-top:10px; background:rgba(239,68,68,0.15); border:1px solid #ef4444; padding:10px; border-radius:6px;">
                            <form method="POST" action="index.php">
                                <input type="hidden" name="action" value="report">
                                <input type="hidden" name="target_user" value="<?php echo htmlspecialchars($post['username'], ENT_QUOTES, 'UTF-8'); ?>">
                                <input type="hidden" name="sub_id" value="<?php echo $post['subbetter_id']; ?>">
                                <label style="font-weight:bold; font-size:11px; color:#fca5a5;">Reason for reporting this post:</label>
                                <input type="text" name="reason" class="input-text" placeholder="Spam, harassment, rule violation..." required style="margin:6px 0;">
                                <button type="submit" style="background:#ef4444; color:#fff; border:none; padding:4px 10px; font-size:11px; cursor:pointer; border-radius:4px; font-weight:bold;">Submit Report</button>
                                <button type="button" onclick="document.getElementById('report_box').style.display='none';" style="background:#334155; border:1px solid #475569; color:#f8fafc; padding:4px 10px; font-size:11px; cursor:pointer; border-radius:4px;">Cancel</button>
                            </form>
                        </div>
                    </div>
                </div>

                <div style="border-top:1px solid #334155; padding-top:14px; margin-top:14px;">
                    <h3 style="font-size:13px; font-weight:bold; margin-bottom:10px; color:#f8fafc;">Comments</h3>
                    
                    <?php if (intval($post['is_locked']) === 1 && !$is_staff): ?>
                        <div class="alert-box alert-error">This post is locked. Comments are closed.</div>
                    <?php else: ?>
                        <form method="POST" action="index.php" id="post_comment_form" style="margin-bottom:16px;">
                            <input type="hidden" name="action" value="new_comment">
                            <input type="hidden" name="post_id" value="<?php echo $post['id']; ?>">
                            <div class="editor-toolbar">
                                <button type="button" class="tool-btn" onclick="insertFormat('**', '**', 'comment_editor')"><strong>B</strong></button>
                                <button type="button" class="tool-btn" onclick="insertFormat('*', '*', 'comment_editor')"><em>I</em></button>
                                <button type="button" class="tool-btn" onclick="insertFormat('[2x]', '[/2x]', 'comment_editor')" style="color:#38bdf8; font-weight:bold;" title="Scale text 2X size">2X Size</button>
                                <button type="button" class="tool-btn" onclick="insertFormat('~~', '~~', 'comment_editor')"><del>S</del></button>
                                <button type="button" class="tool-btn" onclick="insertFormat('`', '`', 'comment_editor')">Code</button>
                                <button type="button" class="tool-btn" onclick="insertFormat('> ', '', 'comment_editor')">Quote</button>
                                <button type="button" class="tool-btn" onclick="insertFormat('[', '](https://)', 'comment_editor')">Link</button>
                            </div>
                            <textarea id="comment_editor" name="content" rows="4" placeholder="What are your thoughts?" required style="margin-bottom:6px;" oninput="updateLivePreview('comment_editor', 'comment_preview_box')"></textarea>
                            
                            <div style="margin-bottom:8px;">
                                <div style="font-weight:bold; font-size:10px; color:#94a3b8; margin-bottom:2px;">Live Comment Preview:</div>
                                <div id="comment_preview_box" style="min-height:30px; max-height:140px; overflow-y:auto; background:#0f172a; border:1px dashed #334155; padding:8px; border-radius:6px; font-size:11px; line-height:1.4;">
                                    <em style="color:#64748b;">Preview appears here as you type...</em>
                                </div>
                            </div>
                            
                            <button type="submit" id="submit_comment_btn" class="btn-reddit btn-reddit-primary" style="width:auto; padding:5px 16px; display:inline-block;">Post Comment</button>
                        </form>
                    <?php endif; ?>

                    <div id="comments_container" data-post-id="<?php echo $post['id']; ?>">
                    <?php
                    $comments_q = mysqli_query($conn, "SELECT c.*, u.username, u.role, u.is_admin, u.is_mod, u.custom_badge, u.avatar_data FROM comments c JOIN users u ON c.user_id=u.id WHERE c.post_id={$post['id']} AND c.is_deleted=0 ORDER BY c.id ASC");
                    if (mysqli_num_rows($comments_q) === 0):
                    ?>
                        <p id="no_comments_msg" style="color:#888; font-style:italic; padding:10px 0;">No comments yet. Be the first to comment!</p>
                    <?php else: 
                        while ($cm = mysqli_fetch_assoc($comments_q)):
                            $c_score = get_target_score('comment', $cm['id'], $conn);
                            $c_vote = isset($my_votes['comment'][$cm['id']]) ? $my_votes['comment'][$cm['id']] : 0;
                    ?>
                        <div class="comment-block" id="comment_block_<?php echo $cm['id']; ?>" data-comment-id="<?php echo $cm['id']; ?>">
                            <div class="comment-meta">
                                <?php echo render_avatar_img($cm, 14); ?>
                                <a href="index.php?u=<?php echo urlencode($cm['username']); ?>"><strong>u/<?php echo htmlspecialchars($cm['username'], ENT_QUOTES, 'UTF-8'); ?></strong></a>
                                <?php echo render_role_tag($cm); ?>
                                &bull; <span class="comment-score-val"><?php echo $c_score; ?> points</span> &bull; <?php echo time_ago_str($cm['created_at']); ?>
                            </div>
                            <div class="comment-text">
                                <?php echo parse_custom_markdown($cm['content']); ?>
                            </div>
                            <div class="post-actions">
                                <a href="javascript:void(0)" onclick="replyToComment('<?php echo htmlspecialchars(addslashes($cm['username']), ENT_QUOTES, 'UTF-8'); ?>')">reply</a>
                                <form method="POST" action="index.php" class="ajax-vote-form" style="display:inline;">
                                    <input type="hidden" name="action" value="vote">
                                    <input type="hidden" name="type" value="comment">
                                    <input type="hidden" name="id" value="<?php echo $cm['id']; ?>">
                                    <input type="hidden" name="v" value="1">
                                    <button type="submit" style="<?php echo ($c_vote === 1) ? 'color:#38bdf8;' : ''; ?>">&#9650; upvote</button>
                                </form>
                                <form method="POST" action="index.php" class="ajax-vote-form" style="display:inline;">
                                    <input type="hidden" name="action" value="vote">
                                    <input type="hidden" name="type" value="comment">
                                    <input type="hidden" name="id" value="<?php echo $cm['id']; ?>">
                                    <input type="hidden" name="v" value="-1">
                                    <button type="submit" style="<?php echo ($c_vote === -1) ? 'color:#818cf8;' : ''; ?>">&#9660; downvote</button>
                                </form>
                                <?php if ($is_staff): ?>
                                    <button type="button" class="btn-mod-toggle" onclick="toggleModRow('mod_row_comm_<?php echo $cm['id']; ?>')">🛡️ mod</button>
                                <?php endif; ?>
                            </div>
                            <?php if ($is_staff): ?>
                            <div id="mod_row_comm_<?php echo $cm['id']; ?>" class="mod-action-row" style="display:none;">
                                <span class="mod-row-label">🛡️ Comment Mod:</span>
                                <form method="POST" action="index.php" style="display:inline;" onsubmit="return confirm('Delete this comment?');">
                                    <input type="hidden" name="action" value="delete_comment">
                                    <input type="hidden" name="comment_id" value="<?php echo $cm['id']; ?>">
                                    <input type="hidden" name="redirect" value="<?php echo htmlspecialchars($_SERVER['REQUEST_URI'], ENT_QUOTES, 'UTF-8'); ?>">
                                    <button type="submit" class="mod-btn-action mod-btn-danger">🗑️ Delete</button>
                                </form>
                                <form method="POST" action="index.php" style="display:inline;" onsubmit="return confirm('Ban user u/<?php echo htmlspecialchars($cm['username'], ENT_QUOTES, 'UTF-8'); ?>?');">
                                    <input type="hidden" name="action" value="ban_user">
                                    <input type="hidden" name="target_user" value="<?php echo htmlspecialchars($cm['username'], ENT_QUOTES, 'UTF-8'); ?>">
                                    <input type="hidden" name="reason" value="Banned via comment moderation">
                                    <button type="submit" class="mod-btn-action mod-btn-danger">🚫 Ban u/<?php echo htmlspecialchars($cm['username'], ENT_QUOTES, 'UTF-8'); ?></button>
                                </form>
                                <a href="index.php?u=<?php echo urlencode($cm['username']); ?>" class="mod-btn-action">👤 Profile</a>
                            </div>
                            <?php endif; ?>
                        </div>
                    <?php endwhile; endif; ?>
                    </div>
                </div>
            <?php endif; ?>

        <?php elseif ($action === 'saved'): ?>
            <div style="font-size:14px; font-weight:bold; margin-bottom:12px; border-bottom:1px solid var(--bf-border); padding-bottom:6px; color:var(--bf-text);">
                Your Saved Posts
            </div>
            <?php
            $saved_q = mysqli_query($conn, "SELECT p.*, s.name as sub_name, u.username, u.role, u.is_admin, u.is_mod, u.custom_badge, u.avatar_data FROM saved_posts sp JOIN posts p ON sp.post_id=p.id JOIN subbetters s ON p.subbetter_id=s.id JOIN users u ON p.user_id=u.id WHERE sp.user_id={$curr_user['id']} AND p.is_deleted=0 ORDER BY sp.id DESC");
            if (mysqli_num_rows($saved_q) === 0):
            ?>
                <p style="color:#94a3b8; padding:10px;">You have no saved posts yet. Click "save" on any post to bookmark it here!</p>
            <?php else:
                while ($post = mysqli_fetch_assoc($saved_q)):
                    $score = get_target_score('post', $post['id'], $conn);
                    $user_vote = isset($my_votes['post'][$post['id']]) ? $my_votes['post'][$post['id']] : 0;
            ?>
                <div class="post-item">
                    <div class="vote-box">
                        <span class="vote-score"><?php echo $score; ?></span>
                    </div>
                    <div class="post-body-col">
                        <a href="index.php?post=<?php echo $post['id']; ?>" class="post-title-link"><?php echo htmlspecialchars($post['title'], ENT_QUOTES, 'UTF-8'); ?></a>
                        <div class="post-meta">
                            submitted <?php echo time_ago_str($post['created_at']); ?> by
                            <?php echo render_avatar_img($post, 14); ?>
                            <a href="index.php?u=<?php echo urlencode($post['username']); ?>">u/<?php echo htmlspecialchars($post['username'], ENT_QUOTES, 'UTF-8'); ?></a>
                            <?php echo render_role_tag($post); ?>
                            to <a href="index.php?b=<?php echo urlencode($post['sub_name']); ?>">r/<?php echo htmlspecialchars($post['sub_name'], ENT_QUOTES, 'UTF-8'); ?></a>
                        </div>
                        <div class="post-actions">
                            <a href="index.php?post=<?php echo $post['id']; ?>">view post & comments</a>
                            <form method="POST" action="index.php" style="display:inline;">
                                <input type="hidden" name="action" value="save_post">
                                <input type="hidden" name="post_id" value="<?php echo $post['id']; ?>">
                                <input type="hidden" name="redirect" value="index.php?action=saved">
                                <button type="submit">remove from saved</button>
                            </form>
                            <?php if ($is_staff): ?>
                                <button type="button" class="btn-mod-toggle" onclick="toggleModRow('mod_row_saved_<?php echo $post['id']; ?>')">🛡️ mod</button>
                            <?php endif; ?>
                        </div>
                        <?php if ($is_staff): ?>
                        <div id="mod_row_saved_<?php echo $post['id']; ?>" class="mod-action-row" style="display:none;">
                            <span class="mod-row-label">🛡️ Mod:</span>
                            <form method="POST" action="index.php" style="display:inline;" onsubmit="return confirm('Delete this post?');">
                                <input type="hidden" name="action" value="delete_post">
                                <input type="hidden" name="post_id" value="<?php echo $post['id']; ?>">
                                <button type="submit" class="mod-btn-action mod-btn-danger">🗑️ Delete</button>
                            </form>
                            <a href="index.php?u=<?php echo urlencode($post['username']); ?>" class="mod-btn-action">👤 Author Profile</a>
                        </div>
                        <?php endif; ?>
                    </div>
                </div>
            <?php endwhile; endif; ?>

        <?php else: ?>
            <div class="sort-bar">
                <div class="sort-links">
                    <span style="font-weight:bold; font-size:11px; margin-right:4px; color:#94a3b8;">view:</span>
                    <a href="index.php?<?php echo ($current_sub ? "b={$current_sub['name']}&" : "") . ($feed_mode ? "feed={$feed_mode}&" : ""); ?>sort=hot" class="sort-link <?php echo ($sort_mode === 'hot') ? 'active' : ''; ?>">hot</a>
                    <a href="index.php?<?php echo ($current_sub ? "b={$current_sub['name']}&" : "") . ($feed_mode ? "feed={$feed_mode}&" : ""); ?>sort=new" class="sort-link <?php echo ($sort_mode === 'new') ? 'active' : ''; ?>">new</a>
                    <a href="index.php?<?php echo ($current_sub ? "b={$current_sub['name']}&" : "") . ($feed_mode ? "feed={$feed_mode}&" : ""); ?>sort=top" class="sort-link <?php echo ($sort_mode === 'top') ? 'active' : ''; ?>">top</a>
                </div>
                <?php if (!empty($search_q)): ?>
                    <div style="font-size:11px; color:#94a3b8;">
                        Search results for "<strong style="color:#f8fafc;"><?php echo htmlspecialchars($search_q, ENT_QUOTES, 'UTF-8'); ?></strong>" (<a href="index.php">clear</a>)
                    </div>
                <?php endif; ?>
            </div>

            <?php
            $where = ["p.is_deleted = 0"];
            if ($current_sub) {
                $where[] = "p.subbetter_id = " . intval($current_sub['id']);
            } elseif ($feed_mode === 'home') {
                if (!empty($my_sub_ids)) {
                    $where[] = "p.subbetter_id IN (" . implode(',', $my_sub_ids) . ")";
                } else {
                    $where[] = "p.subbetter_id = 0";
                }
            }

            if (!empty($search_q)) {
                $sq_safe = mysqli_real_escape_string($conn, $search_q);
                $where[] = "(p.title LIKE '%$sq_safe%' OR p.content LIKE '%$sq_safe%' OR u.username LIKE '%$sq_safe%')";
            }

            $where_sql = implode(' AND ', $where);

            $order_sql = "p.is_pinned DESC, p.id DESC";
            if ($sort_mode === 'new') {
                $order_sql = "p.is_pinned DESC, p.created_at DESC";
            } elseif ($sort_mode === 'top') {
                $order_sql = "p.is_pinned DESC, vote_total DESC, p.id DESC";
            }

            $sql = "SELECT p.*, s.name as sub_name, u.username, u.role, u.is_admin, u.is_mod, u.custom_badge, u.avatar_data,
                    (SELECT COALESCE(SUM(vote_type), 0) FROM user_votes WHERE target_type='post' AND target_id=p.id) as vote_total,
                    (SELECT COUNT(*) FROM comments WHERE post_id=p.id AND is_deleted=0) as comment_count
                    FROM posts p
                    JOIN subbetters s ON p.subbetter_id = s.id
                    JOIN users u ON p.user_id = u.id
                    WHERE $where_sql
                    ORDER BY $order_sql
                    LIMIT 50";

            $posts_res = mysqli_query($conn, $sql);
            if (!$posts_res || mysqli_num_rows($posts_res) === 0):
            ?>
                <div style="padding:30px 10px; text-align:center; color:#94a3b8;">
                    <?php if ($feed_mode === 'home' && empty($my_sub_ids)): ?>
                        <p style="font-size:13px; font-weight:bold; margin-bottom:6px; color:#f8fafc;">Your home feed is empty!</p>
                        <p>Join communities to see their posts here, or explore the <a href="index.php?feed=all">All</a> / <a href="index.php?feed=popular">Popular</a> feeds.</p>
                    <?php else: ?>
                        <p style="font-size:13px; font-weight:bold; margin-bottom:6px; color:#f8fafc;">there doesn't seem to be anything here</p>
                        <p><a href="index.php?action=submit<?php echo $current_sub ? '&b=' . urlencode($current_sub['name']) : ''; ?>">Be the first to submit a post!</a></p>
                    <?php endif; ?>
                </div>
            <?php else:
                $rank = 1;
                while ($post = mysqli_fetch_assoc($posts_res)):
                    $score = intval($post['vote_total']);
                    $comm_cnt = intval($post['comment_count']);
                    $user_vote = isset($my_votes['post'][$post['id']]) ? $my_votes['post'][$post['id']] : 0;
                    $is_saved = in_array(intval($post['id']), $my_saved_pids);
            ?>
                <div class="post-item <?php echo (intval($post['is_pinned']) === 1) ? 'is-pinned' : ''; ?>">
                    <span style="font-size:13px; font-weight:bold; color:#64748b; width:18px; text-align:right; margin-top:8px;"><?php echo $rank++; ?></span>
                    <div class="vote-box">
                        <form method="POST" action="index.php" class="ajax-vote-form">
                            <input type="hidden" name="action" value="vote">
                            <input type="hidden" name="type" value="post">
                            <input type="hidden" name="id" value="<?php echo $post['id']; ?>">
                            <input type="hidden" name="v" value="1">
                            <button type="submit" class="vote-btn up <?php echo ($user_vote === 1) ? 'active' : ''; ?>">&#9650;</button>
                        </form>
                        <span class="vote-score <?php echo ($user_vote === 1) ? 'upvoted' : (($user_vote === -1) ? 'downvoted' : ''); ?>"><?php echo $score; ?></span>
                        <form method="POST" action="index.php" class="ajax-vote-form">
                            <input type="hidden" name="action" value="vote">
                            <input type="hidden" name="type" value="post">
                            <input type="hidden" name="id" value="<?php echo $post['id']; ?>">
                            <input type="hidden" name="v" value="-1">
                            <button type="submit" class="vote-btn down <?php echo ($user_vote === -1) ? 'active' : ''; ?>">&#9660;</button>
                        </form>
                    </div>
                    <div class="post-body-col">
                        <?php if (!empty($post['flair'])): ?>
                            <span class="post-flair"><?php echo htmlspecialchars($post['flair'], ENT_QUOTES, 'UTF-8'); ?></span>
                        <?php endif; ?>
                        <a href="index.php?post=<?php echo $post['id']; ?>" class="post-title-link"><?php echo htmlspecialchars($post['title'], ENT_QUOTES, 'UTF-8'); ?></a>
                        <?php if (!empty($post['link_url'])): ?>
                            <a href="<?php echo htmlspecialchars($post['link_url'], ENT_QUOTES, 'UTF-8'); ?>" target="_blank" rel="noopener" class="post-domain">(<?php echo parse_url($post['link_url'], PHP_URL_HOST); ?>)</a>
                        <?php endif; ?>
                        <div class="post-meta">
                            submitted <?php echo time_ago_str($post['created_at']); ?> by
                            <?php echo render_avatar_img($post, 14); ?>
                            <a href="index.php?u=<?php echo urlencode($post['username']); ?>">u/<?php echo htmlspecialchars($post['username'], ENT_QUOTES, 'UTF-8'); ?></a>
                            <?php echo render_role_tag($post); ?>
                            to <a href="index.php?b=<?php echo urlencode($post['sub_name']); ?>"><strong>r/<?php echo htmlspecialchars($post['sub_name'], ENT_QUOTES, 'UTF-8'); ?></strong></a>
                            <?php if (intval($post['is_pinned']) === 1): ?><strong style="color:#34d399; margin-left:4px;">[Pinned]</strong><?php endif; ?>
                            <?php if (intval($post['is_locked']) === 1): ?><strong style="color:#f87171; margin-left:4px;">[Locked]</strong><?php endif; ?>
                        </div>
                        <div class="post-actions">
                            <a href="index.php?post=<?php echo $post['id']; ?>"><?php echo $comm_cnt; ?> comments</a>
                            <a href="javascript:void(0)" onclick="copyPostLink(window.location.origin + window.location.pathname + '?post=<?php echo $post['id']; ?>')">share</a>
                            <form method="POST" action="index.php" style="display:inline;">
                                <input type="hidden" name="action" value="save_post">
                                <input type="hidden" name="post_id" value="<?php echo $post['id']; ?>">
                                <input type="hidden" name="redirect" value="<?php echo htmlspecialchars($_SERVER['REQUEST_URI'], ENT_QUOTES, 'UTF-8'); ?>">
                                <button type="submit"><?php echo $is_saved ? 'unsave' : 'save'; ?></button>
                            </form>
                            <?php if ($is_staff): ?>
                                <button type="button" class="btn-mod-toggle" onclick="toggleModRow('mod_row_feed_post_<?php echo $post['id']; ?>')">🛡️ mod</button>
                            <?php endif; ?>
                        </div>
                        <?php if ($is_staff): ?>
                        <div id="mod_row_feed_post_<?php echo $post['id']; ?>" class="mod-action-row" style="display:none;">
                            <span class="mod-row-label">🛡️ Mod Actions:</span>
                            <form method="POST" action="index.php" style="display:inline;">
                                <input type="hidden" name="action" value="pin_post">
                                <input type="hidden" name="post_id" value="<?php echo $post['id']; ?>">
                                <input type="hidden" name="val" value="<?php echo (intval($post['is_pinned']) === 1) ? 0 : 1; ?>">
                                <input type="hidden" name="redirect" value="<?php echo htmlspecialchars($_SERVER['REQUEST_URI'], ENT_QUOTES, 'UTF-8'); ?>">
                                <button type="submit" class="mod-btn-action <?php echo (intval($post['is_pinned']) === 1) ? 'mod-btn-warning' : 'mod-btn-success'; ?>"><?php echo (intval($post['is_pinned']) === 1) ? '📌 Unpin' : '📌 Pin'; ?></button>
                            </form>
                            <form method="POST" action="index.php" style="display:inline;">
                                <input type="hidden" name="action" value="lock_post">
                                <input type="hidden" name="post_id" value="<?php echo $post['id']; ?>">
                                <input type="hidden" name="val" value="<?php echo (intval($post['is_locked']) === 1) ? 0 : 1; ?>">
                                <input type="hidden" name="redirect" value="<?php echo htmlspecialchars($_SERVER['REQUEST_URI'], ENT_QUOTES, 'UTF-8'); ?>">
                                <button type="submit" class="mod-btn-action"><?php echo (intval($post['is_locked']) === 1) ? '🔓 Unlock' : '🔒 Lock'; ?></button>
                            </form>
                            <form method="POST" action="index.php" style="display:inline;" onsubmit="return confirm('Delete this post permanently?');">
                                <input type="hidden" name="action" value="delete_post">
                                <input type="hidden" name="post_id" value="<?php echo $post['id']; ?>">
                                <button type="submit" class="mod-btn-action mod-btn-danger">🗑️ Delete Post</button>
                            </form>
                            <form method="POST" action="index.php" style="display:inline;" onsubmit="return confirm('Ban author u/<?php echo htmlspecialchars($post['username'], ENT_QUOTES, 'UTF-8'); ?>?');">
                                <input type="hidden" name="action" value="ban_user">
                                <input type="hidden" name="target_user" value="<?php echo htmlspecialchars($post['username'], ENT_QUOTES, 'UTF-8'); ?>">
                                <input type="hidden" name="reason" value="Banned via feed moderation">
                                <button type="submit" class="mod-btn-action mod-btn-danger">🚫 Ban u/<?php echo htmlspecialchars($post['username'], ENT_QUOTES, 'UTF-8'); ?></button>
                            </form>
                            <a href="index.php?u=<?php echo urlencode($post['username']); ?>" class="mod-btn-action">👤 Author Profile</a>
                        </div>
                        <?php endif; ?>
                    </div>
                </div>
            <?php endwhile; endif; ?>
        <?php endif; ?>
    </div>

    <div class="sidebar">
        <div class="sidebar-box">
            <form method="GET" action="index.php">
                <?php if ($current_sub): ?>
                    <input type="hidden" name="b" value="<?php echo htmlspecialchars($current_sub['name'], ENT_QUOTES, 'UTF-8'); ?>">
                <?php endif; ?>
                <input type="text" name="q" class="input-text" placeholder="Search BetterForums..." value="<?php echo htmlspecialchars($search_q, ENT_QUOTES, 'UTF-8'); ?>">
            </form>
        </div>

        <a href="index.php?action=submit<?php echo $current_sub ? '&b=' . urlencode($current_sub['name']) : ''; ?>" class="btn-reddit btn-reddit-primary">
            Submit a new post
        </a>
        <a href="index.php?action=create_community_page" class="btn-reddit">
            Create your own community
        </a>
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:6px; margin-bottom:10px;">
            <a href="index.php?action=leaderboard" class="btn-reddit" style="display:flex; align-items:center; justify-content:center; gap:5px; margin-bottom:0; background:rgba(251,191,36,0.08); border-color:rgba(251,191,36,0.3); color:#fbbf24; font-weight:600;">
                <i class="fa-solid fa-trophy"></i> Leaderboard
            </a>
            <a href="index.php?action=users" class="btn-reddit" style="display:flex; align-items:center; justify-content:center; gap:5px; margin-bottom:0; background:rgba(56,189,248,0.08); border-color:rgba(56,189,248,0.3); color:#38bdf8; font-weight:600;">
                <i class="fa-solid fa-users"></i> Users Filter
            </a>
        </div>

        <?php if ($current_sub): 
            $is_subbed = in_array(intval($current_sub['id']), $my_sub_ids);
            $sub_cnt_q = mysqli_query($conn, "SELECT COUNT(*) as c FROM subscriptions WHERE subbetter_id={$current_sub['id']}");
            $sub_cnt = ($scr = mysqli_fetch_assoc($sub_cnt_q)) ? intval($scr['c']) : 1;
        ?>
            <div class="sidebar-box">
                <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:8px;">
                    <span style="font-size:14px; font-weight:bold; color:var(--bf-text);">r/<?php echo htmlspecialchars($current_sub['name'], ENT_QUOTES, 'UTF-8'); ?></span>
                    <form method="POST" action="index.php" style="margin:0;">
                        <input type="hidden" name="action" value="toggle_sub">
                        <input type="hidden" name="sub_id" value="<?php echo $current_sub['id']; ?>">
                        <input type="hidden" name="redirect" value="<?php echo htmlspecialchars($_SERVER['REQUEST_URI'], ENT_QUOTES, 'UTF-8'); ?>">
                        <button type="submit" class="btn-reddit" style="padding:2px 10px; font-size:11px; <?php echo $is_subbed ? 'background:var(--bf-surface-2); color:var(--bf-text-muted);' : 'background:var(--bf-primary); color:#fff; border-color:var(--bf-primary);'; ?>">
                            <?php echo $is_subbed ? 'Joined' : 'Join'; ?>
                        </button>
                    </form>
                </div>
                <div style="font-size:11px; color:var(--bf-text-muted); margin-bottom:8px;">
                    <strong><?php echo number_format($sub_cnt); ?></strong> members
                </div>
                <p style="line-height:1.4; color:var(--bf-text); margin-bottom:8px;">
                    <?php echo htmlspecialchars($current_sub['description'] ? $current_sub['description'] : 'Welcome to r/' . $current_sub['name'] . '!', ENT_QUOTES, 'UTF-8'); ?>
                </p>
                <div style="font-size:10px; color:var(--bf-text-muted); border-top:1px solid var(--bf-border); padding-top:6px;">
                    Created by u/<?php echo htmlspecialchars($current_sub['created_by'], ENT_QUOTES, 'UTF-8'); ?> &bull; <?php echo date('M j, Y', strtotime($current_sub['created_at'])); ?>
                </div>
            </div>
        <?php endif; ?>

        <div class="sidebar-box">
            <div class="sidebar-title">Communities</div>
            <div style="display:flex; flex-direction:column; gap:4px;">
                <?php foreach ($all_subs as $sb): 
                    $is_joined = in_array(intval($sb['id']), $my_sub_ids);
                ?>
                    <div style="display:flex; align-items:center; justify-content:space-between; padding:2px 0;">
                        <a href="index.php?b=<?php echo urlencode($sb['name']); ?>" style="<?php echo ($current_sub && $current_sub['id'] == $sb['id']) ? 'font-weight:bold; color:var(--bf-link);' : ''; ?>">
                            r/<?php echo htmlspecialchars($sb['name'], ENT_QUOTES, 'UTF-8'); ?>
                        </a>
                        <span style="font-size:9px; color:var(--bf-text-muted);"><?php echo $is_joined ? '&#10003;' : ''; ?></span>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>

        <div class="sidebar-box" style="font-size:10px; color:var(--bf-text-muted); line-height:1.5;">
            <div style="font-weight:bold; color:var(--bf-text); margin-bottom:4px;">About BetterForums</div>
            <p>A classic, lightning-fast forum community built for discussion, links, and original content.</p>
            <div style="margin-top:6px; font-size:9px; color:var(--bf-text-muted);">
                &copy; <?php echo date('Y'); ?> BetterForums, Inc. All rights reserved.
            </div>
        </div>
    </div>
</div>

<div id="toast-container" class="toast-container"></div>

<!-- Control Panel Modal -->
<div id="admin-modal" class="modal-bg">
    <div class="modal-box">
        <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:16px; border-bottom:1px solid #1e293b; padding-bottom:12px;">
            <div style="display:flex; align-items:center; gap:8px;">
                <span style="display:inline-flex; align-items:center; justify-content:center; width:30px; height:30px; background:rgba(239,68,68,0.15); border:1px solid rgba(239,68,68,0.3); border-radius:8px; color:#f87171; font-size:14px;">
                    <i class="fa-solid fa-shield-halved"></i>
                </span>
                <div>
                    <h3 style="font-size:15px; font-weight:bold; color:#f8fafc; margin:0;">Control Panel</h3>
                    <span style="font-size:11px; color:#94a3b8;">System administration & moderation dashboard</span>
                </div>
            </div>
            <button onclick="closeModal('admin-modal')" style="background:transparent; border:none; color:#64748b; font-size:20px; cursor:pointer; padding:2px 6px;" onmouseover="this.style.color='#f8fafc'" onmouseout="this.style.color='#64748b'">&times;</button>
        </div>

        <div class="admin-tabs-nav">
            <button class="admin-tab-btn active" onclick="adminTab(this, 'a-users')"><i class="fa-solid fa-users"></i> Users</button>
            <button class="admin-tab-btn" onclick="adminTab(this, 'a-bans')"><i class="fa-solid fa-ban"></i> Bans</button>
            <button class="admin-tab-btn" onclick="adminTab(this, 'a-ban-tpl')"><i class="fa-solid fa-file-code"></i> Ban Tpl</button>
            <button class="admin-tab-btn" onclick="adminTab(this, 'a-announce')"><i class="fa-solid fa-bullhorn"></i> Announce</button>
            <button class="admin-tab-btn" onclick="adminTab(this, 'a-maint')"><i class="fa-solid fa-wrench"></i> Maintenance</button>
            <button class="admin-tab-btn" onclick="adminTab(this, 'a-clear-comm')"><i class="fa-solid fa-trash-can"></i> Clear Community</button>
            <button class="admin-tab-btn" onclick="adminTab(this, 'a-comm-mgr')"><i class="fa-solid fa-list"></i> Communities</button>
            <button class="admin-tab-btn" onclick="adminTab(this, 'a-stats')"><i class="fa-solid fa-chart-line"></i> Stats</button>
            <button class="admin-tab-btn" onclick="adminTab(this, 'a-purge')"><i class="fa-solid fa-broom"></i> Purge</button>
            <button class="admin-tab-btn" onclick="adminTab(this, 'a-settings')"><i class="fa-solid fa-sliders"></i> Settings</button>
            <button class="admin-tab-btn" onclick="adminTab(this, 'a-sessions')"><i class="fa-solid fa-network-wired"></i> Sessions</button>
            <?php if ($is_owner): ?>
                <button class="admin-tab-btn" onclick="adminTab(this, 'a-feedback')"><i class="fa-solid fa-comments"></i> Feedbacks</button>
                <button class="admin-tab-btn" onclick="adminTab(this, 'a-nitro')"><i class="fa-solid fa-bolt"></i> Nitro</button>
                <button class="admin-tab-btn" onclick="adminTab(this, 'a-roles')"><i class="fa-solid fa-user-gear"></i> Roles</button>
                <button class="admin-tab-btn" onclick="adminTab(this, 'a-overlay')"><i class="fa-solid fa-masks-theater"></i> Overlay</button>
            <?php endif; ?>
        </div>

        <!-- Section: Users -->
        <div id="a-users" class="admin-section active">
            <div style="display:flex; gap:8px; margin-bottom:12px;">
                <input type="text" id="admin-user-search" placeholder="Search by username or ID..." style="flex:1; background:#090d16; border:1px solid #1e293b; border-radius:6px; padding:7px 12px; color:#f8fafc; font-size:12px; outline:none;" oninput="loadAdminUsers(this.value)">
                <button onclick="loadAdminUsers(document.getElementById('admin-user-search').value)" style="background:#1e293b; color:#cbd5e1; border:1px solid #334155; border-radius:6px; padding:7px 14px; font-size:12px; font-weight:600; cursor:pointer;"><i class="fa-solid fa-rotate"></i> Refresh</button>
            </div>
            <div id="admin-users-list" style="max-height:360px; overflow-y:auto;">
                <p style="text-align:center; color:#64748b; font-style:italic; padding:20px;">Loading registered users...</p>
            </div>
        </div>

        <!-- Section: Bans -->
        <div id="a-bans" class="admin-section">
            <div style="display:flex; gap:8px; margin-bottom:12px;">
                <input type="text" id="admin-bans-search" placeholder="Search banned users..." style="flex:1; background:#090d16; border:1px solid #1e293b; border-radius:6px; padding:7px 12px; color:#f8fafc; font-size:12px; outline:none;" oninput="loadAdminBans(this.value)">
                <button onclick="loadAdminBans(document.getElementById('admin-bans-search').value)" style="background:#1e293b; color:#cbd5e1; border:1px solid #334155; border-radius:6px; padding:7px 14px; font-size:12px; font-weight:600; cursor:pointer;"><i class="fa-solid fa-rotate"></i> Refresh</button>
            </div>
            <div id="admin-bans-list" style="max-height:360px; overflow-y:auto;">
                <p style="text-align:center; color:#64748b; font-style:italic; padding:20px;">Loading banned accounts...</p>
            </div>
        </div>

        <!-- Section: Ban Template -->
        <div id="a-ban-tpl" class="admin-section">
            <div style="margin-bottom:10px; font-size:12px; color:#cbd5e1;">Custom Ban HTML Template:</div>
            <textarea id="ban-template-editor" style="width:100%; height:180px; background:#090d16; border:1px solid #1e293b; border-radius:8px; padding:10px; color:#f8fafc; font-family:monospace; font-size:12px; outline:none; resize:vertical; margin-bottom:10px;"></textarea>
            <button onclick="adminSaveBanTemplate()" style="background:#2563eb; color:#fff; border:none; border-radius:6px; padding:7px 16px; font-size:12px; font-weight:600; cursor:pointer;"><i class="fa-solid fa-floppy-disk"></i> Save Template</button>
        </div>

        <!-- Section: Announce -->
        <div id="a-announce" class="admin-section">
            <div style="margin-bottom:10px; font-size:12px; color:#cbd5e1;">Broadcast Community Announcement:</div>
            <textarea id="announce-input" placeholder="Type banner announcement message here..." style="width:100%; height:120px; background:#090d16; border:1px solid #1e293b; border-radius:8px; padding:10px; color:#f8fafc; font-size:12px; outline:none; resize:vertical; margin-bottom:10px;"><?php echo htmlspecialchars($announcement_banner, ENT_QUOTES, 'UTF-8'); ?></textarea>
            <div style="display:flex; gap:8px;">
                <button onclick="adminAnnounce()" style="background:#2563eb; color:#fff; border:none; border-radius:6px; padding:7px 16px; font-size:12px; font-weight:600; cursor:pointer;"><i class="fa-solid fa-paper-plane"></i> Dispatch to All</button>
                <button onclick="document.getElementById('announce-input').value=''; adminAnnounce();" style="background:#1e293b; color:#cbd5e1; border:1px solid #334155; border-radius:6px; padding:7px 16px; font-size:12px; font-weight:600; cursor:pointer;">Clear Banner</button>
            </div>
        </div>

        <!-- Section: Maintenance -->
        <div id="a-maint" class="admin-section">
            <div style="display:flex; align-items:center; justify-content:space-between; background:#090d16; border:1px solid #1e293b; border-radius:8px; padding:12px 16px; margin-bottom:14px;">
                <div>
                    <div style="font-weight:bold; color:#f8fafc; font-size:13px;">Maintenance Mode</div>
                    <div style="font-size:11px; color:#94a3b8;">When active, only staff/admins can access the forum.</div>
                </div>
                <label class="switch-toggle">
                    <input type="checkbox" id="maint-switch" onchange="toggleMaintenance(this.checked)">
                    <span class="switch-slider"></span>
                </label>
            </div>
            <div style="margin-bottom:8px; font-size:12px; color:#cbd5e1;">Custom Maintenance Message:</div>
            <textarea id="maint-msg-input" placeholder="Message shown to visitors during maintenance..." style="width:100%; height:100px; background:#090d16; border:1px solid #1e293b; border-radius:8px; padding:10px; color:#f8fafc; font-size:12px; outline:none; resize:vertical; margin-bottom:10px;"></textarea>
            <button onclick="saveMaintMsg()" style="background:#2563eb; color:#fff; border:none; border-radius:6px; padding:7px 16px; font-size:12px; font-weight:600; cursor:pointer;"><i class="fa-solid fa-floppy-disk"></i> Save Message</button>
        </div>

        <!-- Section: Clear Community -->
        <div id="a-clear-comm" class="admin-section">
            <div style="margin-bottom:10px; font-size:12px; color:#cbd5e1;">Select a community to clear all non-pinned posts:</div>
            <div style="display:flex; gap:8px; margin-bottom:14px;">
                <select id="clear-comm-select" style="flex:1; background:#090d16; border:1px solid #1e293b; border-radius:6px; padding:7px 12px; color:#f8fafc; font-size:12px; outline:none;">
                    <?php foreach ($all_subs as $sb): ?>
                        <option value="<?php echo $sb['id']; ?>">r/<?php echo htmlspecialchars($sb['name'], ENT_QUOTES, 'UTF-8'); ?></option>
                    <?php endforeach; ?>
                </select>
                <button onclick="adminClearChannel()" style="background:rgba(239,68,68,0.2); color:#f87171; border:1px solid rgba(239,68,68,0.4); border-radius:6px; padding:7px 16px; font-size:12px; font-weight:600; cursor:pointer;"><i class="fa-solid fa-trash-can"></i> Clear Community Posts</button>
            </div>
        </div>

        <!-- Section: Communities Manager -->
        <div id="a-comm-mgr" class="admin-section">
            <div style="background:#090d16; border:1px solid #1e293b; border-radius:8px; padding:12px; margin-bottom:14px;">
                <div style="font-weight:bold; font-size:12px; color:#f8fafc; margin-bottom:8px;">Add New Community</div>
                <div style="display:flex; gap:8px; margin-bottom:8px;">
                    <input type="text" id="new-comm-name" placeholder="Community name (e.g. technology)" style="flex:1; background:#0f172a; border:1px solid #334155; border-radius:6px; padding:6px 10px; color:#f8fafc; font-size:11px; outline:none;">
                    <input type="text" id="new-comm-desc" placeholder="Brief description" style="flex:2; background:#0f172a; border:1px solid #334155; border-radius:6px; padding:6px 10px; color:#f8fafc; font-size:11px; outline:none;">
                    <button onclick="adminAddChannel()" style="background:#2563eb; color:#fff; border:none; border-radius:6px; padding:6px 14px; font-size:11px; font-weight:600; cursor:pointer;"><i class="fa-solid fa-plus"></i> Create</button>
                </div>
            </div>
            <div id="admin-channels-list" style="max-height:280px; overflow-y:auto;">
                <p style="text-align:center; color:#64748b; font-style:italic; padding:16px;">Loading communities...</p>
            </div>
        </div>

        <!-- Section: Stats -->
        <div id="a-stats" class="admin-section">
            <div id="admin-stats-grid" class="stat-grid-box">
                <div class="stat-card"><div class="stat-card-num" id="st-users">-</div><div class="stat-card-lbl">Total Users</div></div>
                <div class="stat-card"><div class="stat-card-num" id="st-posts">-</div><div class="stat-card-lbl">Total Posts</div></div>
                <div class="stat-card"><div class="stat-card-num" id="st-comments">-</div><div class="stat-card-lbl">Comments</div></div>
                <div class="stat-card"><div class="stat-card-num" id="st-channels">-</div><div class="stat-card-lbl">Communities</div></div>
                <div class="stat-card"><div class="stat-card-num" id="st-bans">-</div><div class="stat-card-lbl">Banned Users</div></div>
                <div class="stat-card"><div class="stat-card-num" id="st-motds">-</div><div class="stat-card-lbl">Active MOTDs</div></div>
                <div class="stat-card"><div class="stat-card-num" id="st-hits">-</div><div class="stat-card-lbl">Site Hits</div></div>
            </div>
            <button onclick="loadAdminStats()" style="background:#1e293b; color:#cbd5e1; border:1px solid #334155; border-radius:6px; padding:6px 14px; font-size:11px; font-weight:600; cursor:pointer;"><i class="fa-solid fa-rotate"></i> Refresh Metrics</button>
        </div>

        <!-- Section: Purge -->
        <div id="a-purge" class="admin-section">
            <div style="background:#090d16; border:1px solid #1e293b; border-radius:8px; padding:14px;">
                <div style="font-weight:bold; font-size:13px; color:#f8fafc; margin-bottom:6px;">Purge User Content by ID</div>
                <p style="font-size:11px; color:#94a3b8; margin-bottom:12px;">Deletes all forum posts and comments authored by the specific user ID.</p>
                <div style="display:flex; gap:8px;">
                    <input type="number" id="purge-user-id" placeholder="Enter user ID (e.g. 42)" style="width:200px; background:#0f172a; border:1px solid #334155; border-radius:6px; padding:6px 10px; color:#f8fafc; font-size:12px; outline:none;">
                    <button onclick="adminPurgeUser()" style="background:rgba(239,68,68,0.2); color:#f87171; border:1px solid rgba(239,68,68,0.4); border-radius:6px; padding:6px 16px; font-size:12px; font-weight:600; cursor:pointer;"><i class="fa-solid fa-broom"></i> Purge Content</button>
                </div>
            </div>
        </div>

        <!-- Section: Settings -->
        <div id="a-settings" class="admin-section">
            <div style="background:#090d16; border:1px solid #1e293b; border-radius:8px; padding:14px; margin-bottom:12px;">
                <div style="font-weight:bold; font-size:13px; color:#f8fafc; margin-bottom:12px;">System Configurations</div>
                <div style="display:flex; flex-direction:column; gap:10px;">
                    <label style="display:flex; align-items:center; gap:8px; font-size:12px; color:#cbd5e1; cursor:pointer;">
                        <input type="checkbox" id="cfg-reg-open" checked> Allow Public User Registrations
                    </label>
                    <label style="display:flex; align-items:center; gap:8px; font-size:12px; color:#cbd5e1; cursor:pointer;">
                        <input type="checkbox" id="cfg-avatar-upload" checked> Enable Avatar File Uploads
                    </label>
                    <label style="display:flex; align-items:center; gap:8px; font-size:12px; color:#cbd5e1; cursor:pointer;">
                        <input type="checkbox" id="cfg-dark-default" checked> Dark Theme as Default for Guests
                    </label>
                </div>
            </div>
            <button onclick="adminSaveSettings()" style="background:#2563eb; color:#fff; border:none; border-radius:6px; padding:7px 16px; font-size:12px; font-weight:600; cursor:pointer;"><i class="fa-solid fa-floppy-disk"></i> Save Settings</button>
        </div>

        <!-- Section: Sessions -->
        <div id="a-sessions" class="admin-section">
            <div id="admin-sessions-list" style="max-height:360px; overflow-y:auto;">
                <p style="text-align:center; color:#64748b; font-style:italic; padding:16px;">Loading recent sessions...</p>
            </div>
        </div>

        <?php if ($is_owner): ?>
            <!-- Section: Feedbacks -->
            <div id="a-feedback" class="admin-section">
                <div id="admin-feedback-list" style="max-height:360px; overflow-y:auto;">
                    <p style="text-align:center; color:#64748b; font-style:italic; padding:16px;">Loading feedback submissions...</p>
                </div>
            </div>

            <!-- Section: Nitro -->
            <div id="a-nitro" class="admin-section">
                <div style="background:#090d16; border:1px solid #1e293b; border-radius:8px; padding:14px; margin-bottom:12px;">
                    <div style="font-weight:bold; font-size:13px; color:#f8fafc; margin-bottom:6px;"><i class="fa-solid fa-bolt" style="color:#fbbf24; margin-right:5px;"></i> Nitro Word Challenge</div>
                    <p style="font-size:11px; color:#94a3b8; margin-bottom:12px;">Set a secret word for the community challenge.</p>
                    <div style="display:flex; gap:8px;">
                        <input type="text" id="nitro-secret-word" placeholder="Enter secret keyword..." style="flex:1; background:#0f172a; border:1px solid #334155; border-radius:6px; padding:6px 10px; color:#f8fafc; font-size:12px; outline:none;">
                        <button onclick="adminStartChallenge()" style="background:#f59e0b; color:#000; border:none; border-radius:6px; padding:6px 16px; font-size:12px; font-weight:bold; cursor:pointer;">Start Challenge</button>
                    </div>
                </div>
            </div>

            <!-- Section: Roles -->
            <div id="a-roles" class="admin-section">
                <div style="background:#090d16; border:1px solid #1e293b; border-radius:8px; padding:12px; margin-bottom:12px;">
                    <div style="font-weight:bold; font-size:12px; color:#f8fafc; margin-bottom:8px;">Create Custom Role</div>
                    <div style="display:flex; gap:8px; margin-bottom:8px;">
                        <input type="text" id="new-role-name" placeholder="Role Name (e.g. VIP Supporter)" style="flex:2; background:#0f172a; border:1px solid #334155; border-radius:6px; padding:6px 10px; color:#f8fafc; font-size:11px; outline:none;">
                        <input type="color" id="new-role-color" value="#38bdf8" style="width:40px; height:30px; background:#0f172a; border:1px solid #334155; border-radius:6px; cursor:pointer; padding:2px;">
                        <button onclick="adminCreateRole()" style="background:#2563eb; color:#fff; border:none; border-radius:6px; padding:6px 14px; font-size:11px; font-weight:600; cursor:pointer;"><i class="fa-solid fa-plus"></i> Create</button>
                    </div>
                </div>
                <div id="admin-roles-list" style="max-height:260px; overflow-y:auto;">
                    <p style="text-align:center; color:#64748b; font-style:italic; padding:16px;">Loading custom roles...</p>
                </div>
            </div>

            <!-- Section: Overlay -->
            <div id="a-overlay" class="admin-section">
                <div style="background:#090d16; border:1px solid #1e293b; border-radius:8px; padding:14px;">
                    <div style="font-weight:bold; font-size:13px; color:#f8fafc; margin-bottom:8px;">Avatar PNG Mask / Overlay</div>
                    <div style="display:flex; flex-direction:column; gap:8px;">
                        <input type="number" id="overlay-target-id" placeholder="Target User ID" style="background:#0f172a; border:1px solid #334155; border-radius:6px; padding:6px 10px; color:#f8fafc; font-size:11px; outline:none;">
                        <input type="text" id="overlay-url" placeholder="PNG Overlay Image URL" style="background:#0f172a; border:1px solid #334155; border-radius:6px; padding:6px 10px; color:#f8fafc; font-size:11px; outline:none;">
                        <div style="display:flex; gap:8px;">
                            <input type="number" id="overlay-scale" placeholder="Scale (e.g. 1.1)" step="0.1" value="1.0" style="flex:1; background:#0f172a; border:1px solid #334155; border-radius:6px; padding:6px 10px; color:#f8fafc; font-size:11px; outline:none;">
                            <input type="number" id="overlay-x" placeholder="X Offset %" value="0" style="flex:1; background:#0f172a; border:1px solid #334155; border-radius:6px; padding:6px 10px; color:#f8fafc; font-size:11px; outline:none;">
                            <input type="number" id="overlay-y" placeholder="Y Offset %" value="0" style="flex:1; background:#0f172a; border:1px solid #334155; border-radius:6px; padding:6px 10px; color:#f8fafc; font-size:11px; outline:none;">
                        </div>
                        <button onclick="adminSetOverlay()" style="background:#2563eb; color:#fff; border:none; border-radius:6px; padding:7px 16px; font-size:12px; font-weight:600; cursor:pointer; align-self:flex-start;"><i class="fa-solid fa-wand-magic-sparkles"></i> Apply Overlay</button>
                    </div>
                </div>
            </div>
        <?php endif; ?>
    </div>
</div>

<!-- User Action Modal -->
<div id="user-action-modal" class="modal-bg">
    <div class="modal-box" style="max-width:560px;">
        <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:14px; border-bottom:1px solid #1e293b; padding-bottom:10px;">
            <h3 style="font-size:14px; font-weight:bold; color:#f8fafc; margin:0;"><i class="fa-solid fa-user-gear" style="color:#38bdf8; margin-right:6px;"></i> User Administration</h3>
            <button onclick="closeModal('user-action-modal')" style="background:transparent; border:none; color:#64748b; font-size:20px; cursor:pointer; padding:2px 6px;" onmouseover="this.style.color='#f8fafc'" onmouseout="this.style.color='#64748b'">&times;</button>
        </div>
        <div id="ua-info-card" style="margin-bottom:16px;"></div>

        <div style="margin-bottom:14px; background:#090d16; border:1px solid #1e293b; border-radius:8px; padding:12px;">
            <div style="font-size:11px; font-weight:bold; color:#cbd5e1; margin-bottom:8px; text-transform:uppercase; letter-spacing:0.5px;">Rank Management</div>
            <div style="display:grid; grid-template-columns:1fr 1fr; gap:6px;">
                <?php if ($is_owner): ?>
                    <button id="ua-btn-owner" onclick="doUserAction('promote_owner')" style="background:rgba(234,179,8,0.15); border:1px solid rgba(234,179,8,0.3); color:#fbbf24; padding:7px 10px; border-radius:6px; font-size:11px; font-weight:600; cursor:pointer; text-align:left; display:flex; align-items:center; gap:6px;">
                        <i class="fa-solid fa-crown"></i> Promote to Owner
                    </button>
                <?php endif; ?>
                <button onclick="doUserAction('promote_admin')" style="background:rgba(59,130,246,0.15); border:1px solid rgba(59,130,246,0.3); color:#60a5fa; padding:7px 10px; border-radius:6px; font-size:11px; font-weight:600; cursor:pointer; text-align:left; display:flex; align-items:center; gap:6px;">
                    <i class="fa-solid fa-shield"></i> Promote to Admin
                </button>
                <button onclick="doUserAction('promote_mod')" style="background:rgba(16,185,129,0.15); border:1px solid rgba(16,185,129,0.3); color:#34d399; padding:7px 10px; border-radius:6px; font-size:11px; font-weight:600; cursor:pointer; text-align:left; display:flex; align-items:center; gap:6px;">
                    <i class="fa-solid fa-gavel"></i> Promote to Mod
                </button>
                <button onclick="doUserAction('remove_rank')" style="background:rgba(148,163,184,0.15); border:1px solid rgba(148,163,184,0.3); color:#cbd5e1; padding:7px 10px; border-radius:6px; font-size:11px; font-weight:600; cursor:pointer; text-align:left; display:flex; align-items:center; gap:6px;">
                    <i class="fa-solid fa-user"></i> Remove Rank (Regular)
                </button>
            </div>
        </div>

        <div style="margin-bottom:14px; background:#090d16; border:1px solid #1e293b; border-radius:8px; padding:12px;">
            <div style="font-size:11px; font-weight:bold; color:#cbd5e1; margin-bottom:8px; text-transform:uppercase; letter-spacing:0.5px;">Badges & Tag Flairs</div>
            <div style="display:flex; gap:6px; margin-bottom:8px;">
                <input type="text" id="ua-badge-inp" placeholder="Custom Badge (e.g. Moderator, VIP, Dev)" style="flex:1; background:#0f172a; border:1px solid #334155; border-radius:6px; padding:6px 10px; color:#f8fafc; font-size:11px; outline:none;">
                <button onclick="doUserAction('set_custom_badge', {badge: document.getElementById('ua-badge-inp').value})" style="background:#2563eb; color:#fff; border:none; border-radius:6px; padding:6px 12px; font-size:11px; font-weight:600; cursor:pointer;">Save Badge</button>
            </div>
            <div style="display:flex; gap:6px;">
                <input type="text" id="ua-flair-inp" placeholder="Status Flair (e.g. Linux Enthusiast)" style="flex:1; background:#0f172a; border:1px solid #334155; border-radius:6px; padding:6px 10px; color:#f8fafc; font-size:11px; outline:none;">
                <button onclick="doUserAction('set_status_flair', {flair: document.getElementById('ua-flair-inp').value})" style="background:#0284c7; color:#fff; border:none; border-radius:6px; padding:6px 12px; font-size:11px; font-weight:600; cursor:pointer;">Save Flair</button>
            </div>
        </div>

        <div style="margin-bottom:14px; background:#090d16; border:1px solid #1e293b; border-radius:8px; padding:12px;">
            <div style="font-size:11px; font-weight:bold; color:#cbd5e1; margin-bottom:8px; text-transform:uppercase; letter-spacing:0.5px;">Account Actions & Moderation</div>
            <div style="display:grid; grid-template-columns:1fr 1fr; gap:6px;">
                <button id="ua-btn-ban" onclick="toggleUserBan()" style="background:rgba(239,68,68,0.15); border:1px solid rgba(239,68,68,0.3); color:#f87171; padding:7px 10px; border-radius:6px; font-size:11px; font-weight:600; cursor:pointer; text-align:left; display:flex; align-items:center; gap:6px;">
                    <i class="fa-solid fa-ban"></i> <span id="ua-ban-lbl">Ban User</span>
                </button>
                <button id="ua-btn-mute" onclick="toggleUserMute()" style="background:rgba(245,158,11,0.15); border:1px solid rgba(245,158,11,0.3); color:#fbbf24; padding:7px 10px; border-radius:6px; font-size:11px; font-weight:600; cursor:pointer; text-align:left; display:flex; align-items:center; gap:6px;">
                    <i class="fa-solid fa-comment-slash"></i> <span id="ua-mute-lbl">Mute User</span>
                </button>
                <button id="ua-btn-shadowban" onclick="toggleUserShadowban()" style="background:rgba(168,85,247,0.15); border:1px solid rgba(168,85,247,0.3); color:#c084fc; padding:7px 10px; border-radius:6px; font-size:11px; font-weight:600; cursor:pointer; text-align:left; display:flex; align-items:center; gap:6px;">
                    <i class="fa-solid fa-ghost"></i> <span id="ua-sban-lbl">Shadowban</span>
                </button>
                <button onclick="promptUserPassword()" style="background:rgba(59,130,246,0.15); border:1px solid rgba(59,130,246,0.3); color:#60a5fa; padding:7px 10px; border-radius:6px; font-size:11px; font-weight:600; cursor:pointer; text-align:left; display:flex; align-items:center; gap:6px;">
                    <i class="fa-solid fa-key"></i> Reset Password
                </button>
                <button onclick="doUserAction('reset_avatar')" style="background:rgba(148,163,184,0.15); border:1px solid rgba(148,163,184,0.3); color:#cbd5e1; padding:7px 10px; border-radius:6px; font-size:11px; font-weight:600; cursor:pointer; text-align:left; display:flex; align-items:center; gap:6px;">
                    <i class="fa-solid fa-image"></i> Reset to SVG Avatar
                </button>
                <button onclick="confirmPurgeUser()" style="background:rgba(239,68,68,0.15); border:1px solid rgba(239,68,68,0.3); color:#f87171; padding:7px 10px; border-radius:6px; font-size:11px; font-weight:600; cursor:pointer; text-align:left; display:flex; align-items:center; gap:6px;">
                    <i class="fa-solid fa-broom"></i> Purge All Posts
                </button>
                <?php if ($is_admin): ?>
                    <button onclick="confirmDeleteUser()" style="background:rgba(239,68,68,0.25); border:1px solid rgba(239,68,68,0.5); color:#fca5a5; padding:7px 10px; border-radius:6px; font-size:11px; font-weight:600; cursor:pointer; text-align:left; display:flex; align-items:center; gap:6px; grid-column: span 2;">
                        <i class="fa-solid fa-trash"></i> Permanently Delete Account
                    </button>
                <?php endif; ?>
            </div>
        </div>
    </div>
</div>

<script>
let currentTargetUser = null;

function toast(msg, type='success') {
    const box = document.getElementById('toast-container');
    if (!box) return;
    const t = document.createElement('div');
    t.className = `toast-msg ${type}`;
    const icon = type === 'success' ? '<i class="fa-solid fa-circle-check"></i>' : '<i class="fa-solid fa-triangle-exclamation"></i>';
    t.innerHTML = `${icon} <span>${msg}</span>`;
    box.appendChild(t);
    setTimeout(() => {
        t.style.opacity = '0';
        t.style.transform = 'translateX(20px)';
        t.style.transition = 'all 0.2s ease';
        setTimeout(() => t.remove(), 200);
    }, 3200);
}

function openModal(id) {
    const el = document.getElementById(id);
    if (el) el.classList.add('open');
}

function closeModal(id) {
    const el = document.getElementById(id);
    if (el) el.classList.remove('open');
}

async function apiAdmin(act, params = {}) {
    const fd = new FormData();
    fd.append('admin_api', '1');
    fd.append('act', act);
    for (const k in params) {
        fd.append(k, params[k]);
    }
    try {
        const res = await fetch('index.php', { method: 'POST', body: fd });
        return await res.json();
    } catch (e) {
        console.error('API admin error:', e);
        return { ok: false, error: 'Network request failed' };
    }
}

function openAdminPanel() {
    openModal('admin-modal');
    loadAdminUsers();
    checkMaintStatus();
}

function adminTab(btn, sectionId) {
    document.querySelectorAll('.admin-tab-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    document.querySelectorAll('.admin-section').forEach(s => s.classList.remove('active'));
    const sec = document.getElementById(sectionId);
    if (sec) sec.classList.add('active');

    if (sectionId === 'a-users') loadAdminUsers();
    if (sectionId === 'a-bans') loadAdminBans();
    if (sectionId === 'a-ban-tpl') loadBanTemplate();
    if (sectionId === 'a-maint') checkMaintStatus();
    if (sectionId === 'a-comm-mgr') loadAdminChannels();
    if (sectionId === 'a-stats') loadAdminStats();
    if (sectionId === 'a-settings') loadAdminSettings();
    if (sectionId === 'a-sessions') loadAdminSessions();
    if (sectionId === 'a-feedback') loadAdminFeedback();
    if (sectionId === 'a-roles') loadAdminRoles();
}

function esc(str) {
    if (!str) return '';
    return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

async function loadAdminUsers(q = '') {
    const list = document.getElementById('admin-users-list');
    const r = await apiAdmin('get_users', { q });
    if (!r.ok || !r.users || !r.users.length) {
        list.innerHTML = '<p style="text-align:center; color:#64748b; font-style:italic; padding:20px;">No registered users found.</p>';
        return;
    }
    list.innerHTML = r.users.map(u => {
        const isGoll = (u.username.toLowerCase() === 'gollclock');
        const roleLabel = isGoll ? '<span style="background:rgba(234,179,8,0.2); color:#fbbf24; border:1px solid rgba(234,179,8,0.3); border-radius:4px; padding:1px 5px; font-size:10px; font-weight:bold;">OWNER</span>'
            : (u.role === 'OWNER' ? '<span style="background:rgba(234,179,8,0.2); color:#fbbf24; border:1px solid rgba(234,179,8,0.3); border-radius:4px; padding:1px 5px; font-size:10px; font-weight:bold;">OWNER</span>'
            : (u.role === 'ADMIN' || u.is_admin == 1 ? '<span style="background:rgba(59,130,246,0.2); color:#60a5fa; border:1px solid rgba(59,130,246,0.3); border-radius:4px; padding:1px 5px; font-size:10px; font-weight:bold;">ADMIN</span>'
            : (u.role === 'MOD' || u.is_mod == 1 ? '<span style="background:rgba(16,185,129,0.2); color:#34d399; border:1px solid rgba(16,185,129,0.3); border-radius:4px; padding:1px 5px; font-size:10px; font-weight:bold;">MOD</span>'
            : '<span style="background:rgba(148,163,184,0.15); color:#94a3b8; border-radius:4px; padding:1px 5px; font-size:10px;">USER</span>')));

        const banBadge = u.is_banned ? '<span style="background:rgba(239,68,68,0.2); color:#f87171; border:1px solid rgba(239,68,68,0.3); border-radius:4px; padding:1px 5px; font-size:10px; font-weight:bold;">BANNED</span>' : '';
        const customBadge = u.custom_badge ? `<span style="background:rgba(148,163,184,0.2); color:#cbd5e1; border-radius:4px; padding:1px 5px; font-size:10px;">${esc(u.custom_badge)}</span>` : '';
        const avSrc = u.avatar_data ? esc(u.avatar_data) : `https://api.dicebear.com/10.x/initials/svg?seed=${encodeURIComponent(u.username)}&chars=2&textColor=ffffff`;

        return `<div class="user-table-row">
            <img src="${avSrc}" style="width:32px; height:32px; border-radius:50%; object-fit:cover; border:1px solid #334155; background:#0f172a; flex-shrink:0;">
            <div style="flex:1; min-width:0;">
                <div style="display:flex; align-items:center; gap:6px; flex-wrap:wrap;">
                    <span style="font-weight:600; color:#f8fafc; font-size:12px;">u/${esc(u.username)}</span>
                    <span style="color:#64748b; font-size:10px; font-family:monospace;">#${u.id}</span>
                    ${roleLabel}
                    ${banBadge}
                    ${customBadge}
                </div>
                <div style="font-size:10px; color:#94a3b8; margin-top:2px;">
                    IP: ${esc(u.ip_address || '127.0.0.1')} &bull; Joined: ${(u.created_at || '').slice(0,10)}
                    ${u.status_flair ? ` &bull; <em>${esc(u.status_flair)}</em>` : ''}
                </div>
            </div>
            <button onclick="openUserActions(${JSON.stringify(u).replace(/"/g,'&quot;')})" style="background:#1e293b; hover:bg-slate-700; color:#cbd5e1; border:1px solid #334155; border-radius:6px; padding:5px 12px; font-size:11px; font-weight:600; cursor:pointer; display:inline-flex; align-items:center; gap:4px;">
                <i class="fa-solid fa-ellipsis"></i> Actions
            </button>
        </div>`;
    }).join('');
}

async function loadAdminBans(q = '') {
    const list = document.getElementById('admin-bans-list');
    const r = await apiAdmin('get_bans', { q });
    if (!r.ok || !r.bans || !r.bans.length) {
        list.innerHTML = '<p style="text-align:center; color:#64748b; font-style:italic; padding:20px;">No active bans recorded.</p>';
        return;
    }
    list.innerHTML = r.bans.map(b => {
        return `<div class="user-table-row">
            <div style="width:32px; height:32px; border-radius:50%; background:rgba(239,68,68,0.15); border:1px solid rgba(239,68,68,0.3); display:flex; align-items:center; justify-content:center; color:#f87171; font-size:13px; flex-shrink:0;">
                <i class="fa-solid fa-ban"></i>
            </div>
            <div style="flex:1; min-width:0;">
                <div style="font-weight:600; color:#f87171; font-size:12px;">u/${esc(b.target_username)}</div>
                <div style="font-size:10px; color:#94a3b8; margin-top:2px;">
                    Reason: ${esc(b.reason || 'Rule violation')} &bull; Banned by: ${esc(b.reviewed_by || 'Staff')} &bull; ${esc(b.created_at || '')}
                </div>
            </div>
            <button onclick="unbanUserDirect('${esc(b.target_username)}')" style="background:rgba(16,185,129,0.15); color:#34d399; border:1px solid rgba(16,185,129,0.3); border-radius:6px; padding:5px 12px; font-size:11px; font-weight:600; cursor:pointer;">
                <i class="fa-solid fa-unlock"></i> Unban
            </button>
        </div>`;
    }).join('');
}

async function unbanUserDirect(uname) {
    const r = await apiAdmin('admin_action', { target_user_id: 0, sub_action: 'unban_user' });
    toast(`Unban requested for u/${uname}`);
    loadAdminBans();
}

function openUserActions(u) {
    currentTargetUser = u;
    const isGoll = (u.username.toLowerCase() === 'gollclock');
    const avSrc = u.avatar_data ? esc(u.avatar_data) : `https://api.dicebear.com/10.x/initials/svg?seed=${encodeURIComponent(u.username)}&chars=2&textColor=ffffff`;

    const roleText = isGoll ? '👑 OWNER'
        : (u.role === 'OWNER' ? '👑 OWNER'
        : (u.role === 'ADMIN' || u.is_admin == 1 ? '🛡️ ADMIN'
        : (u.role === 'MOD' || u.is_mod == 1 ? '⚔️ MODERATOR'
        : '👤 REGULAR USER')));

    document.getElementById('ua-info-card').innerHTML = `
        <div style="display:flex; align-items:center; gap:12px; background:#090d16; border:1px solid #1e293b; border-radius:8px; padding:12px;">
            <img src="${avSrc}" style="width:48px; height:48px; border-radius:50%; object-fit:cover; border:2px solid #334155; background:#0f172a; flex-shrink:0;">
            <div style="flex:1; min-width:0;">
                <div style="font-size:14px; font-weight:bold; color:#f8fafc; display:flex; align-items:center; gap:8px;">
                    u/${esc(u.username)}
                    <span style="font-size:11px; color:#94a3b8; font-weight:normal;">(#${u.id})</span>
                </div>
                <div style="font-size:11px; color:#38bdf8; font-weight:600; margin-top:2px;">${roleText}</div>
                <div style="font-size:10px; color:#64748b; margin-top:2px;">IP: ${esc(u.ip_address || '127.0.0.1')} &bull; Registered: ${(u.created_at || '').slice(0,10)}</div>
            </div>
        </div>
    `;

    document.getElementById('ua-badge-inp').value = u.custom_badge || '';
    document.getElementById('ua-flair-inp').value = u.status_flair || '';
    
    document.getElementById('ua-ban-lbl').innerText = u.is_banned ? 'Unban User' : 'Ban User';
    document.getElementById('ua-mute-lbl').innerText = (u.is_muted == 1) ? 'Unmute User' : 'Mute User';
    document.getElementById('ua-sban-lbl').innerText = (u.is_shadowbanned == 1) ? 'Lift Shadowban' : 'Shadowban';

    const ownerBtn = document.getElementById('ua-btn-owner');
    if (ownerBtn) {
        ownerBtn.style.display = isGoll ? 'none' : 'flex';
    }

    openModal('user-action-modal');
}

async function doUserAction(sub_action, extra = {}) {
    if (!currentTargetUser) return;
    const r = await apiAdmin('admin_action', {
        target_user_id: currentTargetUser.id,
        sub_action: sub_action,
        ...extra
    });
    if (r.ok) {
        toast(r.msg || 'User action executed successfully!', 'success');
        closeModal('user-action-modal');
        loadAdminUsers(document.getElementById('admin-user-search')?.value || '');
    } else {
        toast(r.error || 'Action failed', 'error');
    }
}

function toggleUserBan() {
    if (!currentTargetUser) return;
    if (currentTargetUser.is_banned) {
        doUserAction('unban_user');
    } else {
        const reason = prompt(`Enter ban reason for u/${currentTargetUser.username}:`, 'Rule violation');
        if (reason !== null) {
            doUserAction('ban_user', { reason });
        }
    }
}

function toggleUserMute() {
    if (!currentTargetUser) return;
    if (currentTargetUser.is_muted == 1) {
        doUserAction('unmute');
    } else {
        doUserAction('mute');
    }
}

function toggleUserShadowban() {
    if (!currentTargetUser) return;
    if (currentTargetUser.is_shadowbanned == 1) {
        doUserAction('unshadowban');
    } else {
        doUserAction('shadowban');
    }
}

function promptUserPassword() {
    if (!currentTargetUser) return;
    const pw = prompt(`Enter new password for u/${currentTargetUser.username}:`);
    if (pw && pw.length >= 4) {
        doUserAction('reset_password', { new_password: pw });
    } else if (pw !== null) {
        alert('Password must be at least 4 characters');
    }
}

function confirmPurgeUser() {
    if (!currentTargetUser) return;
    if (confirm(`Purge all posts and comments by u/${currentTargetUser.username}?`)) {
        doUserAction('purge_user');
    }
}

function confirmDeleteUser() {
    if (!currentTargetUser) return;
    if (confirm(`PERMANENTLY DELETE account u/${currentTargetUser.username}? This cannot be undone!`)) {
        doUserAction('delete_user');
    }
}

async function checkMaintStatus() {
    const r = await apiAdmin('get_maint_status');
    if (r.ok) {
        const sw = document.getElementById('maint-switch');
        if (sw) sw.checked = (r.maintenance === 1);
        const inp = document.getElementById('maint-msg-input');
        if (inp && r.message) inp.value = r.message;
    }
}

async function toggleMaintenance(isChecked) {
    const val = isChecked ? 1 : 0;
    const r = await apiAdmin('toggle_maint', { val });
    if (r.ok) {
        toast(`Maintenance mode is now ${val ? 'ON' : 'OFF'}`);
    } else {
        toast('Failed to toggle maintenance mode', 'error');
    }
}

async function saveMaintMsg() {
    const message = document.getElementById('maint-msg-input').value;
    const r = await apiAdmin('save_maint_msg', { message });
    if (r.ok) {
        toast('Maintenance message saved successfully');
    } else {
        toast('Failed to save maintenance message', 'error');
    }
}

async function adminAnnounce() {
    const message = document.getElementById('announce-input').value;
    const r = await apiAdmin('admin_announce', { message });
    if (r.ok) {
        toast(message ? 'Community announcement banner dispatched!' : 'Announcement banner cleared!');
    } else {
        toast('Failed to update announcement', 'error');
    }
}

async function loadAdminChannels() {
    const list = document.getElementById('admin-channels-list');
    const r = await apiAdmin('get_channels');
    if (!r.ok || !r.channels || !r.channels.length) {
        list.innerHTML = '<p style="text-align:center; color:#64748b; font-style:italic; padding:16px;">No communities found.</p>';
        return;
    }
    list.innerHTML = r.channels.map(c => {
        const lockIcon = (c.is_locked == 1) ? '<i class="fa-solid fa-lock" style="color:#fbbf24;"></i>' : '<i class="fa-solid fa-lock-open" style="color:#34d399;"></i>';
        const lockTxt = (c.is_locked == 1) ? 'Unlock' : 'Lock';
        return `<div class="user-table-row">
            <div style="flex:1; min-width:0;">
                <div style="font-weight:600; color:#f8fafc; font-size:12px;">r/${esc(c.name)} ${lockIcon}</div>
                <div style="font-size:10px; color:#94a3b8;">${esc(c.description || 'No description')} &bull; <strong>${c.post_count || 0}</strong> posts</div>
            </div>
            <div style="display:flex; gap:6px;">
                <button onclick="adminToggleLockChannel(${c.id})" style="background:#1e293b; color:#cbd5e1; border:1px solid #334155; border-radius:6px; padding:4px 10px; font-size:10px; cursor:pointer;">${lockTxt}</button>
                <button onclick="adminDeleteChannel(${c.id}, '${esc(c.name)}')" style="background:rgba(239,68,68,0.2); color:#f87171; border:1px solid rgba(239,68,68,0.3); border-radius:6px; padding:4px 10px; font-size:10px; cursor:pointer;">Delete</button>
            </div>
        </div>`;
    }).join('');
}

async function adminAddChannel() {
    const name = document.getElementById('new-comm-name').value.trim();
    const description = document.getElementById('new-comm-desc').value.trim();
    if (!name) return toast('Please enter a community name', 'error');
    const r = await apiAdmin('add_channel', { name, description });
    if (r.ok) {
        toast(`Community r/${name} created!`);
        document.getElementById('new-comm-name').value = '';
        document.getElementById('new-comm-desc').value = '';
        loadAdminChannels();
    } else {
        toast(r.error || 'Failed to create community', 'error');
    }
}

async function adminToggleLockChannel(id) {
    const r = await apiAdmin('toggle_lock_channel', { channel_id: id });
    if (r.ok) {
        toast('Community lock status updated');
        loadAdminChannels();
    }
}

async function adminDeleteChannel(id, name) {
    if (confirm(`Delete community r/${name} permanently?`)) {
        const r = await apiAdmin('delete_channel', { channel_id: id });
        if (r.ok) {
            toast(`Community r/${name} deleted`);
            loadAdminChannels();
        }
    }
}

async function adminClearChannel() {
    const sel = document.getElementById('clear-comm-select');
    const id = sel.value;
    const name = sel.options[sel.selectedIndex].text;
    if (confirm(`Clear all posts in ${name}?`)) {
        const r = await apiAdmin('clear_channel', { channel_id: id });
        if (r.ok) {
            toast(`Posts in ${name} cleared!`);
        }
    }
}

async function loadAdminStats() {
    const r = await apiAdmin('get_stats');
    if (r.ok && r.stats) {
        document.getElementById('st-users').innerText = Number(r.stats.total_users).toLocaleString();
        document.getElementById('st-posts').innerText = Number(r.stats.total_posts).toLocaleString();
        document.getElementById('st-comments').innerText = Number(r.stats.total_comments).toLocaleString();
        document.getElementById('st-channels').innerText = Number(r.stats.total_channels).toLocaleString();
        document.getElementById('st-bans').innerText = Number(r.stats.total_bans).toLocaleString();
        document.getElementById('st-motds').innerText = Number(r.stats.total_motds).toLocaleString();
        document.getElementById('st-hits').innerText = Number(r.stats.hit_counter).toLocaleString();
        toast('System metrics updated');
    }
}

async function adminPurgeUser() {
    const uid = document.getElementById('purge-user-id').value;
    if (!uid) return toast('Please enter a user ID', 'error');
    if (confirm(`Purge all posts and comments by user ID #${uid}?`)) {
        const r = await apiAdmin('purge_user_id', { user_id: uid });
        if (r.ok) {
            toast(r.msg || `Purged content for user #${uid}`);
            document.getElementById('purge-user-id').value = '';
        }
    }
}

async function loadBanTemplate() {
    const r = await apiAdmin('get_ban_template');
    if (r.ok && r.template) {
        document.getElementById('ban-template-editor').value = r.template;
    }
}

async function adminSaveBanTemplate() {
    const template = document.getElementById('ban-template-editor').value;
    const r = await apiAdmin('save_ban_template', { template });
    if (r.ok) {
        toast('Ban template saved successfully');
    }
}

async function loadAdminSettings() {
    const r = await apiAdmin('get_settings');
    if (r.ok && r.settings) {
        if (r.settings.reg_open !== undefined) document.getElementById('cfg-reg-open').checked = r.settings.reg_open;
        if (r.settings.avatar_upload !== undefined) document.getElementById('cfg-avatar-upload').checked = r.settings.avatar_upload;
        if (r.settings.dark_default !== undefined) document.getElementById('cfg-dark-default').checked = r.settings.dark_default;
    }
}

async function adminSaveSettings() {
    const settings = {
        reg_open: document.getElementById('cfg-reg-open').checked,
        avatar_upload: document.getElementById('cfg-avatar-upload').checked,
        dark_default: document.getElementById('cfg-dark-default').checked
    };
    const r = await apiAdmin('save_settings', { settings: JSON.stringify(settings) });
    if (r.ok) {
        toast('System configurations saved');
    }
}

async function loadAdminSessions() {
    const list = document.getElementById('admin-sessions-list');
    const r = await apiAdmin('get_sessions');
    if (!r.ok || !r.sessions || !r.sessions.length) {
        list.innerHTML = '<p style="text-align:center; color:#64748b; font-style:italic; padding:16px;">No recent sessions found.</p>';
        return;
    }
    list.innerHTML = r.sessions.map(s => {
        return `<div class="user-table-row">
            <div style="flex:1;">
                <div style="font-weight:600; color:#f8fafc; font-size:12px;">u/${esc(s.username)} <span style="font-size:10px; color:#64748b;">#${s.id}</span></div>
                <div style="font-size:10px; color:#94a3b8;">IP: ${esc(s.ip_address || '127.0.0.1')} &bull; Role: ${esc(s.role || 'USER')}</div>
            </div>
            <div style="font-size:10px; color:#64748b;">${esc(s.last_seen || s.created_at || '')}</div>
        </div>`;
    }).join('');
}

async function loadAdminFeedback() {
    const list = document.getElementById('admin-feedback-list');
    if (!list) return;
    const r = await apiAdmin('get_feedbacks');
    if (!r.ok || !r.feedbacks || !r.feedbacks.length) {
        list.innerHTML = '<p style="text-align:center; color:#64748b; font-style:italic; padding:16px;">No user feedbacks submitted yet.</p>';
        return;
    }
    list.innerHTML = r.feedbacks.map(f => {
        return `<div class="user-table-row" style="flex-direction:column; align-items:flex-start;">
            <div style="display:flex; justify-content:space-between; width:100%; font-size:11px; margin-bottom:4px;">
                <strong style="color:#38bdf8;">u/${esc(f.username || 'Anonymous')}</strong>
                <span style="color:#64748b;">${esc(f.created_at || '')}</span>
            </div>
            <p style="font-size:12px; color:#cbd5e1; margin:0; line-height:1.4;">${esc(f.content || '')}</p>
        </div>`;
    }).join('');
}

async function adminStartChallenge() {
    const secret_word = document.getElementById('nitro-secret-word').value.trim();
    if (!secret_word) return toast('Please enter a secret word', 'error');
    const r = await apiAdmin('start_nitro_challenge', { secret_word });
    if (r.ok) {
        toast(r.msg || 'Nitro challenge started!');
        document.getElementById('nitro-secret-word').value = '';
    }
}

async function loadAdminRoles() {
    const list = document.getElementById('admin-roles-list');
    if (!list) return;
    const r = await apiAdmin('get_roles');
    if (!r.ok || !r.roles || !r.roles.length) {
        list.innerHTML = '<p style="text-align:center; color:#64748b; font-style:italic; padding:16px;">No custom roles created yet.</p>';
        return;
    }
    list.innerHTML = r.roles.map(rl => {
        return `<div class="user-table-row">
            <div style="flex:1;">
                <span style="font-weight:bold; color:${esc(rl.color || '#fff')}; font-size:12px;">${esc(rl.name)}</span>
            </div>
            <button onclick="adminDeleteRole(${rl.id})" style="background:rgba(239,68,68,0.2); color:#f87171; border:1px solid rgba(239,68,68,0.3); border-radius:6px; padding:4px 10px; font-size:10px; cursor:pointer;">Delete</button>
        </div>`;
    }).join('');
}

async function adminCreateRole() {
    const name = document.getElementById('new-role-name').value.trim();
    const color = document.getElementById('new-role-color').value;
    if (!name) return toast('Enter a role name', 'error');
    const r = await apiAdmin('create_role', { name, color, permissions: '[]' });
    if (r.ok) {
        toast(`Role ${name} created!`);
        document.getElementById('new-role-name').value = '';
        loadAdminRoles();
    }
}

async function adminDeleteRole(id) {
    if (confirm('Delete this custom role?')) {
        const r = await apiAdmin('delete_role', { role_id: id });
        if (r.ok) {
            toast('Role deleted');
            loadAdminRoles();
        }
    }
}

async function adminSetOverlay() {
    const target_id = document.getElementById('overlay-target-id').value;
    const url = document.getElementById('overlay-url').value.trim();
    const scale = parseFloat(document.getElementById('overlay-scale').value) || 1.0;
    const x = parseFloat(document.getElementById('overlay-x').value) || 0;
    const y = parseFloat(document.getElementById('overlay-y').value) || 0;

    if (!target_id) return toast('Target user ID required', 'error');
    const overlay = { url, scale, x, y };
    const r = await apiAdmin('set_avatar_overlay', { target_user_id: target_id, overlay: JSON.stringify(overlay) });
    if (r.ok) {
        toast(`Overlay updated for user #${target_id}`);
    }
}

// ----------------------------------------------------
// Real-time Live Sync & Dynamic UI Engine (No Reload)
// ----------------------------------------------------
let lastCommentId = 0;
const commentsContainer = document.getElementById('comments_container');
if (commentsContainer) {
    const existingComments = commentsContainer.querySelectorAll('[data-comment-id]');
    existingComments.forEach(c => {
        const cid = parseInt(c.getAttribute('data-comment-id'), 10);
        if (cid > lastCommentId) lastCommentId = cid;
    });
}

function showLiveBannedOverlay(reason) {
    if (document.getElementById('live-banned-overlay')) return;
    const overlay = document.createElement('div');
    overlay.id = 'live-banned-overlay';
    overlay.style.cssText = 'position:fixed; top:0; left:0; width:100vw; height:100vh; background:rgba(2,6,23,0.96); backdrop-filter:blur(8px); z-index:999999; display:flex; align-items:center; justify-content:center; padding:20px;';
    overlay.innerHTML = `
        <div style="background:#0f172a; border:2px solid #ef4444; border-radius:12px; max-width:480px; width:100%; padding:24px; text-align:center; box-shadow:0 25px 50px -12px rgba(239,68,68,0.25);">
            <div style="font-size:48px; margin-bottom:12px;">🚫</div>
            <h2 style="font-size:20px; font-weight:bold; color:#f87171; margin-bottom:8px;">Account Suspended</h2>
            <p style="color:#cbd5e1; font-size:13px; margin-bottom:16px;">Your account has been banned by a forum administrator.</p>
            <div style="background:#1e293b; border:1px solid #334155; border-radius:8px; padding:12px; font-size:12px; color:#fca5a5; margin-bottom:20px; text-align:left;">
                <strong>Reason:</strong> ${esc(reason || 'Violating forum community guidelines')}
            </div>
            <a href="logout.php" style="display:inline-block; background:#ef4444; color:#fff; font-weight:bold; padding:8px 24px; border-radius:6px; text-decoration:none; font-size:12px;">Logout</a>
        </div>
    `;
    document.body.appendChild(overlay);
}

function showLiveMaintenanceOverlay(msg) {
    let overlay = document.getElementById('live-maintenance-overlay');
    if (!overlay) {
        overlay = document.createElement('div');
        overlay.id = 'live-maintenance-overlay';
        overlay.style.cssText = 'position:fixed; top:0; left:0; width:100vw; height:100vh; background:#0f172a; z-index:999998; display:flex; align-items:center; justify-content:center; padding:20px; color:#f8fafc; font-family:ui-sans-serif, system-ui, sans-serif;';
        document.body.appendChild(overlay);
    }
    overlay.innerHTML = `
        <div style="background:#1e293b; border:1px solid #334155; border-radius:14px; padding:36px; max-width:480px; width:100%; text-align:center; box-shadow:0 25px 60px rgba(0,0,0,0.7);">
            <div style="width:60px; height:60px; background:rgba(234,179,8,0.15); border:1px solid rgba(234,179,8,0.3); border-radius:50%; display:flex; align-items:center; justify-content:center; margin:0 auto 16px; color:#fbbf24; font-size:24px;">
                <i class="fa-solid fa-wrench"></i>
            </div>
            <h2 style="font-size:20px; font-weight:bold; margin-bottom:10px; color:#f8fafc;">Maintenance Mode</h2>
            <p style="color:#94a3b8; font-size:13px; line-height:1.6; margin-bottom:20px;">${esc(msg || 'BetterForums is currently undergoing scheduled maintenance. Please check back shortly.')}</p>
            <div style="font-size:11px; color:#64748b; margin-bottom:16px;">BetterForums staff can bypass maintenance by logging into an Admin/Owner account.</div>
            <div style="display:inline-flex; align-items:center; gap:6px; font-size:11px; color:#38bdf8; background:rgba(56,189,248,0.1); border:1px solid rgba(56,189,248,0.25); border-radius:6px; padding:4px 10px;">
                <i class="fa-solid fa-rotate fa-spin" style="font-size:10px;"></i> Auto-reconnecting live...
            </div>
        </div>
    `;
}

function hideLiveMaintenanceOverlay() {
    const overlay = document.getElementById('live-maintenance-overlay');
    if (overlay) {
        overlay.remove();
    }
}

function renderCommentHtml(cm) {
    const isStaff = <?php echo ($is_staff ? 'true' : 'false'); ?>;
    let roleTag = '';
    const uRole = (cm.role || '').toUpperCase();
    const isOwner = (cm.username.toLowerCase() === 'gollclock' || uRole === 'OWNER');
    const isAdmin = (uRole === 'ADMIN' || parseInt(cm.is_admin, 10) === 1);
    const isMod = (uRole === 'MOD' || parseInt(cm.is_mod, 10) === 1);

    if (isOwner) {
        roleTag = `<span class="role-badge role-badge-owner" style="background:rgba(251,191,36,0.15); border:1px solid rgba(251,191,36,0.4); color:#fbbf24; font-weight:bold; font-size:10px; padding:1px 6px; border-radius:4px; margin-left:4px; display:inline-flex; align-items:center; gap:3px;"><i class="fa-solid fa-crown"></i> OWNER</span>`;
    } else if (isAdmin) {
        roleTag = `<span class="role-badge role-badge-admin" style="background:rgba(248,113,113,0.15); border:1px solid rgba(248,113,113,0.4); color:#f87171; font-weight:bold; font-size:10px; padding:1px 6px; border-radius:4px; margin-left:4px; display:inline-flex; align-items:center; gap:3px;"><i class="fa-solid fa-shield-halved"></i> ADMIN</span>`;
    } else if (isMod) {
        roleTag = `<span class="role-badge role-badge-mod" style="background:rgba(52,211,153,0.15); border:1px solid rgba(52,211,153,0.4); color:#34d399; font-weight:bold; font-size:10px; padding:1px 6px; border-radius:4px; margin-left:4px; display:inline-flex; align-items:center; gap:3px;"><i class="fa-solid fa-gavel"></i> MOD</span>`;
    } else if (cm.custom_badge) {
        roleTag = `<span class="role-badge" style="background:#334155; color:#cbd5e1; font-size:10px; padding:1px 6px; border-radius:4px; margin-left:4px;">${esc(cm.custom_badge)}</span>`;
    }

    const avatarUrl = cm.avatar_data ? cm.avatar_data : `https://api.dicebear.com/10.x/initials/svg?seed=${encodeURIComponent(cm.username)}&chars=2&textColor=ffffff`;

    return `
        <div class="comment-block" id="comment_block_${cm.id}" data-comment-id="${cm.id}" style="animation: fadeIn 0.3s ease;">
            <div class="comment-meta">
                <img src="${esc(avatarUrl)}" alt="${esc(cm.username)}" style="width:14px; height:14px; border-radius:50%; vertical-align:middle; margin-right:4px; display:inline-block;">
                <a href="index.php?u=${encodeURIComponent(cm.username)}"><strong>u/${esc(cm.username)}</strong></a>
                ${roleTag}
                &bull; <span class="comment-score-val">0 points</span> &bull; just now
            </div>
            <div class="comment-text">
                ${cm.content_html || cm.parsed_content || esc(cm.content)}
            </div>
            <div class="post-actions">
                <a href="javascript:void(0)" onclick="replyToComment('${esc(cm.username)}')">reply</a>
                <form method="POST" action="index.php" class="ajax-vote-form" style="display:inline;">
                    <input type="hidden" name="action" value="vote">
                    <input type="hidden" name="type" value="comment">
                    <input type="hidden" name="id" value="${cm.id}">
                    <input type="hidden" name="v" value="1">
                    <button type="submit">&#9650; upvote</button>
                </form>
                <form method="POST" action="index.php" class="ajax-vote-form" style="display:inline;">
                    <input type="hidden" name="action" value="vote">
                    <input type="hidden" name="type" value="comment">
                    <input type="hidden" name="id" value="${cm.id}">
                    <input type="hidden" name="v" value="-1">
                    <button type="submit">&#9660; downvote</button>
                </form>
                ${isStaff ? `<button type="button" class="btn-mod-toggle" onclick="toggleModRow('mod_row_comm_${cm.id}')">🛡️ mod</button>` : ''}
            </div>
            ${isStaff ? `
            <div id="mod_row_comm_${cm.id}" class="mod-action-row" style="display:none;">
                <span class="mod-row-label">🛡️ Comment Mod:</span>
                <form method="POST" action="index.php" style="display:inline;" onsubmit="return confirm('Delete this comment?');">
                    <input type="hidden" name="action" value="delete_comment">
                    <input type="hidden" name="comment_id" value="${cm.id}">
                    <button type="submit" class="mod-btn-action mod-btn-danger">🗑️ Delete</button>
                </form>
                <form method="POST" action="index.php" style="display:inline;" onsubmit="return confirm('Ban user u/${esc(cm.username)}?');">
                    <input type="hidden" name="action" value="ban_user">
                    <input type="hidden" name="target_user" value="${esc(cm.username)}">
                    <input type="hidden" name="reason" value="Banned via comment moderation">
                    <button type="submit" class="mod-btn-action mod-btn-danger">🚫 Ban u/${esc(cm.username)}</button>
                </form>
                <a href="index.php?u=${encodeURIComponent(cm.username)}" class="mod-btn-action">👤 Profile</a>
            </div>` : ''}
        </div>
    `;
}

async function doLiveSync() {
    try {
        const postId = commentsContainer ? (commentsContainer.getAttribute('data-post-id') || 0) : 0;
        let url = `index.php?live_sync=1`;
        if (postId > 0) {
            url += `&post_id=${postId}&last_comment_id=${lastCommentId}`;
        }

        const res = await fetch(url, { 
            headers: { 'Accept': 'application/json' },
            credentials: 'same-origin'
        });
        if (!res.ok) return;

        const contentType = res.headers.get('content-type') || '';
        if (!contentType.includes('application/json')) {
            return;
        }

        const text = await res.text();
        if (!text || !text.trim()) return;

        let data;
        try {
            data = JSON.parse(text);
        } catch (parseErr) {
            return;
        }

        if (!data) return;

        // 1. Check logged out / session expired
        if (data.logged_out) {
            window.location.href = 'login.php';
            return;
        }

        // 2. Check live ban status
        if (data.banned) {
            showLiveBannedOverlay(data.ban_reason || 'Account suspended');
            return;
        }

        // 3. Check live maintenance mode
        if (data.maintenance === true) {
            showLiveMaintenanceOverlay(data.maintenance_msg);
        } else if (data.maintenance === false) {
            hideLiveMaintenanceOverlay();
        }

        if (!data.ok) return;

        // 4. Auto update current user header state (Karma, Role tag)
        if (data.user) {
            const karmaEl = document.getElementById('header_user_karma');
            if (karmaEl && data.user.karma !== undefined) {
                karmaEl.textContent = `(${data.user.karma.toLocaleString()} karma)`;
            }

            const roleContainer = document.getElementById('header_role_tag_container');
            if (roleContainer && data.user.role) {
                const uRole = (data.user.role || '').toUpperCase();
                const isOwner = (data.user.username && data.user.username.toLowerCase() === 'gollclock') || uRole === 'OWNER';
                const isAdmin = (uRole === 'ADMIN' || parseInt(data.user.is_admin, 10) === 1);
                const isMod = (uRole === 'MOD' || parseInt(data.user.is_mod, 10) === 1);

                if (isOwner) {
                    roleContainer.innerHTML = `<span class="role-badge role-badge-owner" style="background:rgba(251,191,36,0.15); border:1px solid rgba(251,191,36,0.4); color:#fbbf24; font-weight:bold; font-size:10px; padding:1px 6px; border-radius:4px; margin-left:4px; display:inline-flex; align-items:center; gap:3px;"><i class="fa-solid fa-crown"></i> OWNER</span>`;
                } else if (isAdmin) {
                    roleContainer.innerHTML = `<span class="role-badge role-badge-admin" style="background:rgba(248,113,113,0.15); border:1px solid rgba(248,113,113,0.4); color:#f87171; font-weight:bold; font-size:10px; padding:1px 6px; border-radius:4px; margin-left:4px; display:inline-flex; align-items:center; gap:3px;"><i class="fa-solid fa-shield-halved"></i> ADMIN</span>`;
                } else if (isMod) {
                    roleContainer.innerHTML = `<span class="role-badge role-badge-mod" style="background:rgba(52,211,153,0.15); border:1px solid rgba(52,211,153,0.4); color:#34d399; font-weight:bold; font-size:10px; padding:1px 6px; border-radius:4px; margin-left:4px; display:inline-flex; align-items:center; gap:3px;"><i class="fa-solid fa-gavel"></i> MOD</span>`;
                } else {
                    roleContainer.innerHTML = '';
                }
            }
        }

        // 5. Live update announcement banner
        const bannerContainer = document.getElementById('live_announcement_banner_container');
        if (bannerContainer && data.announcement !== undefined) {
            if (data.announcement && data.announcement.trim().length > 0) {
                bannerContainer.innerHTML = `<div class="announcement-banner"><strong>Community Announcement:</strong> <span>${esc(data.announcement)}</span></div>`;
            } else {
                bannerContainer.innerHTML = '';
            }
        }

        // 6. Auto update comments on active post
        if (data.post && data.post.new_comments && data.post.new_comments.length > 0 && commentsContainer) {
            const noCommentsMsg = document.getElementById('no_comments_msg');
            if (noCommentsMsg) noCommentsMsg.remove();

            data.post.new_comments.forEach(cm => {
                if (document.getElementById(`comment_block_${cm.id}`)) return;
                const div = document.createElement('div');
                div.innerHTML = renderCommentHtml(cm);
                const node = div.firstElementChild;
                commentsContainer.appendChild(node);
                if (cm.id > lastCommentId) lastCommentId = cm.id;
            });
        }
    } catch (e) {
        // Handled silently
    }
}

// Start live sync polling every 2.5 seconds
setInterval(doLiveSync, 2500);

// AJAX Comment Submission
const commentForm = document.getElementById('post_comment_form');
if (commentForm) {
    commentForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        const editor = document.getElementById('comment_editor');
        const submitBtn = document.getElementById('submit_comment_btn');
        const content = (editor ? editor.value : '').trim();
        if (!content) return toast('Please write a comment', 'error');

        if (submitBtn) {
            submitBtn.disabled = true;
            submitBtn.textContent = 'Posting...';
        }

        try {
            const formData = new FormData(commentForm);
            const res = await fetch('index.php', {
                method: 'POST',
                body: formData
            });

            if (res.ok) {
                if (editor) editor.value = '';
                const previewBox = document.getElementById('comment_preview_box');
                if (previewBox) previewBox.innerHTML = '<em style="color:#64748b;">Preview appears here as you type...</em>';
                toast('Comment posted!');
                await doLiveSync();
            } else {
                toast('Failed to post comment', 'error');
            }
        } catch (err) {
            toast('Network error submitting comment', 'error');
        } finally {
            if (submitBtn) {
                submitBtn.disabled = false;
                submitBtn.textContent = 'Post Comment';
            }
        }
    });
}

// AJAX Voting Event Delegation (No reload on voting)
document.addEventListener('submit', async function(e) {
    const form = e.target;
    if (form && form.classList && form.classList.contains('ajax-vote-form')) {
        e.preventDefault();
        const formData = new FormData(form);
        const type = formData.get('type');
        const id = formData.get('id');
        const v = parseInt(formData.get('v'), 10);

        try {
            const res = await fetch('index.php', {
                method: 'POST',
                body: formData
            });
            if (res.ok) {
                // Instantly update visual state in DOM
                const voteBox = form.closest('.vote-box');
                if (voteBox) {
                    const scoreSpan = voteBox.querySelector('.vote-score');
                    const upBtn = voteBox.querySelector('.vote-btn.up');
                    const downBtn = voteBox.querySelector('.vote-btn.down');
                    if (scoreSpan) {
                        let currentScore = parseInt(scoreSpan.textContent, 10) || 0;
                        const wasUp = upBtn && upBtn.classList.contains('active');
                        const wasDown = downBtn && downBtn.classList.contains('active');

                        if (v === 1) {
                            if (wasUp) {
                                upBtn.classList.remove('active');
                                scoreSpan.classList.remove('upvoted');
                                scoreSpan.textContent = currentScore - 1;
                            } else {
                                if (upBtn) upBtn.classList.add('active');
                                if (downBtn) downBtn.classList.remove('active');
                                scoreSpan.classList.add('upvoted');
                                scoreSpan.classList.remove('downvoted');
                                scoreSpan.textContent = currentScore + (wasDown ? 2 : 1);
                            }
                        } else if (v === -1) {
                            if (wasDown) {
                                downBtn.classList.remove('active');
                                scoreSpan.classList.remove('downvoted');
                                scoreSpan.textContent = currentScore + 1;
                            } else {
                                if (downBtn) downBtn.classList.add('active');
                                if (upBtn) upBtn.classList.remove('active');
                                scoreSpan.classList.add('downvoted');
                                scoreSpan.classList.remove('upvoted');
                                scoreSpan.textContent = currentScore - (wasUp ? 2 : 1);
                            }
                        }
                    }
                } else {
                    // In comment row actions
                    const btn = form.querySelector('button');
                    if (btn) {
                        if (v === 1) {
                            btn.style.color = btn.style.color ? '' : '#38bdf8';
                        } else {
                            btn.style.color = btn.style.color ? '' : '#818cf8';
                        }
                    }
                }
                doLiveSync();
            }
        } catch (err) {
            console.error('Vote error:', err);
        }
    }
});
</script>
</body>
</html>
