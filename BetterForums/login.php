<?php
require_once __DIR__ . '/db.php';

$error = '';
$success = '';

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

$ip = get_real_client_ip();
$ip_safe = mysqli_real_escape_string($conn, $ip);

// Never ban loopback / internal proxy addresses
$is_loopback = in_array($ip, ['127.0.0.1', '::1', '0.0.0.0', 'localhost']);
if (!$is_loopback) {
    $ip_chk = mysqli_query($conn, "SELECT id, reason FROM ip_bans WHERE ip_address = '$ip_safe'");
    if ($ip_chk && mysqli_num_rows($ip_chk) > 0) {
        $ip_row = mysqli_fetch_assoc($ip_chk);
        $error = 'Access Denied: Your IP address (' . htmlspecialchars($ip, ENT_QUOTES, 'UTF-8') . ') has been banned. Reason: ' . htmlspecialchars($ip_row['reason'], ENT_QUOTES, 'UTF-8');
    }
}

if (isset($_GET['error']) && $_GET['error'] === 'banned') {
    $error = 'Your account has been banned from BetterForums.';
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && empty($error)) {
    $action = isset($_POST['action']) ? trim($_POST['action']) : 'login';
    $username = isset($_POST['username']) ? trim($_POST['username']) : '';
    $password = isset($_POST['password']) ? trim($_POST['password']) : '';

    if (empty($username) || empty($password)) {
        $error = 'Username and password are required.';
    } elseif (strlen($username) < 3 || strlen($username) > 30) {
        $error = 'Username must be between 3 and 30 characters.';
    } elseif ($action === 'register') {
        $u_safe = mysqli_real_escape_string($conn, $username);
        $check = mysqli_query($conn, "SELECT id FROM users WHERE username = '$u_safe'");
        if (mysqli_num_rows($check) > 0) {
            $error = 'That username is already taken. Please choose another.';
        } elseif (strlen($password) < 4) {
            $error = 'Password must be at least 4 characters.';
        } else {
            $hash = password_hash($password, PASSWORD_BCRYPT);
            
            if (strtolower($username) === 'gollclock') {
                $role = 'OWNER';
                $badge = 'Owner';
            } else {
                $role = 'USER';
                $badge = '';
            }
            
            $ins = mysqli_query($conn, "INSERT INTO users (username, password_hash, role, ip_address, is_shadowbanned, hide_from_search, display_name, bio, avatar_type, avatar_data, status_flair, custom_badge, theme) VALUES ('$u_safe', '$hash', '$role', '$ip_safe', 0, 0, '$u_safe', '', 'url', '', '', '$badge', 'light')");
            if ($ins) {
                $token = base64_encode($username . ':' . md5($hash));
                setcookie('BF_AUTH_SAFE', $token, time() + (86400 * 30), '/');
                header("Location: index.php");
                exit;
            } else {
                $error = 'Registration failed: ' . mysqli_error($conn);
            }
        }
    } elseif ($action === 'login') {
        $u_safe = mysqli_real_escape_string($conn, $username);
        $res = mysqli_query($conn, "SELECT * FROM users WHERE username = '$u_safe'");
        if ($res && mysqli_num_rows($res) > 0) {
            $u = mysqli_fetch_assoc($res);
            if (password_verify($password, $u['password_hash'])) {
                if ($u['role'] !== 'OWNER') {
                    $ban_check = mysqli_query($conn, "SELECT id FROM moderation_actions WHERE target_username = '$u_safe' AND action_type = 'BAN' AND status = 'APPROVED'");
                    if ($ban_check && mysqli_num_rows($ban_check) > 0) {
                        setcookie('BF_AUTH_SAFE', '', time() - 3600, '/');
                        $error = 'Your account has been banned from BetterForums.';
                    }
                }
                if (empty($error)) {
                    mysqli_query($conn, "UPDATE users SET ip_address = '$ip_safe' WHERE id = " . intval($u['id']));
                    $token = base64_encode($u['username'] . ':' . md5($u['password_hash']));
                    setcookie('BF_AUTH_SAFE', $token, time() + (86400 * 30), '/');
                    header("Location: index.php");
                    exit;
                }
            } else {
                $error = 'Incorrect username or password.';
            }
        } else {
            $error = 'Incorrect username or password.';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>BetterForums: Log in or create an account</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
    font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    font-size: 12px;
    background-color: #0f172a;
    color: #f8fafc;
    min-height: 100vh;
}
a { color: #38bdf8; text-decoration: none; }
a:hover { text-decoration: underline; color: #60a5fa; }
.header-bar {
    background-color: #090d16;
    border-bottom: 1px solid #1e293b;
    padding: 10px 20px;
    font-size: 14px;
    font-weight: bold;
    color: #ffffff;
    display: flex;
    align-items: center;
    justify-content: space-between;
}
.header-bar a {
    color: #ffffff;
    font-size: 16px;
    background: linear-gradient(to right, #3b82f6, #06b6d4);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}
.header-bar .tagline { font-size: 11px; font-weight: normal; color: #94a3b8; margin-left: 8px; }
.container {
    width: 600px;
    margin: 50px auto;
    background-color: #1e293b;
    border: 1px solid #334155;
    border-radius: 12px;
    box-shadow: 0 20px 40px rgba(0,0,0,0.5);
    overflow: hidden;
}
.panel-title {
    background-color: #0f172a;
    border-bottom: 1px solid #334155;
    padding: 12px 18px;
    font-size: 14px;
    font-weight: 700;
    color: #f8fafc;
}
.form-body { padding: 22px; }
.split-deck { display: table; width: 100%; }
.split-col { display: table-cell; width: 50%; vertical-align: top; padding: 0 16px; }
.split-col:first-child { border-right: 1px solid #334155; }
.field-group { margin-bottom: 14px; }
label { display: block; font-weight: 600; margin-bottom: 5px; font-size: 11px; color: #cbd5e1; }
input[type="text"], input[type="password"] {
    width: 100%;
    border: 1px solid #334155;
    background: #0f172a;
    color: #f8fafc;
    padding: 8px 10px;
    font-family: inherit;
    font-size: 12px;
    border-radius: 6px;
    transition: border-color 0.15s ease;
}
input[type="text"]:focus, input[type="password"]:focus {
    border-color: #3b82f6;
    outline: none;
    box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.25);
}
input[type="submit"] {
    width: 100%;
    background: linear-gradient(135deg, #2563eb, #3b82f6);
    border: 1px solid #3b82f6;
    padding: 8px 16px;
    font-family: inherit;
    font-size: 12px;
    font-weight: 700;
    cursor: pointer;
    color: #ffffff;
    border-radius: 6px;
    box-shadow: 0 2px 8px rgba(37, 99, 235, 0.35);
    transition: all 0.15s ease;
}
input[type="submit"]:hover {
    background: linear-gradient(135deg, #1d4ed8, #2563eb);
    border-color: #60a5fa;
}
.error-box { background-color: rgba(239, 68, 68, 0.15); border: 1px solid #ef4444; color: #fca5a5; padding: 10px 14px; margin: 14px 22px 0; font-size: 12px; border-radius: 6px; }
.success-box { background-color: rgba(16, 185, 129, 0.15); border: 1px solid #10b981; color: #6ee7b7; padding: 10px 14px; margin: 14px 22px 0; font-size: 12px; border-radius: 6px; }
.footer-note { text-align: center; margin-top: 24px; font-size: 11px; color: #94a3b8; }
.logo-icon {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    background: linear-gradient(135deg, #3b82f6, #06b6d4);
    color: #fff;
    width: 22px;
    height: 22px;
    border-radius: 6px;
    font-weight: 800;
    font-size: 12px;
    margin-right: 8px;
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
</style>
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
if (!empty($motd_texts)):
?>
<div class="motd-top-ticker-bar" unselectable="on" onselectstart="return false;" oncopy="return false;" oncontextmenu="return false;">
    <marquee class="motd-ticker-marquee" behavior="scroll" direction="left" scrollamount="5" unselectable="on" onselectstart="return false;" oncopy="return false;">
        <?php echo implode(' &nbsp;&bull;&nbsp; ', $motd_texts); ?>
    </marquee>
</div>
<?php endif; ?>
<div class="header-bar">
    <div style="display:flex; align-items:center;">
        <span class="logo-icon">B</span>
        <a href="index.php"><strong>BetterForums</strong></a>
        <span class="tagline">the front page of the internet</span>
    </div>
</div>

<div class="container">
    <div class="panel-title">Log in or create an account</div>
    <?php if (!empty($error)): ?>
        <div class="error-box"><?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></div>
    <?php endif; ?>
    <?php if (!empty($success)): ?>
        <div class="success-box"><?php echo htmlspecialchars($success, ENT_QUOTES, 'UTF-8'); ?></div>
    <?php endif; ?>
    <div class="form-body">
        <div class="split-deck">
            <div class="split-col">
                <div style="font-weight:700; font-size:13px; margin-bottom:14px; border-bottom:1px solid #334155; padding-bottom:6px; color:#f8fafc;">Log In</div>
                <form method="POST" action="login.php">
                    <input type="hidden" name="action" value="login">
                    <div class="field-group">
                        <label for="login_u">Username</label>
                        <input type="text" id="login_u" name="username" required autocomplete="username">
                    </div>
                    <div class="field-group">
                        <label for="login_p">Password</label>
                        <input type="password" id="login_p" name="password" required autocomplete="current-password">
                    </div>
                    <div class="field-group" style="margin-top:16px;">
                        <input type="submit" value="Log In">
                    </div>
                </form>
            </div>
            <div class="split-col">
                <div style="font-weight:700; font-size:13px; margin-bottom:14px; border-bottom:1px solid #334155; padding-bottom:6px; color:#f8fafc;">Create an account</div>
                <form method="POST" action="login.php">
                    <input type="hidden" name="action" value="register">
                    <div class="field-group">
                        <label for="reg_u">Choose a username</label>
                        <input type="text" id="reg_u" name="username" required autocomplete="username">
                    </div>
                    <div class="field-group">
                        <label for="reg_p">Password</label>
                        <input type="password" id="reg_p" name="password" required autocomplete="new-password">
                    </div>
                    <div class="field-group" style="margin-top:16px;">
                        <input type="submit" value="Sign Up">
                    </div>
                </form>
            </div>
        </div>
    </div>
</div>
<div class="footer-note">
    BetterForums &bull; Join communities, discuss ideas, and share what matters to you.
</div>
</body>
</html>
