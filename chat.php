<?php
session_set_cookie_params(["samesite" => "None", "secure" => true]);
session_start();
header("Content-Security-Policy: frame-ancestors *");
header("X-Frame-Options: ALLOWALL");
require_once 'db.php';
if(!isset($_SESSION['user_id'])){header('Location: index.php');exit;}
$uid=(int)$_SESSION['user_id'];
$uname=$_SESSION['username'];
$pdo=getDB();
$meRow=$pdo->prepare("SELECT * FROM users WHERE id=?");$meRow->execute([$uid]);$meRow=$meRow->fetch();
if(!$meRow||!empty($meRow['is_banned'])){
    $ban = null;
    try {
        $banStmt = $pdo->prepare("SELECT reason, ban_icon, ban_type FROM bans WHERE user_id=? ORDER BY id DESC LIMIT 1");
        $banStmt->execute([$uid]);
        $ban = $banStmt->fetch();
        if ($ban && !empty($ban['ban_type'])) {
            $tplStmt = $pdo->prepare("SELECT html_content FROM ban_templates WHERE ban_type=?");
            $tplStmt->execute([$ban['ban_type']]);
            $tpl = $tplStmt->fetchColumn();
            if ($tpl) {
                session_destroy();
                // Replace reason placeholder if any in the template
                $tpl = str_replace('{{REASON}}', htmlspecialchars($ban['reason'] ?? ''), $tpl);
                echo $tpl;
                exit;
            }
        }
    } catch(Exception $e){}
    $reason = $ban ? $ban['reason'] : 'Account suspended';
    $iconQ = ($ban && !empty($ban['ban_icon'])) ? '&icon=' . urlencode($ban['ban_icon']) : '';
    session_destroy();
    header('Location: banned.php?reason=' . urlencode($reason) . $iconQ);exit;
}
// Ensure all expected columns exist before accessing them
try { $pdo->exec("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin TINYINT(1) NOT NULL DEFAULT 0"); } catch(Exception $e){}
try { $pdo->exec("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_mod TINYINT(1) NOT NULL DEFAULT 0"); } catch(Exception $e){}
try { $pdo->exec("ALTER TABLE users ADD COLUMN IF NOT EXISTS name_color VARCHAR(20) NOT NULL DEFAULT '#94a3b8'"); } catch(Exception $e){}
try { $pdo->exec("ALTER TABLE users ADD COLUMN IF NOT EXISTS force_logout TINYINT(1) NOT NULL DEFAULT 0"); } catch(Exception $e){}
try { $pdo->exec("ALTER TABLE users ADD COLUMN IF NOT EXISTS last_seen DATETIME DEFAULT NULL"); } catch(Exception $e){}
try { $pdo->exec("ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar TEXT DEFAULT NULL"); } catch(Exception $e){}
// Re-fetch meRow after ensuring columns exist
$meRow=$pdo->prepare("SELECT * FROM users WHERE id=?");$meRow->execute([$uid]);$meRow=$meRow->fetch();
if(empty($meRow['name_color'])) $meRow['name_color']='#94a3b8';

$isAdmin=((!empty($meRow['is_admin']))||$uname==='gollclock');
$isMod=((!empty($meRow['is_mod'])) || $isAdmin);
$isSuperAdmin=($uname==='gollclock');

$myPerms = [];
if(!empty($meRow['role_id'])) {
   try {
     $rStmt = $pdo->prepare("SELECT permissions FROM roles WHERE id=?");
     $rStmt->execute([$meRow['role_id']]);
     $rp = $rStmt->fetchColumn();
     if($rp) $myPerms = json_decode($rp, true) ?: [];
   } catch(Exception $e){}
}

  $isImpersonating = isset($_SESSION['admin_original_id']);
  $impersonatorName = $_SESSION['admin_original_name'] ?? '';
  
// Maintenance gate
if(!$isAdmin && !$isImpersonating){
    try {
        $pdo->exec("CREATE TABLE IF NOT EXISTS site_config (
            id INT PRIMARY KEY DEFAULT 1,
            maintenance TINYINT(1) DEFAULT 0,
            maintenance_msg TEXT,
            allow_images TINYINT(1) DEFAULT 1,
            allow_audio TINYINT(1) DEFAULT 1,
            custom_wordle VARCHAR(255) DEFAULT NULL
        )");
        $pdo->exec("INSERT IGNORE INTO site_config(id) VALUES(1)");
        $sc = $pdo->query("SELECT maintenance, maintenance_msg FROM site_config WHERE id=1")->fetch();
        if($sc && $sc['maintenance'] == 1){
            $msg=$sc['maintenance_msg'] ?? 'Under maintenance';
            ?><!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Maintenance</title>
            <script src="https://cdn.tailwindcss.com"></script></head>
            <body class="bg-slate-900 min-h-screen flex items-center justify-center text-center p-8">
              <div><div class="text-6xl mb-6">🔧</div>
              <h1 class="text-2xl font-bold text-white mb-3">Under Maintenance</h1>
              <p class="text-slate-400"><?=htmlspecialchars($msg)?></p>
              <a href="index.php" class="inline-block mt-8 text-blue-400 hover:text-blue-300 text-sm">← Back</a></div>
            </body></html><?php exit;
        }
    } catch(Exception $e) { /* site_config unavailable, skip maintenance check */ }
}
$pdo->prepare("UPDATE users SET last_seen=NOW() WHERE id=?")->execute([$uid]);
?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>BetterChat</title>
<script src="https://cdn.tailwindcss.com"></script>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<style>
body{background-color:#0f172a;color:#f8fafc;font-family:ui-sans-serif,system-ui,-apple-system,sans-serif}
.msg-row { content-visibility: auto; contain-intrinsic-size: auto 60px; }
input[type=number]::-webkit-inner-spin-button, input[type=number]::-webkit-outer-spin-button { -webkit-appearance: none; margin: 0; }
input[type=number] { -moz-appearance: textfield; }
.gradient-text{background:linear-gradient(to right,#3b82f6,#06b6d4);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
::-webkit-scrollbar{width:5px}::-webkit-scrollbar-track{background:#0f172a}
::-webkit-scrollbar-thumb{background:#1e293b;border-radius:4px}::-webkit-scrollbar-thumb:hover{background:#334155}

:root {
  --nav-w: 240px;
  --mem-w: 220px;
}
.app-grid{display:grid;grid-template-columns:var(--nav-w) 1fr var(--mem-w);grid-template-rows:52px 1fr;height:100dvh;overflow:hidden;transition:grid-template-columns 0.2s;}
#app-header{grid-column:1/-1;grid-row:1}
#sidebar{grid-column:1;grid-row:2;overflow-y:auto;background-color:#0f172a;z-index:40;}
#main{grid-column:2;grid-row:2;display:flex;flex-direction:column;overflow:hidden;position:relative;}
#members{grid-column:3;grid-row:2;overflow-y:auto;background-color:#0f172a;z-index:40;}
#messages{flex:1;overflow-y:auto;padding:16px 20px;display:flex;flex-direction:column;gap:2px}

@media(max-width:768px){
  .app-grid{grid-template-columns:0px 1fr 0px;}
  #sidebar, #members{position:absolute;top:52px;bottom:0;width:280px;transition:transform 0.3s cubic-bezier(0.4, 0, 0.2, 1);box-shadow:0 0 20px rgba(0,0,0,0.5);}
  #sidebar{left:0;transform:translateX(-100%);grid-column:unset;grid-row:unset;}
  #members{right:0;transform:translateX(100%);grid-column:unset;grid-row:unset;}
  #sidebar.open{transform:translateX(0);}
  #members.open{transform:translateX(0);}
  #main{grid-column:1/-1;}
}

.msg-row:hover{background:rgba(255,255,255,.03)}
.msg-row:hover .msg-actions{opacity:1}
.msg-actions{opacity:0;transition:opacity .15s}

/* Modals */
.modal-bg{position:fixed;inset:0;background:rgba(0,0,0,.75);backdrop-filter:blur(6px);
  display:flex;align-items:center;justify-content:center;z-index:1000;
  opacity:0;pointer-events:none;transition:opacity .2s}
.modal-bg.open{opacity:1;pointer-events:all}
.modal-box{background:#0f172a;border:1px solid #1e293b;border-radius:12px;padding:28px;
  min-width:360px;max-width:520px;width:100%;max-height:90vh;overflow-y:auto;
  transform:translateY(16px);transition:transform .25s cubic-bezier(.16,1,.3,1);
  box-shadow:0 25px 60px rgba(0,0,0,.8)}
.modal-bg.open .modal-box{transform:none}

/* Admin modal wider */
#admin-modal .modal-box{min-width:660px;max-width:760px}

.channel-btn:hover{background:rgba(255,255,255,.04)}
.channel-btn.active{background:rgba(59,130,246,.15)}

/* Toast */
.toast{position:fixed;bottom:24px;right:24px;background:#1e293b;border:1px solid #334155;
  border-radius:10px;padding:12px 18px;font-size:.82rem;
  box-shadow:0 8px 32px rgba(0,0,0,.6);animation:slideIn .25s ease;z-index:9999}
@keyframes slideIn{from{opacity:0;transform:translateX(12px)}to{opacity:1;transform:none}}

/* Voice recorder */
.voice-btn.recording{background:rgba(239,68,68,.2)!important;border-color:rgba(239,68,68,.5)!important;color:#f87171!important}
.voice-btn.recording i{animation:pulse 1s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}

/* File/iframe message */
.file-msg{display:flex;align-items:center;gap:10px;background:rgba(255,255,255,.04);
  border:1px solid #1e293b;border-radius:10px;padding:10px 14px;max-width:320px;margin-top:4px}
.iframe-msg{border:1px solid #1e293b;border-radius:10px;overflow:hidden;max-width:500px;margin-top:4px}
.iframe-msg iframe{width:100%;height:300px;border:none;background:#fff}

/* Admin user table */
.user-table-row:hover{background:rgba(255,255,255,.03)}

/* Maint banner */
.maint-banner{background:linear-gradient(to right,rgba(234,179,8,.12),transparent);
  border-bottom:1px solid rgba(234,179,8,.18);padding:7px 20px;font-size:.77rem;
  color:#fbbf24;display:flex;align-items:center;gap:8px;flex-shrink:0}

/* Edit textarea */
.edit-area{background:#0f172a;border:1px solid #3b82f6;border-radius:6px;padding:6px 10px;
  color:#f8fafc;font-size:.875rem;width:100%;resize:none;outline:none;font-family:inherit}

/* Audio player */
audio{max-width:280px;height:36px;accent-color:#3b82f6}

/* Twemoji */
img.emoji {
  height: 1.2em;
  width: 1.2em;
  margin: 0 .05em 0 .1em;
  vertical-align: -0.1em;
  display: inline-block;
}
<?php 
if (!empty($meRow['site_theme']) || (!empty($meRow['is_vip']) && !empty($meRow['site_theme']))) {
    $tArr = explode(',', $meRow['site_theme']);
    $t1 = $tArr[0] ?? '#0f172a';
    $t2 = $tArr[1] ?? $t1;
    $t3 = $tArr[2] ?? '#2563eb';
    echo "
    body, .app-grid, #sidebar, #members, .modal-box, #app-header, .admin-section, .profile-section, .app-container {
        background: linear-gradient(135deg, {$t1}, {$t2}) !important;
        background-color: color-mix(in srgb, {$t1} 85%, black) !important;
        background-attachment: fixed !important;
    }
    input, textarea, select {
        background-color: color-mix(in srgb, {$t1} 80%, black) !important;
    }
    /* Dynamic VIP Accent (Replacing primary blue) */
    .bg-blue-600, .bg-blue-500, .bg-blue-400 { background-color: {$t3} !important; }
    .bg-blue-500\/10 { background-color: color-mix(in srgb, {$t3} 10%, transparent) !important; }
    .bg-blue-500\/20 { background-color: color-mix(in srgb, {$t3} 20%, transparent) !important; }
    .bg-blue-600\/20 { background-color: color-mix(in srgb, {$t3} 20%, transparent) !important; }
    .bg-blue-600\/15 { background-color: color-mix(in srgb, {$t3} 15%, transparent) !important; }
    .hover\:bg-blue-600\/25:hover { background-color: color-mix(in srgb, {$t3} 25%, transparent) !important; }
    .hover\:bg-blue-500:hover, .hover\:bg-blue-600:hover, .hover\:bg-blue-400:hover { background-color: color-mix(in srgb, {$t3} 80%, white) !important; }
    .text-blue-400, .text-blue-300 { color: color-mix(in srgb, {$t3} 80%, white) !important; }
    .text-blue-500, .text-blue-600 { color: {$t3} !important; }
    .text-blue-500\/80 { color: color-mix(in srgb, {$t3} 80%, transparent) !important; }
    .text-blue-400\/70 { color: color-mix(in srgb, color-mix(in srgb, {$t3} 80%, white) 70%, transparent) !important; }
    .border-blue-500, .border-blue-600 { border-color: {$t3} !important; }
    .border-blue-500\/25 { border-color: color-mix(in srgb, {$t3} 25%, transparent) !important; }
    .border-blue-500\/30 { border-color: color-mix(in srgb, {$t3} 30%, transparent) !important; }
    .border-blue-500\/40 { border-color: color-mix(in srgb, {$t3} 40%, transparent) !important; }
    .focus-within\:border-blue-500:focus-within { border-color: {$t3} !important; }
    .border-blue-400, .border-blue-300 { border-color: color-mix(in srgb, {$t3} 80%, white) !important; }
    .hover\:border-blue-500:hover, .hover\:border-blue-400:hover { border-color: {$t3} !important; }
    .hover\:text-blue-400:hover, .hover\:text-blue-300:hover, .hover\:text-blue-500:hover { color: color-mix(in srgb, {$t3} 80%, white) !important; }
    .shadow-blue-500\/20 { box-shadow: 0 4px 6px -1px color-mix(in srgb, {$t3} 20%, transparent), 0 2px 4px -2px color-mix(in srgb, {$t3} 20%, transparent) !important; }
    .shadow-blue-500\/30 { box-shadow: 0 4px 6px -1px color-mix(in srgb, {$t3} 30%, transparent), 0 2px 4px -2px color-mix(in srgb, {$t3} 30%, transparent) !important; }
    .shadow-blue-900\/20 { box-shadow: 0 4px 6px -1px color-mix(in srgb, {$t3} 20%, black), 0 2px 4px -2px color-mix(in srgb, {$t3} 20%, black) !important; }
    .hover\:shadow-blue-500\/30:hover { box-shadow: 0 10px 15px -3px color-mix(in srgb, {$t3} 30%, transparent), 0 4px 6px -4px color-mix(in srgb, {$t3} 30%, transparent) !important; }
    .gradient-text { background: linear-gradient(to right, {$t3}, color-mix(in srgb, {$t3} 60%, white)) !important; -webkit-background-clip: text !important; -webkit-text-fill-color: transparent !important; }
    .accent-blue-500 { accent-color: {$t3} !important; }
    
    /* Slate Tinting - Override default gray-blue tones to match the custom theme ($t1) */
    .bg-slate-900, .bg-slate-900\/80, .bg-slate-900\/90, .bg-slate-900\/50, .bg-slate-800, .bg-slate-800\/50, .bg-slate-700, .hover\:bg-slate-700:hover, .hover\:bg-slate-800:hover {
        --tw-bg-opacity: 1 !important;
    }
    .bg-slate-900 { background-color: color-mix(in srgb, {$t1} 85%, black) !important; }
    .bg-slate-900\/80 { background-color: color-mix(in srgb, {$t1} 85%, rgba(0,0,0,0.8)) !important; }
    .bg-slate-800 { background-color: color-mix(in srgb, {$t1} 70%, black) !important; }
    .bg-slate-700 { background-color: color-mix(in srgb, {$t1} 55%, black) !important; }
    .hover\:bg-slate-700:hover { background-color: color-mix(in srgb, {$t1} 55%, black) !important; }
    .hover\:bg-slate-800:hover { background-color: color-mix(in srgb, {$t1} 65%, black) !important; }
    
    .border-slate-800, .border-slate-800\/50, .border-slate-700, .border-slate-700\/50 {
        --tw-border-opacity: 1 !important;
    }
    .border-slate-800 { border-color: color-mix(in srgb, {$t1} 60%, black) !important; }
    .border-slate-700 { border-color: color-mix(in srgb, {$t1} 45%, black) !important; }
    
    .text-slate-300 { color: color-mix(in srgb, {$t1} 10%, white) !important; }
    .text-slate-400 { color: color-mix(in srgb, {$t1} 25%, white) !important; }
    .text-slate-500 { color: color-mix(in srgb, {$t1} 40%, white) !important; }
    .hover\:text-slate-200:hover { color: color-mix(in srgb, {$t1} 5%, white) !important; }
    .hover\:text-slate-300:hover { color: color-mix(in srgb, {$t1} 15%, white) !important; }
    
    /* Hardcoded Element Overrides */
    .modal-box { background-color: color-mix(in srgb, {$t1} 85%, black) !important; border-color: color-mix(in srgb, {$t1} 60%, black) !important; }
    #members { background-color: color-mix(in srgb, {$t1} 85%, black) !important; }
    .toast { background-color: color-mix(in srgb, {$t1} 70%, black) !important; border-color: color-mix(in srgb, {$t1} 45%, black) !important; }
    .file-msg, .iframe-msg { border-color: color-mix(in srgb, {$t1} 60%, black) !important; }
    .channel-btn.active { background-color: color-mix(in srgb, {$t3} 15%, transparent) !important; }
    
    /* Scrollbars and inputs Native overrides */
    ::-webkit-scrollbar-thumb { background: color-mix(in srgb, {$t3} 40%, transparent) !important; border-radius: 4px; }
    ::-webkit-scrollbar-thumb:hover { background: {$t3} !important; }
    .edit-area { border-color: {$t3} !important; }
    audio { accent-color: {$t3} !important; }
    ::selection { background-color: color-mix(in srgb, {$t3} 40%, transparent) !important; }
    ";
}
?>
</style>
<script src="https://unpkg.com/twemoji@latest/dist/twemoji.min.js" crossorigin="anonymous"></script>
</head>
<body class="overflow-hidden">
<div class="app-grid">

<!-- ══ HEADER ══════════════════════════════════════════════════════════════ -->
<header id="app-header" class="sticky top-0 z-50 bg-slate-900/80 backdrop-blur-md border-b border-slate-800 px-2 lg:px-4 flex items-center gap-2 lg:gap-3">
  <button class="lg:hidden text-slate-400 hover:text-white p-1" onclick="document.getElementById('sidebar').classList.toggle('open'); document.getElementById('members').classList.remove('open');">
    <i class="fa-solid fa-bars text-lg"></i>
  </button>
  <h1 class="text-xl lg:text-2xl font-extrabold gradient-text tracking-tighter flex-shrink-0 hidden sm:block w-[130px]">BetterChat</h1>
  
  <?php if ($isImpersonating): ?>
  <div class="flex items-center gap-1 lg:gap-2 bg-red-900/80 text-white px-2 py-1 rounded-full text-[10px] lg:text-xs font-bold border border-red-500 shadow-lg shadow-red-500/20">
    <i class="fa-solid fa-user-secret"></i> <span class="hidden md:inline">Controlling <?=$uname?></span>
    <button onclick="leaveControl()" class="ml-1 md:ml-2 bg-black/30 hover:bg-black/50 px-2 py-0.5 rounded transition">Leave</button>
  </div>
  <?php endif; ?>

  <div class="flex items-center gap-1 text-slate-300 text-sm flex-shrink-0">
    <i class="fa-solid fa-hashtag text-xs text-slate-500"></i>
    <span id="header-ch-name" class="font-medium whitespace-nowrap overflow-hidden text-ellipsis max-w-[80px] lg:max-w-none">general</span>
  </div>

  <button id="call-btn" class="hidden flex items-center justify-center w-8 h-8 rounded-full bg-slate-800 hover:bg-slate-700 text-green-400 transition-colors shadow-sm border border-slate-700 mx-1" onclick="startCall()" title="Start Voice Call">
    <i class="fa-solid fa-phone"></i>
  </button>

  <!-- Search -->
  <div class="hidden md:flex flex-1 max-w-[200px] lg:max-w-xs items-center bg-slate-800 rounded-full px-3.5 py-1.5 border border-slate-700 focus-within:border-blue-500 transition-colors mx-2">
    <i class="fa-solid fa-magnifying-glass text-slate-500 mr-2 text-xs"></i>
    <input id="msg-search" placeholder="Search…" oninput="filterMessages(this.value)"
      class="bg-transparent border-none outline-none flex-1 text-slate-200 placeholder-slate-600 text-xs lg:text-sm">
  </div>

  <div class="flex flex-1 items-center gap-1 justify-end ml-auto">
    <button onclick="openModal('bug-modal')" class="p-1.5 rounded-lg text-orange-500 hover:text-orange-400 hover:bg-slate-800 transition-colors" title="Report Bug / Feedback">
      <i class="fa-solid fa-bug"></i>
    </button>
    <a href="/search" target="_blank" class="hidden sm:inline-block p-1.5 rounded-lg text-blue-400 hover:text-blue-300 hover:bg-slate-800 transition-colors" title="BetterHub Search (BetGle)">
      <i class="fa-solid fa-earth-americas text-sm"></i>
    </a>
    <button onclick="openWordle()" class="hidden sm:inline-block p-1.5 rounded-lg text-emerald-500 hover:text-emerald-400 hover:bg-slate-800 transition-colors" title="Play Daily Wordle">
      <i class="fa-solid fa-gamepad text-sm"></i>
    </button>
    <button onclick="openInbox()" class="relative p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors">
      <i class="fa-solid fa-inbox text-sm"></i>
      <span id="inbox-badge" class="absolute -top-0.5 -right-0.5 bg-red-500 text-white text-[10px] rounded-full min-w-[15px] h-4 flex items-center justify-center px-1 hidden">0</span>
    </button>
    <button onclick="openModal('friend-modal')" class="hidden lg:inline-block p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors" title="Add friend">
      <i class="fa-solid fa-user-plus text-sm"></i>
    </button>
    <div onclick="openModal('profile-modal')" id="self-av-wrap" class="relative w-7 h-7 lg:w-8 lg:h-8 flex-shrink-0 cursor-pointer mx-1">
      <div class="w-full h-full rounded-full bg-blue-600 border border-slate-700 hover:border-blue-500 overflow-hidden flex items-center justify-center text-[10px] lg:text-xs font-bold text-white">
        <?=$meRow['avatar']?'<img src="'.htmlspecialchars($meRow['avatar']).'" class="w-full h-full object-cover">':htmlspecialchars(strtoupper(substr($uname,0,1)))?>
      </div>
      <?php 
         if ($meRow['avatar_overlay']) {
            $ov = json_decode($meRow['avatar_overlay'], true);
            if ($ov && !empty($ov['url'])) {
                $y = $ov['y'] ?? 0;
                $x = $ov['x'] ?? 0;
                $s = $ov['scale'] ?? 1;
                echo '<img src="'.htmlspecialchars($ov['url']).'" style="position:absolute; width:100%; height:100%; top:'.$y.'%; left:'.$x.'%; transform:scale('.$s.'); pointer-events:none; z-index:10; object-fit:contain;">';
            }
         }
      ?>
    </div>
    <?php if($isAdmin):?>
    <button onclick="openAdminPanel()" class="hidden md:flex items-center gap-1.5 bg-red-500/10 hover:bg-red-500/20 border border-red-500/30 text-red-400 px-2 py-1 lg:px-2.5 lg:py-1.5 rounded-lg transition-colors text-[10px] lg:text-xs font-semibold">
      <i class="fa-solid fa-shield-halved"></i> <span class="hidden lg:inline">CONTROL</span>
    </button>
    <?php endif;?>
    <a href="logout.php" class="hidden sm:inline-block p-1.5 rounded-lg text-slate-500 hover:text-white hover:bg-slate-800 transition-colors" title="Logout">
      <i class="fa-solid fa-right-from-bracket text-sm"></i>
    </a>
    <button class="lg:hidden text-slate-400 hover:text-white p-1" onclick="document.getElementById('members').classList.toggle('open'); document.getElementById('sidebar').classList.remove('open');">
      <i class="fa-solid fa-users text-lg"></i>
    </button>
  </div>
</header>

<!-- ══ SIDEBAR ══════════════════════════════════════════════════════════════ -->
<aside id="sidebar" class="bg-slate-900 border-r border-slate-800 flex flex-col">
  <div class="p-3 flex-1 min-h-0 flex flex-col">
    <p class="text-[10px] uppercase tracking-widest text-slate-600 font-semibold px-2 mb-2 flex-shrink-0">Channels</p>
    <div id="channel-list" class="space-y-0.5 overflow-y-auto flex-1 pr-1"></div>
  </div>
  <div class="border-t border-slate-800 mx-3 my-1 flex-shrink-0"></div>
  <div class="p-3 flex-1 min-h-0 flex flex-col">
    <div class="flex items-center justify-between px-2 mb-2 flex-shrink-0">
      <p class="text-[10px] uppercase tracking-widest text-slate-600 font-semibold">Friends</p>
      <button onclick="openModal('friend-modal')" class="text-slate-600 hover:text-blue-400 transition-colors text-xs"><i class="fa-solid fa-plus"></i></button>
    </div>
    <div id="dm-list" class="space-y-0.5 overflow-y-auto flex-1 pr-1"></div>
  </div>
  
  <!-- User bar -->
  <div class="border-t border-slate-800 p-3 flex items-center gap-2.5 flex-shrink-0">
    <div onclick="openModal('profile-modal')" class="relative w-8 h-8 flex-shrink-0 cursor-pointer">
      <div class="w-full h-full rounded-full bg-blue-600 overflow-hidden flex items-center justify-center text-xs font-bold text-white border border-slate-700 hover:border-blue-500 transition-colors">
        <?=$meRow['avatar']?'<img src="'.htmlspecialchars($meRow['avatar']).'" class="w-full h-full object-cover">':htmlspecialchars(strtoupper(substr($uname,0,1)))?>
      </div>
      <?php 
         if ($meRow['avatar_overlay']) {
            $ov = json_decode($meRow['avatar_overlay'], true);
            if ($ov && !empty($ov['url'])) {
                $y = $ov['y'] ?? 0;
                $x = $ov['x'] ?? 0;
                $s = $ov['scale'] ?? 1;
                echo '<img src="'.htmlspecialchars($ov['url']).'" style="position:absolute; width:100%; height:100%; top:'.$y.'%; left:'.$x.'%; transform:scale('.$s.'); pointer-events:none; z-index:10; object-fit:contain;">';
            }
         }
      ?>
    </div>
    <div class="flex-1 min-w-0">
      <p class="text-sm font-semibold truncate" id="self-name" style="color:<?=htmlspecialchars($meRow['name_color'])?>"><?=htmlspecialchars($uname)?></p>
      <p class="text-[10px] text-emerald-400">● online<?=$isAdmin?' · <span class="text-red-400">admin</span>':''?></p>
    </div>
    <button onclick="openModal('profile-modal')" class="text-slate-600 hover:text-white transition-colors"><i class="fa-solid fa-gear text-xs"></i></button>
  </div>
</aside>

<!-- ══ MAIN ═════════════════════════════════════════════════════════════════ -->
<main id="main">
  
  <div id="call-ui-container" class="hidden flex-col bg-[#202225] border-b border-slate-800 shrink-0 p-4 relative z-10 shadow-lg" style="flex: 0 0 auto;">
    <div class="flex items-center justify-between mb-4 shrink-0 px-2">
      <div class="font-bold text-slate-200 text-sm flex items-center gap-2">
         <i class="fa-solid fa-phone text-slate-500"></i>
         <span id="call-title">Voice Call</span>
      </div>
      <div class="text-[11px] uppercase tracking-wider text-green-400 font-bold px-2 py-1 rounded bg-green-500/10" id="call-status">Connected</div>
    </div>
    
    <!-- Video/Voice Grid -->
    <div class="flex-1 grid grid-cols-1 sm:grid-cols-2 gap-4 h-[35vh] sm:h-[45vh] lg:h-[55vh] min-h-[250px] relative">
       <!-- Remote User Box -->
       <div class="bg-[#36393f] rounded-xl flex items-center justify-center relative overflow-hidden group shadow-md border border-slate-700/50">
          <div class="w-20 h-20 sm:w-28 sm:h-28 rounded-full bg-slate-800 flex items-center justify-center overflow-hidden shadow-xl ring-4 ring-[#2f3136]">
            <!-- Wait, since we are doing voice only right now, use generic avatar or initial. -->
            <i class="fa-solid fa-user text-4xl sm:text-5xl text-slate-500"></i>
          </div>
          <div class="absolute bottom-3 left-4 bg-black/60 px-3 py-1.5 rounded-lg text-xs font-semibold text-white backdrop-blur-sm">
             <span id="call-remote-name">User</span>
          </div>
       </div>

       <!-- Local User Box -->
       <div class="bg-[#2f3136] rounded-xl flex items-center justify-center relative overflow-hidden shadow-md border border-slate-700/50">
          <div class="w-20 h-20 sm:w-28 sm:h-28 rounded-full bg-[#5865F2] flex items-center justify-center overflow-hidden shadow-xl ring-4 ring-[#36393f]">
            <?php if($meRow['avatar']): ?>
            <img src="<?=htmlspecialchars($meRow['avatar'])?>" class="w-full h-full object-cover">
            <?php else: ?>
            <span class="text-3xl sm:text-5xl text-white font-bold"><?=htmlspecialchars(strtoupper(substr($uname,0,1)))?></span>
            <?php endif; ?>
          </div>
          <div class="absolute bottom-3 left-4 bg-black/60 px-3 py-1.5 rounded-lg text-xs font-semibold text-white backdrop-blur-sm">
             <?=htmlspecialchars($uname)?> (You)
          </div>
       </div>
    </div>

    <!-- Controls -->
    <div class="shrink-0 flex items-center justify-center gap-4 pt-6 pb-2">
      <button id="call-btn-mute" class="w-12 h-12 rounded-full bg-[#3ba55c] hover:bg-[#2d7d46] transition-colors text-white shadow-md flex items-center justify-center text-lg" onclick="toggleMute()" title="Mute Microphone">
        <i class="fa-solid fa-microphone"></i>
      </button>
      <button id="call-btn-deafen" class="w-12 h-12 rounded-full bg-[#4f545c] hover:bg-[#3b3e45] transition-colors text-white shadow-md flex items-center justify-center text-lg" onclick="toggleDeafen()" title="Deafen Audio">
        <i class="fa-solid fa-headphones"></i>
      </button>
      <button id="call-btn-accept" class="hidden w-12 h-12 rounded-full bg-[#3ba55c] hover:bg-[#2d7d46] transition-colors text-white shadow-md flex items-center justify-center text-lg animate-bounce" onclick="acceptCall()" title="Accept Call">
        <i class="fa-solid fa-phone"></i>
      </button>
      <button id="call-btn-end" class="w-12 h-12 rounded-full bg-[#ed4245] hover:bg-[#c03537] transition-colors text-white shadow-lg flex items-center justify-center text-lg" onclick="endCall()" title="End Call">
        <i class="fa-solid fa-phone-slash"></i>
      </button>
    </div>
  </div>
  <audio id="remote-audio" autoplay class="hidden"></audio>

  <?php if($isAdmin):?>
  <div id="maint-banner" class="maint-banner hidden">
    <i class="fa-solid fa-triangle-exclamation flex-shrink-0"></i>
    <span>⚠ Maintenance mode is <strong>ON</strong></span>
    <button onclick="this.parentElement.classList.add('hidden')" class="ml-auto text-yellow-400/50 hover:text-yellow-400"><i class="fa-solid fa-xmark text-xs"></i></button>
  </div>
  <?php endif;?>

  <div id="messages"></div>

  <!-- Typing Indicator -->
  <style>
    @keyframes typingPulse {
      0%, 100% { opacity: 0.2; }
      50% { opacity: 1; }
    }
    .typing-dots span { animation: typingPulse 1.4s infinite; font-size: 1.2em; line-height: 1; }
    .typing-dots span:nth-child(2) { animation-delay: 0.2s; }
    .typing-dots span:nth-child(3) { animation-delay: 0.4s; }
  </style>
  <div id="typing-indicator" class="hidden px-5 py-2 text-xs text-slate-400 italic bg-[#0f172a]">
    <span id="typing-users"></span> is typing<span class="typing-dots"><span>.</span><span>.</span><span>.</span></span>
  </div>

  <!-- Reply Preview -->
  <div id="reply-preview" class="hidden px-4 py-2 bg-slate-800 text-sm border-l-2 border-blue-500 flex justify-between items-center text-slate-300">
    <div class="truncate">
      Replying to <b id="reply-to-user" class="text-white drop-shadow"></b>: <span id="reply-to-text" class="italic opacity-80"></span>
    </div>
    <button onclick="cancelReply()" class="text-slate-400 hover:text-white px-2 cursor-pointer">&times;</button>
  </div>

  <!-- Input bar -->
  <div class="px-4 pb-4 pt-2 border-t border-slate-800 flex-shrink-0 relative">
    <!-- Extra toolbar (visible always, clickable for admin) -->
    <div class="flex items-center gap-1.5 mb-2">
      <!-- Voice record — everyone -->
      <button id="voice-btn" onclick="toggleVoice()" title="Voice message"
        class="voice-btn flex items-center gap-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-400 hover:text-white px-2.5 py-1.5 rounded-lg transition-all text-xs font-medium">
        <i class="fa-solid fa-microphone"></i> <span id="voice-label">Voice</span>
      </button>

      <!-- File — admin only trigger, visible to all -->
      <button onclick="<?=$isAdmin?'document.getElementById(\'file-inp\').click()':'toast(\'Only admins can send files.\',\'error\')' ?>"
        title="Send file<?=$isAdmin?'':' (Admin only)'?>"
        class="flex items-center gap-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 <?=$isAdmin?'text-slate-400 hover:text-white':'text-slate-600 cursor-default'?> px-2.5 py-1.5 rounded-lg transition-all text-xs font-medium">
        <i class="fa-solid fa-file-arrow-up"></i> File
        <?php if(!$isAdmin):?><i class="fa-solid fa-lock text-[9px] ml-0.5 text-slate-700"></i><?php endif;?>
      </button>
      <input type="file" id="file-inp" class="hidden" onchange="sendFile(this)">

      <!-- Iframe — admin only trigger, visible to all -->
      <button onclick="<?=$isAdmin?'openModal(\'iframe-modal\')':'toast(\'Only admins can embed iframes.\',\'error\')' ?>"
        title="Embed iframe<?=$isAdmin?'':' (Admin only)'?>"
        class="flex items-center gap-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 <?=$isAdmin?'text-slate-400 hover:text-white':'text-slate-600 cursor-default'?> px-2.5 py-1.5 rounded-lg transition-all text-xs font-medium">
        <i class="fa-solid fa-globe"></i> Embed
        <?php if(!$isAdmin):?><i class="fa-solid fa-lock text-[9px] ml-0.5 text-slate-700"></i><?php endif;?>
      </button>

      <div id="voice-timer" class="text-xs text-red-400 font-mono hidden ml-1">● <span id="voice-time">0:00</span></div>
    </div>

    <div class="flex items-end gap-2.5 bg-slate-800 rounded-xl px-4 py-3 border border-slate-700 focus-within:border-blue-500 transition-colors">
      <button onclick="document.getElementById('img-inp').click()" title="Send image"
        class="text-slate-500 hover:text-blue-400 transition-colors flex-shrink-0 self-end pb-0.5">
        <i class="fa-solid fa-circle-plus text-lg"></i>
      </button>
      <input type="file" id="img-inp" accept="image/*" class="hidden" onchange="sendImage(this)">
      <textarea id="msg-input" rows="1" placeholder="Message #general…"
        onkeydown="handleKey(event)" oninput="autoGrow(this)"
        class="bg-transparent border-none outline-none flex-1 text-slate-200 placeholder-slate-600 text-sm resize-none max-h-28"></textarea>
      <button onclick="toggleGifPicker()" title="Send GIF"
        class="text-slate-400 hover:text-blue-400 transition-colors flex-shrink-0 self-end font-bold text-[10px] bg-slate-900 hover:bg-slate-700 px-1.5 py-0.5 rounded border border-slate-700 mb-1">
        GIF
      </button>
      <button onclick="toast('Emoji coming soon!','info')" class="text-slate-500 hover:text-yellow-400 transition-colors flex-shrink-0 self-end pb-0.5">
        <i class="fa-regular fa-face-smile text-lg"></i>
      </button>
      <button onclick="sendMessage()"
        class="bg-blue-600 hover:bg-blue-500 text-white rounded-lg p-2 flex-shrink-0 self-end transition-all hover:shadow-lg hover:shadow-blue-500/30">
        <i class="fa-solid fa-paper-plane text-sm"></i>
      </button>
    </div>

    <!-- GIF Picker Popover -->
    <div id="gif-picker" class="hidden absolute bottom-full right-4 mb-2 w-80 sm:w-96 h-[400px] bg-slate-900 border border-slate-700 rounded-xl shadow-2xl flex-col z-50 overflow-hidden">
      <div class="p-3 border-b border-slate-800 flex justify-between items-center bg-slate-900/90 backdrop-blur">
        <input id="gif-search" type="text" placeholder="Search Giphy..." class="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-slate-200 text-sm outline-none focus:border-blue-500 transition-colors" oninput="searchGifs(this.value)">
      </div>
      <div id="gif-results" class="flex-1 overflow-y-auto p-2 columns-2 gap-2 space-y-2">
        <div class="col-span-2 text-center text-slate-500 text-sm mt-10">Type to search GIFs...</div>
      </div>
      <div class="p-2 border-t border-slate-800 text-center bg-slate-900">
        <span class="text-[10px] text-slate-500 font-bold tracking-wider">POWERED BY GIPHY</span>
      </div>
    </div>
  </div>
</main>

<!-- ══ MEMBERS ══════════════════════════════════════════════════════════════ -->
<aside id="members" class="bg-slate-900 border-l border-slate-800">
  <p class="text-[10px] uppercase tracking-widest text-slate-600 font-semibold px-4 pt-4 pb-2">Members</p>
  <div id="members-list" class="px-2 space-y-0.5"></div>
</aside>
</div>

<!-- ══ IMAGE ZOOM ═══════════════════════════════════════════════════════════ -->
<div id="img-zoom" onclick="this.style.display='none'"
  style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.92);z-index:3000;cursor:zoom-out;align-items:center;justify-content:center">
  <img id="img-zoom-src" src="" class="max-w-[90vw] max-h-[90vh] rounded-xl">
</div>

<!-- ══ MODALS ════════════════════════════════════════════════════════════════ -->

<!-- Profile + Password modal -->
<div class="modal-bg" id="profile-modal">
  <div class="modal-box">
    <div class="flex items-center justify-between mb-5">
      <h2 class="text-base font-bold text-slate-100 flex items-center gap-2"><i class="fa-solid fa-user-pen text-blue-400"></i> Profile & Settings</h2>
      <button onclick="closeModal('profile-modal')" class="text-slate-500 hover:text-white"><i class="fa-solid fa-xmark"></i></button>
    </div>
    <!-- Tabs -->
    <div class="flex bg-slate-900 rounded-lg p-1 mb-5">
      <button class="profile-tab flex-1 py-1.5 md:py-2 rounded-md text-[10px] md:text-xs font-semibold bg-blue-600 text-white" onclick="profileTab(this,'pf-profile')">Profile</button>
      <button class="profile-tab flex-1 py-1.5 md:py-2 rounded-md text-[10px] md:text-xs font-semibold text-slate-400 hover:text-white" onclick="profileTab(this,'pf-password')">Password</button>
      <button class="profile-tab flex-1 py-1.5 md:py-2 rounded-md text-[10px] md:text-xs font-semibold text-slate-400 hover:text-white" onclick="profileTab(this,'pf-layout')">Layout</button>
    </div>

    <!-- Profile tab -->
    <div id="pf-profile" class="profile-section">
      <div class="flex flex-col items-center mb-5">
        <div class="relative w-24 h-24 mb-2 flex items-center justify-center">
            <div id="av-preview" onclick="document.getElementById('av-upload').click()"
              class="w-20 h-20 rounded-full bg-blue-600 border-4 border-slate-700 hover:border-blue-500 transition-colors cursor-pointer overflow-hidden flex items-center justify-center text-2xl font-bold text-white shadow-xl shadow-blue-500/20">
              <?=$meRow['avatar']?'<img src="'.htmlspecialchars($meRow['avatar']).'" class="w-full h-full object-cover">':htmlspecialchars(strtoupper(substr($uname,0,1)))?>
            </div>
            <?php 
               $myOverlayHtml = '';
               if ($meRow['avatar_overlay']) {
                  $ov = json_decode($meRow['avatar_overlay'], true);
                  if ($ov && !empty($ov['url'])) {
                      $y = $ov['y'] ?? 0;
                      $x = $ov['x'] ?? 0;
                      $s = $ov['scale'] ?? 1;
                      $myOverlayHtml = '<img src="'.htmlspecialchars($ov['url']).'" style="position:absolute; width:80px; height:80px; top:calc(50% - 40px + '.$y.'px); left:calc(50% - 40px + '.$x.'px); transform:scale('.$s.'); pointer-events:none; z-index:10; object-fit:contain;">';
                  }
               }
               echo $myOverlayHtml;
            ?>
        </div>
        <p class="text-xs text-slate-500 mt-2">Click to upload avatar</p>
        <input type="file" id="av-upload" accept="image/*" class="hidden" onchange="previewAvatar(this)">
      </div>
      <div class="mb-4">
        <label class="block text-[10px] uppercase tracking-widest text-slate-500 font-semibold mb-2">Username</label>
        <div class="bg-slate-900/60 border border-slate-700 rounded-lg px-4 py-2.5 text-slate-400 text-sm"><?=htmlspecialchars($uname)?></div>
      </div>
      <div class="mb-5">
        <label class="block text-[10px] uppercase tracking-widest text-slate-500 font-semibold mb-2">Name Colour</label>
        <div class="flex items-center gap-3 mb-3">
          <input type="color" id="name-color" value="<?=htmlspecialchars($meRow['name_color'])?>" oninput="updateColorPreview(this.value)"
            class="w-10 h-9 rounded-lg border border-slate-700 bg-slate-900 cursor-pointer p-1">
          <span id="color-preview-name" class="text-sm font-semibold px-3 py-1.5 bg-slate-900 border border-slate-700 rounded-lg"
            style="color:<?=htmlspecialchars($meRow['name_color'])?>"><?=htmlspecialchars($uname)?></span>
        </div>
        <div class="flex gap-2 flex-wrap">
          <?php foreach(['#3b82f6','#06b6d4','#10b981','#f59e0b','#ef4444','#a855f7','#ec4899','#f8fafc'] as $c):?>
            <div onclick="setColor('<?=$c?>')" class="w-6 h-6 rounded-full cursor-pointer border-2 border-transparent hover:border-white transition-all hover:scale-110" style="background:<?=$c?>"></div>
          <?php endforeach;?>
        </div>
      </div>

      <?php if (!empty($meRow['is_vip']) || !empty($meRow['is_nitro'])): ?>
      <div class="mb-5 bg-gradient-to-r from-pink-500/10 to-purple-500/10 border border-pink-500/20 p-4 rounded-lg">
        <h3 class="text-sm font-bold text-pink-400 mb-3 flex items-center gap-2"><i class="fa-solid fa-crown text-yellow-400"></i> VIP Customization</h3>
        
        <div class="mb-3">
          <label class="block text-[10px] uppercase tracking-widest text-slate-400 font-semibold mb-1">Avatar Image/GIF URL</label>
          <input type="text" id="vip-avatar-url" placeholder="https://example.com/my-gif.gif" value="<?=htmlspecialchars($meRow['avatar'] && filter_var($meRow['avatar'], FILTER_VALIDATE_URL) ? $meRow['avatar'] : '')?>" class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 outline-none focus:border-pink-500 transition-colors">
          <p class="text-[10px] text-slate-500 mt-1">Supercedes uploaded avatar if set. Use for animated GIFs.</p>
        </div>

        <div class="mb-3">
          <label class="block text-[10px] uppercase tracking-widest text-slate-400 font-semibold mb-1">Custom Profile Tag</label>
          <input type="text" id="vip-tag" placeholder="e.g. Developer" value="<?=htmlspecialchars($meRow['custom_tag']??'')?>" class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 outline-none focus:border-pink-500 transition-colors">
        </div>

        <?php
          $rawTheme = $meRow['site_theme'] ?? '#0f172a,#0f172a,#2563eb';
          $tArr = explode(',', $rawTheme);
          $vT1 = $tArr[0] ?? '#0f172a';
          $vT2 = $tArr[1] ?? $vT1;
          $vTA = $tArr[2] ?? '#2563eb';
        ?>
        <div>
          <label class="block text-[10px] uppercase tracking-widest text-slate-400 font-semibold mb-2">Website Theme Colors</label>
          
          <div class="space-y-3 mb-4 bg-slate-900/50 p-3 rounded border border-slate-700/50">
              <div class="flex items-center justify-between">
                <span class="text-xs text-slate-400 font-medium">Gradient Start (Color 1)</span>
                <input type="color" id="vip-theme" value="<?=htmlspecialchars($vT1)?>" class="w-10 h-8 rounded border border-slate-700 bg-slate-900 cursor-pointer p-0.5">
              </div>
              <div class="flex items-center justify-between">
                <span class="text-xs text-slate-400 font-medium">Gradient End (Color 2)</span>
                <input type="color" id="vip-theme2" value="<?=htmlspecialchars($vT2)?>" class="w-10 h-8 rounded border border-slate-700 bg-slate-900 cursor-pointer p-0.5">
              </div>
              <div class="flex items-center justify-between border-t border-slate-700/50 pt-3">
                <span class="text-xs text-blue-400 font-bold">Accent Color (Replaces Blue)</span>
                <input type="color" id="vip-accent" value="<?=htmlspecialchars($vTA)?>" class="w-10 h-8 rounded border border-slate-700 bg-slate-900 cursor-pointer p-0.5">
              </div>
              <button type="button" onclick="resetVipTheme()" class="mt-2 w-full text-xs font-semibold py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded border border-slate-700 transition-colors">
                <i class="fa-solid fa-rotate-left mr-1"></i> Reset to Default Colors
              </button>
          </div>
          
          <div class="flex gap-2 flex-wrap pb-1">
            <?php foreach(['#0f172a','#1c1917','#312e81','#4c1d95','#be185d','#9f1239','#14532d','#064e3b'] as $c):?>
              <div onclick="document.getElementById('vip-theme').value='<?=$c?>'; document.getElementById('vip-theme2').value='<?=$c?>';" class="w-6 h-6 rounded-full cursor-pointer border-2 border-transparent hover:border-white transition-all hover:scale-110 shadow-md" style="background:<?=$c?>"></div>
            <?php endforeach;?>
          </div>
        </div>
      </div>
      <?php endif; ?>

      <button onclick="saveProfile()" class="w-full bg-blue-600 hover:bg-blue-500 text-white font-semibold py-2.5 rounded-lg transition-all text-sm flex items-center justify-center gap-2">
        <i class="fa-solid fa-floppy-disk"></i> Save Profile
      </button>
    </div>

    <!-- Password tab -->
    <div id="pf-password" class="profile-section hidden">
      <div class="space-y-4 mb-5">
        <div>
          <label class="block text-[10px] uppercase tracking-widest text-slate-500 font-semibold mb-2">Current Password</label>
          <div class="flex items-center bg-slate-900 border border-slate-700 rounded-lg px-4 py-3 focus-within:border-blue-500 transition-colors">
            <i class="fa-solid fa-lock text-slate-500 mr-2 text-sm"></i>
            <input type="password" id="pw-old" placeholder="••••••••" class="bg-transparent border-none outline-none flex-1 text-slate-200 placeholder-slate-600 text-sm">
          </div>
        </div>
        <div>
          <label class="block text-[10px] uppercase tracking-widest text-slate-500 font-semibold mb-2">New Password</label>
          <div class="flex items-center bg-slate-900 border border-slate-700 rounded-lg px-4 py-3 focus-within:border-blue-500 transition-colors">
            <i class="fa-solid fa-key text-slate-500 mr-2 text-sm"></i>
            <input type="password" id="pw-new" placeholder="min. 6 chars" class="bg-transparent border-none outline-none flex-1 text-slate-200 placeholder-slate-600 text-sm">
          </div>
        </div>
        <div>
          <label class="block text-[10px] uppercase tracking-widest text-slate-500 font-semibold mb-2">Confirm New Password</label>
          <div class="flex items-center bg-slate-900 border border-slate-700 rounded-lg px-4 py-3 focus-within:border-blue-500 transition-colors">
            <i class="fa-solid fa-key text-slate-500 mr-2 text-sm"></i>
            <input type="password" id="pw-confirm" placeholder="repeat new password" class="bg-transparent border-none outline-none flex-1 text-slate-200 placeholder-slate-600 text-sm">
          </div>
        </div>
      </div>
      <button onclick="changePassword()" class="w-full bg-blue-600 hover:bg-blue-500 text-white font-semibold py-2.5 rounded-lg transition-all text-sm flex items-center justify-center gap-2">
        <i class="fa-solid fa-shield-halved"></i> Change Password
      </button>
    </div>

    <!-- Layout tab -->
    <div id="pf-layout" class="profile-section hidden">
      <div class="space-y-4 mb-5">
        <div>
          <label class="block text-[10px] uppercase tracking-widest text-slate-500 font-semibold mb-2 flex items-center justify-between">
            Sidebar Width
            <span id="nav-w-val" class="text-blue-400">240px</span>
          </label>
          <input type="range" id="nav-w" min="150" max="400" value="240" step="10" class="w-full accent-blue-500" oninput="document.getElementById('nav-w-val').innerText=this.value+'px'; document.documentElement.style.setProperty('--nav-w', this.value + 'px');">
        </div>
        <div>
          <label class="block text-[10px] uppercase tracking-widest text-slate-500 font-semibold mb-2 flex items-center justify-between">
            Members Panel Width
            <span id="mem-w-val" class="text-blue-400">220px</span>
          </label>
          <input type="range" id="mem-w" min="150" max="400" value="220" step="10" class="w-full accent-blue-500" oninput="document.getElementById('mem-w-val').innerText=this.value+'px'; document.documentElement.style.setProperty('--mem-w', this.value + 'px');">
        </div>
        <div class="bg-slate-900/60 p-3 rounded-lg border border-slate-700 mt-2">
           <p class="text-xs text-slate-400 leading-relaxed mb-3"><i class="fa-solid fa-circle-info mr-1 text-slate-500"></i> These settings change how much space the side panels take up on desktop. They are saved to your browser.</p>
           <button onclick="resetLayout()" class="text-xs text-red-400 hover:text-red-300 transition-colors font-medium border border-red-500/30 px-3 py-1.5 rounded bg-red-500/10">Reset Default</button>
        </div>
      </div>
      <button onclick="saveLayout()" class="w-full bg-blue-600 hover:bg-blue-500 text-white font-semibold py-2.5 rounded-lg transition-all text-sm flex items-center justify-center gap-2">
        <i class="fa-solid fa-floppy-disk"></i> Save Layout
      </button>
    </div>
  </div>
</div>

<!-- Inbox -->
<div class="modal-bg" id="inbox-modal">
  <div class="modal-box" style="max-width:480px">
    <div class="flex items-center justify-between mb-5">
      <h2 class="text-base font-bold text-slate-100 flex items-center gap-2"><i class="fa-solid fa-inbox text-blue-400"></i> Inbox</h2>
      <button onclick="closeModal('inbox-modal')" class="text-slate-500 hover:text-white"><i class="fa-solid fa-xmark"></i></button>
    </div>
    <div id="inbox-content" class="text-sm text-slate-400 italic">Loading…</div>
  </div>
</div>

<!-- Add Friend -->
<div class="modal-bg" id="friend-modal">
  <div class="modal-box">
    <div class="flex items-center justify-between mb-5">
      <h2 class="text-base font-bold text-slate-100 flex items-center gap-2"><i class="fa-solid fa-user-plus text-blue-400"></i> Add Friend</h2>
      <button onclick="closeModal('friend-modal')" class="text-slate-500 hover:text-white"><i class="fa-solid fa-xmark"></i></button>
    </div>
    <p class="text-slate-400 text-sm mb-4">Send a friend request — they'll see it in their Inbox.</p>
    <div class="mb-4">
      <div class="flex items-center bg-slate-900 border border-slate-700 rounded-lg px-4 py-3 focus-within:border-blue-500 transition-colors">
        <i class="fa-solid fa-at text-slate-500 mr-2 text-sm"></i>
        <input id="friend-name" type="text" placeholder="their_handle" onkeydown="if(event.key==='Enter')sendFriendRequest()"
          class="bg-transparent border-none outline-none flex-1 text-slate-200 placeholder-slate-600 text-sm">
      </div>
    </div>
    <div class="flex gap-3">
      <button onclick="sendFriendRequest()" class="flex-1 bg-blue-600 hover:bg-blue-500 text-white font-semibold py-2.5 rounded-lg text-sm flex items-center justify-center gap-2">
        <i class="fa-solid fa-paper-plane"></i> Send Request
      </button>
      <button onclick="closeModal('friend-modal')" class="px-4 py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-sm border border-slate-700">Cancel</button>
    </div>
  </div>
</div>

<!-- Iframe embed modal (admin) -->
<?php if($isAdmin):?>
<div class="modal-bg" id="iframe-modal">
  <div class="modal-box">
    <div class="flex items-center justify-between mb-5">
      <h2 class="text-base font-bold text-slate-100 flex items-center gap-2"><i class="fa-solid fa-globe text-blue-400"></i> Embed Iframe</h2>
      <button onclick="closeModal('iframe-modal')" class="text-slate-500 hover:text-white"><i class="fa-solid fa-xmark"></i></button>
    </div>
    <div class="mb-4">
      <label class="block text-[10px] uppercase tracking-widest text-slate-500 font-semibold mb-2">URL to Embed</label>
      <div class="flex items-center bg-slate-900 border border-slate-700 rounded-lg px-4 py-3 focus-within:border-blue-500 transition-colors">
        <i class="fa-solid fa-link text-slate-500 mr-2 text-sm"></i>
        <input id="iframe-url" type="url" placeholder="https://example.com"
          class="bg-transparent border-none outline-none flex-1 text-slate-200 placeholder-slate-600 text-sm">
      </div>
    </div>
    <div class="mb-5">
      <label class="block text-[10px] uppercase tracking-widest text-slate-500 font-semibold mb-2">Label (optional)</label>
      <div class="flex items-center bg-slate-900 border border-slate-700 rounded-lg px-4 py-3 focus-within:border-blue-500 transition-colors">
        <i class="fa-solid fa-tag text-slate-500 mr-2 text-sm"></i>
        <input id="iframe-label" type="text" placeholder="Friendly name"
          class="bg-transparent border-none outline-none flex-1 text-slate-200 placeholder-slate-600 text-sm">
      </div>
    </div>
    <div class="flex gap-3">
      <button onclick="sendIframe()" class="flex-1 bg-blue-600 hover:bg-blue-500 text-white font-semibold py-2.5 rounded-lg text-sm flex items-center justify-center gap-2">
        <i class="fa-solid fa-globe"></i> Embed in Chat
      </button>
      <button onclick="closeModal('iframe-modal')" class="px-4 py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-sm border border-slate-700">Cancel</button>
    </div>
  </div>
</div>

<!-- ADMIN CONTROL PANEL -->
<div class="modal-bg" id="admin-modal">
  <div class="modal-box" style="max-width:720px;border-color:rgba(220,38,38,.25)">
    <div class="flex items-center justify-between mb-5">
      <h2 class="text-base font-bold text-red-400 flex items-center gap-2"><i class="fa-solid fa-shield-halved"></i> Control Panel</h2>
      <button onclick="closeModal('admin-modal')" class="text-slate-500 hover:text-white"><i class="fa-solid fa-xmark"></i></button>
    </div>

    <!-- Admin tabs -->
    <div class="flex flex-wrap bg-slate-900 rounded-lg p-1 mb-5 gap-1">
      <?php
      $adminTabs = [
        'a-users' => ['Users', 'fa-users'],
        'a-bans' => ['Bans', 'fa-gavel'],
        'a-ban-tpl' => ['Ban Tpl', 'fa-file-code'],
        'a-announce' => ['Announce', 'fa-bullhorn'],
        'a-maintenance' => ['Maintenance', 'fa-wrench'],
        'a-channel' => ['Clear Chat', 'fa-trash'],
        'a-channels-mgr' => ['Channels', 'fa-list'],
        'a-stats' => ['Stats', 'fa-chart-simple'],
        'a-purge' => ['Purge', 'fa-eraser'],
        'a-settings' => ['Settings', 'fa-sliders'],
        'a-sessions' => ['Sessions', 'fa-clock-rotate-left']
      ];
      foreach($adminTabs as $id => $data): 
        if ($isSuperAdmin || !empty($myPerms[$id])): ?>
          <button class="admin-tab flex-1 py-2 px-2 rounded-md text-[11px] font-semibold text-slate-400 hover:text-white" onclick="adminTab(this,'<?=$id?>')"><i class="fa-solid <?=$data[1]?> mr-1"></i><?=$data[0]?></button>
      <?php endif; endforeach; ?>
      <?php if ($uname === 'gollclock'): ?>
      <button class="admin-tab flex-1 py-2 px-2 rounded-md text-[11px] font-semibold text-slate-400 hover:text-white border border-purple-500/30" onclick="adminTab(this,'a-feedback')"><i class="fa-solid fa-bug mr-1"></i>Feedbacks</button>
      <button class="admin-tab flex-1 py-2 px-2 rounded-md text-[11px] font-semibold text-slate-400 hover:text-white" onclick="adminTab(this,'a-nitro')"><i class="fa-solid fa-gift mr-1"></i>Nitro</button>
      <button class="admin-tab flex-1 py-2 px-2 rounded-md text-[11px] font-semibold text-slate-400 hover:text-white" onclick="adminTab(this,'a-roles')"><i class="fa-solid fa-user-tag mr-1"></i>Roles</button>
      <button class="admin-tab flex-1 py-2 px-2 rounded-md text-[11px] font-semibold text-slate-400 hover:text-white" onclick="adminTab(this,'a-overlay')"><i class="fa-solid fa-image mr-1"></i>Overlay</button>
      <?php endif; ?>
    </div>

    <!-- USERS -->
    <div id="a-users" class="admin-section">
      <div class="flex items-center gap-3 mb-4">
        <div class="flex flex-1 items-center bg-slate-900 border border-slate-700 rounded-lg px-4 py-2.5 focus-within:border-blue-500 transition-colors">
          <i class="fa-solid fa-magnifying-glass text-slate-500 mr-2 text-xs"></i>
          <input id="user-search" type="text" placeholder="Search users…" oninput="loadAdminUsers(this.value)"
            class="bg-transparent border-none outline-none flex-1 text-slate-200 placeholder-slate-600 text-sm">
        </div>
        <button onclick="loadAdminUsers()" class="bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 px-3 py-2.5 rounded-lg text-sm transition-colors">
          <i class="fa-solid fa-rotate-right"></i>
        </button>
      </div>
      <div id="admin-users-list" class="space-y-2 max-h-96 overflow-y-auto">
        <p class="text-slate-500 italic text-sm">Loading…</p>
      </div>
    </div>

    <!-- BANS -->
    <div id="a-bans" class="admin-section hidden">
      <div class="flex items-center gap-3 mb-4">
        <div class="flex flex-1 items-center bg-slate-900 border border-slate-700 rounded-lg px-4 py-2.5 focus-within:border-blue-500 transition-colors">
          <i class="fa-solid fa-magnifying-glass text-slate-500 mr-2 text-xs"></i>
          <input id="ban-search" type="text" placeholder="Search banned users…" oninput="loadAdminBans(this.value)"
            class="bg-transparent border-none outline-none flex-1 text-slate-200 placeholder-slate-600 text-sm">
        </div>
        <button onclick="loadAdminBans()" class="bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 px-3 py-2.5 rounded-lg text-sm transition-colors">
          <i class="fa-solid fa-rotate-right"></i>
        </button>
      </div>
      <div id="admin-bans-list" class="space-y-2 max-h-96 overflow-y-auto">
        <p class="text-slate-500 italic text-sm">Loading…</p>
      </div>
    </div>

    <!-- ANNOUNCE -->
    <div id="a-announce" class="admin-section hidden">
      <label class="block text-[10px] uppercase tracking-widest text-red-400/70 font-semibold mb-2">Broadcast to all channels & inboxes</label>
      <textarea id="admin-msg" rows="3" placeholder="Your announcement…"
        class="w-full bg-slate-900 border border-red-500/20 rounded-lg px-4 py-3 text-slate-200 placeholder-slate-600 text-sm outline-none focus:border-red-500/40 transition-colors resize-none mb-3"></textarea>
      <button onclick="adminAnnounce()" class="w-full bg-red-600 hover:bg-red-500 text-white font-semibold py-2.5 rounded-lg text-sm flex items-center justify-center gap-2">
        <i class="fa-solid fa-bullhorn"></i> Dispatch to All
      </button>
    </div>

    <!-- MAINTENANCE -->
    <div id="a-maintenance" class="admin-section hidden">
      <div class="bg-slate-900 border border-slate-700 rounded-xl p-4 mb-4">
        <div class="flex items-center justify-between mb-3">
          <div>
            <p class="text-sm font-semibold text-slate-200">Maintenance Mode</p>
            <p class="text-xs text-slate-500 mt-0.5">Non-admins see a maintenance page instead of chat</p>
          </div>
          <button id="maint-toggle" onclick="toggleMaintenance()"
            class="relative inline-flex w-12 h-6 rounded-full transition-colors bg-slate-700 flex-shrink-0">
            <span id="maint-knob" class="absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full shadow transition-transform"></span>
          </button>
        </div>
        <p id="maint-status-text" class="text-xs font-semibold text-slate-500">Loading…</p>
      </div>
      <div class="mb-3">
        <label class="block text-[10px] uppercase tracking-widest text-slate-500 font-semibold mb-2">Maintenance Message</label>
        <textarea id="maint-msg" rows="2" class="w-full bg-slate-900 border border-slate-700 rounded-lg px-4 py-2.5 text-slate-200 text-sm outline-none focus:border-yellow-500/40 resize-none" placeholder="Message shown to users…"></textarea>
      </div>
      <button onclick="saveMaintMsg()" class="w-full bg-yellow-600/20 hover:bg-yellow-600/30 text-yellow-400 border border-yellow-500/30 font-semibold py-2.5 rounded-lg text-sm flex items-center justify-center gap-2">
        <i class="fa-solid fa-floppy-disk"></i> Save Message
      </button>
    </div>

    <!-- CLEAR CHAT -->
    <div id="a-channel" class="admin-section hidden">
      <p class="text-sm text-slate-400 mb-4">Permanently delete all non-system messages from a channel.</p>
      <div class="mb-4">
        <label class="block text-[10px] uppercase tracking-widest text-slate-500 font-semibold mb-2">Channel</label>
        <select id="clear-channel" class="w-full bg-slate-900 border border-slate-700 rounded-lg px-4 py-2.5 text-slate-200 text-sm outline-none"></select>
      </div>
      <button onclick="clearChannel()" class="w-full bg-red-600/20 hover:bg-red-600/30 text-red-400 border border-red-500/30 font-semibold py-2.5 rounded-lg text-sm flex items-center justify-center gap-2">
        <i class="fa-solid fa-trash"></i> Clear Channel Messages
      </button>
    </div>

    <!-- CHANNELS MGR -->
    <div id="a-channels-mgr" class="admin-section hidden">
      <div class="flex gap-2 mb-4">
        <input id="new-channel-name" type="text" placeholder="New channel name..." class="flex-1 bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 outline-none focus:border-blue-500 transition-colors">
        <button onclick="adminAddChannel()" class="bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded-lg text-sm font-semibold transition-all"><i class="fa-solid fa-plus"></i> Add</button>
      </div>
      <div id="admin-channels-list" class="space-y-2 max-h-96 overflow-y-auto"></div>
    </div>

    <!-- STATS -->
    <div id="a-stats" class="admin-section hidden">
      <div id="admin-stats-grid" class="grid grid-cols-2 gap-4">
         <p class="text-slate-500 italic text-sm">Loading...</p>
      </div>
    </div>

    <!-- PURGE -->
    <div id="a-purge" class="admin-section hidden">
      <p class="text-sm text-slate-400 mb-4">Delete all messages sent by a specific user ID.</p>
      <div class="flex gap-2 mb-4">
        <input id="purge-user-id" type="number" placeholder="User ID..." class="flex-1 bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 outline-none focus:border-red-500 transition-colors">
        <button onclick="adminPurgeUser()" class="bg-red-600 hover:bg-red-500 text-white px-4 py-2 rounded-lg text-sm font-semibold transition-all"><i class="fa-solid fa-fire"></i> Purge</button>
      </div>
    </div>

    <!-- SETTINGS -->
    <div id="a-settings" class="admin-section hidden">
      <div class="space-y-3" id="admin-settings-list">
        <p class="text-slate-500 italic text-sm">Loading...</p>
      </div>
      <button onclick="adminSaveSettings()" class="mt-4 w-full bg-blue-600 hover:bg-blue-500 text-white font-semibold py-2.5 rounded-lg text-sm transition-all"><i class="fa-solid fa-floppy-disk"></i> Save Settings</button>
    </div>

    <!-- SESSIONS -->
    <div id="a-sessions" class="admin-section hidden">
      <div id="admin-sessions-list" class="space-y-2 max-h-96 overflow-y-auto">
        <p class="text-slate-500 italic text-sm">Loading...</p>
      </div>
    </div>

    <!-- FEEDBACKS -->
    <div id="a-feedback" class="admin-section hidden">
      <div class="flex items-center justify-between mb-4">
         <h3 class="text-xs uppercase tracking-widest text-slate-500 font-bold">User Feedback</h3>
         <button onclick="loadAdminFeedback()" class="bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 px-3 py-1.5 rounded-lg text-[10px] transition-colors"><i class="fa-solid fa-rotate-right"></i> Refresh</button>
      </div>
      <div id="admin-feedback-list" class="space-y-2 max-h-96 overflow-y-auto">
        <p class="text-slate-500 italic text-sm">Loading...</p>
      </div>
    </div>

    <!-- BAN TEMPLATES -->
    <div id="a-ban-tpl" class="admin-section hidden">
      <p class="text-sm text-slate-400 mb-4">Set custom HTML to show users instead of the default ban screen. Leave blank for default.</p>
      <div class="space-y-4">
        <div>
          <label class="block text-[10px] uppercase tracking-widest text-slate-500 font-semibold mb-2">Ban Type</label>
          <select id="adm-tpl-type" class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 outline-none focus:border-blue-500">
            <option value="permanent">Account (Permanent)</option>
            <option value="timed">Account (Timed)</option>
            <option value="ip">IP Ban</option>
            <option value="cookie">Cookie Ban</option>
          </select>
        </div>
        <div>
          <label class="block text-[10px] uppercase tracking-widest text-slate-500 font-semibold mb-2">Custom HTML</label>
          <textarea id="adm-tpl-html" rows="8" class="w-full bg-slate-900 border border-slate-700 font-mono text-xs rounded-lg px-3 py-2 text-slate-200 outline-none focus:border-blue-500" placeholder="<html>..."></textarea>
        </div>
        <button onclick="adminSaveBanTemplate()" class="w-full bg-blue-600 hover:bg-blue-500 text-white font-semibold py-2.5 rounded-lg text-sm transition-all"><i class="fa-solid fa-floppy-disk"></i> Save Template</button>
      </div>
    </div>

    <!-- NITRO -->
    <div id="a-nitro" class="admin-section hidden">
      <div class="flex items-center justify-between mb-4">
        <p class="text-sm text-slate-400">Start a challenge. Users who type the secret word exactly will receive Nitro!</p>
        <button onclick="document.getElementById('nitro-info').classList.toggle('hidden')" class="bg-blue-600/20 text-blue-400 hover:text-blue-300 font-bold px-3 py-1.5 rounded text-xs flex items-center gap-1 border border-blue-500/30 transition-colors">
          <i class="fa-solid fa-circle-info"></i> Info
        </button>
      </div>

      <div id="nitro-info" class="hidden mb-6 bg-slate-800/80 border border-slate-700/50 p-4 rounded-xl shadow-inner">
        <h4 class="text-pink-400 font-bold text-sm mb-2 flex items-center gap-2"><i class="fa-solid fa-gem text-xs"></i> Nitro Features</h4>
        <ul class="text-xs text-slate-300 space-y-2 list-disc pl-4 marker:text-pink-500">
          <li><strong>Exclusive Badge:</strong> Shimmering gradient NITRO badge next to their name in chat.</li>
          <li><strong>Website Color Customization:</strong> Customize the application background color in settings.</li>
          <li><strong>Profile Pictures by Image URL:</strong> Use external image links for high-res avatars.</li>
          <li><strong>Animated GIF Avatars:</strong> Set a direct link to a .gif for an animated profile picture.</li>
          <li><strong>Self-Assignable Tags:</strong> Create a custom title tag (e.g., "Developer", "VIP") directly from profile settings.</li>
          <li><strong>Custom Avatar Overlays:</strong> (Managed by Admins) Display special borders or icons right over the user's avatar.</li>
        </ul>
      </div>

      <div class="flex gap-2">
        <input id="nitro-word-input" type="text" placeholder="Secret word or answer..." class="flex-1 bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 outline-none focus:border-pink-500 transition-colors">
        <button onclick="adminStartChallenge()" class="bg-pink-600 hover:bg-pink-500 text-white px-4 py-2 rounded-lg text-sm font-semibold transition-all"><i class="fa-solid fa-play"></i> Start</button>
      </div>
    </div>

    <!-- ROLES -->
    <div id="a-roles" class="admin-section hidden">
      <div class="flex gap-2 mb-2">
        <input id="role-name-input" type="text" placeholder="Role Name" class="flex-1 bg-slate-900 border border-slate-700 rounded-lg px-2 py-2 text-sm text-slate-200 outline-none focus:border-purple-500 transition-colors">
        <input id="role-color-input" type="color" value="#ffffff" class="w-10 h-[38px] bg-slate-900 border border-slate-700 rounded-lg outline-none cursor-pointer">
      </div>
      <div class="mb-4 text-sm text-slate-300 h-48 overflow-y-auto px-2 bg-slate-900 border border-slate-700 rounded-lg py-2">
        <label class="block text-[10px] uppercase tracking-widest text-slate-500 font-semibold mb-2">Allowed Admin Tabs</label>
        <div class="grid grid-cols-2 gap-2 mb-4" id="role-perms-boxes">
          <label><input type="checkbox" value="a-users" class="mr-1"> Users</label>
          <label><input type="checkbox" value="a-bans" class="mr-1"> Bans</label>
          <label><input type="checkbox" value="a-ban-tpl" class="mr-1"> Ban Templates</label>
          <label><input type="checkbox" value="a-announce" class="mr-1"> Announce</label>
          <label><input type="checkbox" value="a-maintenance" class="mr-1"> Maintenance</label>
          <label><input type="checkbox" value="a-channel" class="mr-1"> Clear Chat</label>
          <label><input type="checkbox" value="a-channels-mgr" class="mr-1"> Channels</label>
          <label><input type="checkbox" value="a-stats" class="mr-1"> Stats</label>
          <label><input type="checkbox" value="a-purge" class="mr-1"> Purge</label>
          <label><input type="checkbox" value="a-settings" class="mr-1"> Settings</label>
          <label><input type="checkbox" value="a-sessions" class="mr-1"> Sessions</label>
          <label><input type="checkbox" value="a-roles" class="mr-1"> Roles</label>
          <label><input type="checkbox" value="a-overlay" class="mr-1"> Overlays</label>
        </div>
        <label class="block text-[10px] uppercase tracking-widest text-slate-500 font-semibold mb-2">User Actions</label>
        <div class="grid grid-cols-2 gap-2" id="role-perms-actions">
          <label><input type="checkbox" value="ua-ban" class="mr-1"> Ban User</label>
          <label><input type="checkbox" value="ua-unban" class="mr-1"> Unban User</label>
          <label><input type="checkbox" value="ua-promote" class="mr-1"> Promote/Demote</label>
          <label><input type="checkbox" value="ua-reset" class="mr-1"> Reset Password</label>
          <label><input type="checkbox" value="ua-delete" class="mr-1"> Delete Account</label>
          <label><input type="checkbox" value="ua-kick" class="mr-1"> Kick User</label>
          <label><input type="checkbox" value="ua-mute" class="mr-1"> Mute/Unmute</label>
          <label><input type="checkbox" value="ua-shadowban" class="mr-1"> Shadowban</label>
          <label><input type="checkbox" value="ua-control" class="mr-1"> Control</label>
          <label><input type="checkbox" value="ua-vip" class="mr-1"> Manage VIP</label>
          <label><input type="checkbox" value="ua-avatar" class="mr-1"> Remove Avatar</label>
          <label><input type="checkbox" value="ua-color" class="mr-1"> Reset Color</label>
          <label><input type="checkbox" value="ua-tag" class="mr-1"> Set Tag</label>
          <label><input type="checkbox" value="ua-media" class="mr-1"> Audio/Img Revoke</label>
          <label><input type="checkbox" value="ua-warn" class="mr-1"> Warn User</label>
          <label><input type="checkbox" value="ua-purge" class="mr-1"> Purge User</label>
        </div>
      </div>
      <button onclick="adminCreateRole()" class="w-full bg-purple-600 hover:bg-purple-500 text-white px-3 py-2 rounded-lg text-sm font-semibold transition-all"><i class="fa-solid fa-plus"></i> Create Role</button>
      
      <div id="admin-roles-list" class="space-y-2 max-h-96 overflow-y-auto mt-4">
         <p class="text-slate-500 italic text-sm">Loading...</p>
      </div>
    </div>

    <!-- AVATAR OVERLAY -->
    <div id="a-overlay" class="admin-section hidden">
      <p class="text-sm text-slate-400 mb-4">Apply PNG masks/frames to user avatars.</p>
      <div class="flex gap-4">
        <!-- Preview Box -->
        <div class="w-24 flex-shrink-0 flex flex-col items-center gap-2">
            <div class="relative w-16 h-16 flex items-center justify-center">
                <div class="w-full h-full rounded-full bg-slate-800 border-2 border-slate-700 overflow-hidden flex items-center justify-center">
                   <span class="text-xl font-bold text-slate-500">?</span>
                </div>
                <img id="overlay-preview-img" src="" class="absolute pointer-events-none hidden" style="width:100%; height:100%; top:0; left:0; object-fit:contain; z-index:10;">
            </div>
            <span class="text-[10px] text-slate-500 uppercase tracking-widest font-semibold mt-1">Preview</span>
        </div>
        
        <!-- Controls -->
        <div class="flex-1 space-y-3">
          <div class="flex gap-2">
            <input id="overlay-uid" type="number" placeholder="User ID" class="w-24 bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 outline-none">
            <input id="overlay-url" oninput="updateOverlayPreview()" type="text" placeholder="Image URL (PNG ideal)" class="flex-1 bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 outline-none">
          </div>
          <div class="flex gap-2 items-center text-sm text-slate-400">
            <label>Scale: <input id="overlay-scale" min="0.1" max="3" step="0.1" value="1" type="number" oninput="updateOverlayPreview()" class="w-16 bg-slate-900 border border-slate-700 rounded px-1"></label>
            <label>X: <input id="overlay-x" type="number" value="0" oninput="updateOverlayPreview()" class="w-14 bg-slate-900 border border-slate-700 rounded px-1"></label>
            <label>Y: <input id="overlay-y" type="number" value="0" oninput="updateOverlayPreview()" class="w-14 bg-slate-900 border border-slate-700 rounded px-1"></label>
          </div>
          <button onclick="adminSetOverlay()" class="w-full bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded-lg text-sm font-semibold transition-all">Apply Overlay</button>
        </div>
      </div>
    </div>

  </div>
</div>
<?php endif;?>

<!-- ══ USER ACTION MODAL (admin) ════════════════════════════════════════════ -->
<?php if($isAdmin):?>
<div class="modal-bg" id="user-action-modal">
  <div class="modal-box" style="max-width:460px">
    <div class="flex items-center justify-between mb-4">
      <h2 class="text-base font-bold text-slate-100 flex items-center gap-2"><i class="fa-solid fa-user-shield text-blue-400"></i> User Actions</h2>
      <button onclick="closeModal('user-action-modal')" class="text-slate-500 hover:text-white"><i class="fa-solid fa-xmark"></i></button>
    </div>

    <!-- User info card -->
    <div id="ua-info" class="bg-slate-800 rounded-xl p-3 mb-4 text-sm text-slate-300"></div>

    <!-- Ban info panel (shown when user is already banned) -->
    <div id="ua-ban-info" class="hidden bg-red-500/8 border border-red-500/20 rounded-xl p-3.5 mb-4">
      <p class="text-[10px] uppercase tracking-widest text-red-400/70 font-semibold mb-2.5"><i class="fa-solid fa-ban mr-1"></i>Active Ban Details</p>
      <div class="space-y-1.5 text-sm">
        <div class="flex justify-between"><span class="text-slate-500">Reason</span><span id="ua-ban-reason" class="text-slate-200 text-right max-w-[220px] truncate">—</span></div>
        <div class="flex justify-between"><span class="text-slate-500">Duration</span><span id="ua-ban-duration" class="text-slate-200">—</span></div>
        <div class="flex justify-between"><span class="text-slate-500">Expires</span><span id="ua-ban-expires" class="text-slate-200">—</span></div>
        <div class="flex justify-between"><span class="text-slate-500">Banned by</span><span id="ua-ban-by" class="text-slate-200">—</span></div>
      </div>
    </div>

    <!-- Action buttons -->
    <div class="space-y-2" id="ua-buttons"></div>

    <!-- Ban form (hidden until "Ban User" clicked) -->
    <div id="ua-ban-section" class="hidden mt-4 pt-4 border-t border-slate-800 space-y-3">
      <p class="text-[10px] uppercase tracking-widest text-red-400/80 font-semibold"><i class="fa-solid fa-ban mr-1"></i>Ban User</p>

      <div>
        <label class="block text-[10px] uppercase tracking-widest text-slate-500 font-semibold mb-1.5">Ban Reason <span class="text-slate-600 normal-case">(shown to user)</span></label>
        <div class="flex gap-2">
          <input id="ua-ban-icon-inp" type="text" placeholder="Emoji/Icon (e.g. 🤡 or fa-skull)" 
            class="w-1/3 bg-slate-900 border border-slate-700 rounded-lg px-3 py-2.5 text-slate-200 placeholder-slate-600 text-sm outline-none focus:border-red-500/60 transition-colors">
          <input id="ua-ban-reason-inp" type="text" placeholder="e.g. Spamming, rule violation…"
            class="flex-1 bg-slate-900 border border-slate-700 rounded-lg px-3 py-2.5 text-slate-200 placeholder-slate-600 text-sm outline-none focus:border-red-500/60 transition-colors">
        </div>
      </div>

      <div>
        <label class="block text-[10px] uppercase tracking-widest text-slate-500 font-semibold mb-1.5">Duration</label>
        <div class="flex gap-2">
          <select id="ua-ban-type" onchange="toggleBanTime()" class="bg-slate-900 border border-slate-700 rounded-lg px-3 py-2.5 text-slate-200 text-sm outline-none focus:border-red-500/60 transition-colors flex-shrink-0">
            <option value="permanent">Account (Permanent)</option>
            <option value="timed">Account (Timed)</option>
            <option value="ip">IP Ban (Network)</option>
            <option value="cookie">Cookie Ban (Device)</option>
          </select>
          <div id="ua-ban-time-wrap" class="hidden flex-1 flex gap-2">
            <input id="ua-ban-amount" type="number" min="1" value="1" placeholder="Amount"
              class="flex-1 bg-slate-900 border border-slate-700 rounded-lg px-3 py-2.5 text-slate-200 text-sm outline-none focus:border-red-500/60 transition-colors min-w-0">
            <select id="ua-ban-unit" class="bg-slate-900 border border-slate-700 rounded-lg px-3 py-2.5 text-slate-200 text-sm outline-none focus:border-red-500/60 transition-colors flex-shrink-0">
              <option value="minutes">Minutes</option>
              <option value="hours">Hours</option>
              <option value="days" selected>Days</option>
              <option value="weeks">Weeks</option>
            </select>
          </div>
        </div>
      </div>

      <div id="ua-ban-preview" class="text-xs text-slate-500 italic hidden"></div>

      <div class="flex gap-2 pt-1">
        <button onclick="submitBan()"
          class="flex-1 bg-red-600 hover:bg-red-500 text-white font-semibold py-2.5 rounded-lg text-sm transition-all flex items-center justify-center gap-2">
          <i class="fa-solid fa-gavel"></i> Confirm Ban
        </button>
        <button onclick="document.getElementById('ua-ban-section').classList.add('hidden')"
          class="px-4 py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-400 rounded-lg text-sm border border-slate-700 transition-colors">
          Cancel
        </button>
      </div>
    </div>

    <!-- Reset password subsection -->
    <div id="ua-pw-section" class="hidden mt-4 pt-4 border-t border-slate-800">
      <p class="text-[10px] uppercase tracking-widest text-slate-500 font-semibold mb-2.5"><i class="fa-solid fa-key mr-1"></i>Reset Password</p>
      <div class="flex gap-2">
        <input id="ua-new-pw" type="text" placeholder="New password (min 6 chars)"
          class="flex-1 bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-slate-200 text-sm outline-none focus:border-blue-500 transition-colors">
        <button onclick="doResetPw()" class="bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded-lg text-sm font-semibold transition-all">Set</button>
      </div>
    </div>

    <!-- Extended actions subsection -->
    <div id="ua-ext-section" class="hidden mt-4 pt-4 border-t border-slate-800">
      <p class="text-[10px] uppercase tracking-widest text-slate-500 font-semibold mb-2.5"><i class="fa-solid fa-ellipsis-h mr-1"></i>Extended Actions</p>
      <div class="space-y-2" id="ua-extended-buttons"></div>
    </div>
  </div>
</div>
<?php endif;?>

<!-- ══ FEEDBACK / BUG MODAL ════════════════════════════════════════════════════ -->
<div class="modal-bg" id="bug-modal">
  <div class="modal-box" style="max-width:420px; border-color: rgba(249,115,22,.3);">
    <div class="flex items-center justify-between mb-4">
      <h2 class="text-base font-bold text-orange-400 flex items-center gap-2"><i class="fa-solid fa-bug"></i> Report Bug / Feedback</h2>
      <button onclick="closeModal('bug-modal')" class="text-slate-500 hover:text-white"><i class="fa-solid fa-xmark"></i></button>
    </div>
    <p class="text-xs text-slate-400 mb-4">
      Found a bug? Have a suggestion? Send it directly to the platform developer (gollclock).
    </p>
    <textarea id="bug-message" rows="4" placeholder="Describe the issue or feedback in detail..." class="w-full bg-slate-900 border border-slate-700/60 rounded-xl px-3 py-2 text-sm text-slate-200 outline-none focus:border-orange-500 transition-colors mb-4 resize-none"></textarea>
    <div class="flex justify-end gap-2">
       <button onclick="closeModal('bug-modal')" class="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-400 rounded-lg text-sm border border-slate-700 transition">Cancel</button>
       <button onclick="submitBug(event)" class="px-4 py-2 bg-orange-600 hover:bg-orange-500 text-white rounded-lg text-sm font-semibold transition flex items-center gap-2"><i class="fa-solid fa-paper-plane"></i> Send Report</button>
    </div>
  </div>
</div>

<!-- ══ WORDLE MODAL ════════════════════════════════════════════════════════════ -->
<div class="modal-bg" id="wordle-modal">
  <div class="modal-box relative overflow-hidden" style="max-width:380px; padding: 1.5rem 1rem;">
    <div class="flex items-center justify-between mb-4">
      <h2 class="text-xl font-black text-slate-100 uppercase tracking-widest"><i class="fa-solid fa-gamepad text-emerald-400 mr-2"></i>Wordle</h2>
      <button onclick="closeModal('wordle-modal')" class="text-slate-500 hover:text-white"><i class="fa-solid fa-xmark"></i></button>
    </div>
    <div id="wordle-feedback" class="h-6 flex items-center justify-center font-semibold text-sm rounded bg-slate-800 text-white mb-2 opacity-0 transition-opacity"></div>
    
    <!-- Grid -->
    <div id="wordle-grid" class="grid grid-rows-6 gap-2 w-full max-w-[280px] mx-auto mb-6">
      <!-- Generated by JS -->
    </div>
    
    <!-- Keyboard -->
    <div id="wordle-keyboard" class="w-full select-none flex flex-col gap-2 items-center mx-auto text-sm mb-4">
      <!-- Generated by JS -->
    </div>
    
    <button id="wordle-replay-btn" onclick="forceWordleReset()" class="hidden w-full max-w-[280px] mx-auto py-2.5 bg-emerald-600 hover:bg-emerald-500 text-slate-100 font-bold rounded-lg transition-colors text-sm mb-4">
      <i class="fa-solid fa-rotate-right mr-1"></i> Play Again
    </button>

    <!-- Info Button -->
    <button onclick="document.getElementById('wordle-help').classList.remove('hidden')" class="absolute bottom-4 left-4 w-7 h-7 rounded-full bg-slate-800 border border-slate-700 text-slate-400 hover:text-white hover:bg-slate-700 flex items-center justify-center transition-colors">
      <i class="fa-solid fa-info text-xs"></i>
    </button>

    <!-- Instructions Overlay -->
    <div id="wordle-help" class="hidden absolute inset-0 bg-slate-900 z-10 flex flex-col items-center justify-center text-left p-6">
      <button onclick="document.getElementById('wordle-help').classList.add('hidden')" class="absolute top-5 right-5 text-slate-500 hover:text-white transition-colors">
        <i class="fa-solid fa-xmark text-lg"></i>
      </button>
      <h3 class="text-xl font-black text-white mb-4 uppercase tracking-wider">How To Play</h3>
      <p class="text-sm text-slate-300 w-full mb-4">Guess the Wordle in 6 tries.</p>
      <ul class="text-xs text-slate-400 space-y-3 w-full mb-6">
        <li class="flex items-start gap-2"><div class="w-1.5 h-1.5 rounded-full bg-slate-600 mt-1 flex-shrink-0"></div>Each guess must be a valid 5-letter word.</li>
        <li class="flex items-start gap-2"><div class="w-1.5 h-1.5 rounded-full bg-slate-600 mt-1 flex-shrink-0"></div>The color of the tiles will change to show how close your guess was to the word.</li>
        <li class="flex items-start gap-2"><div class="w-1.5 h-1.5 rounded-full bg-emerald-500 mt-1 flex-shrink-0"></div><span class="text-emerald-400 font-bold">Green:</span> The letter is in the word and in the correct spot.</li>
        <li class="flex items-start gap-2"><div class="w-1.5 h-1.5 rounded-full bg-yellow-500 mt-1 flex-shrink-0"></div><span class="text-yellow-400 font-bold">Yellow:</span> The letter is in the word but in the wrong spot.</li>
        <li class="flex items-start gap-2"><div class="w-1.5 h-1.5 rounded-full bg-slate-500 mt-1 flex-shrink-0"></div><span class="font-bold text-white">Grey:</span> The letter is not in the word in any spot.</li>
      </ul>
      <button onclick="document.getElementById('wordle-help').classList.add('hidden')" class="w-full py-2.5 bg-blue-600 hover:bg-blue-500 text-white font-bold rounded-lg transition-colors text-sm">Play</button>
    </div>
  </div>
</div>

<!-- ══ SCRIPTS ════════════════════════════════════════════════════════════════ -->
<script>
// ── State ──────────────────────────────────────────────────────────────────
let currentChannel=1,currentChannelName='general',currentChannelType='text';
let lastMsgId=0,oldestMsgId=Infinity,channels=[],newAvatar=null,maintOn=false;
let mediaRecorder=null,audioChunks=[],voiceActive=false,voiceTimer=null,voiceSeconds=0;
let actionTargetUser=null;
let knownOnlineIds=new Set(), knownChannelIds=new Set(), knownMessageIds=new Set();
let firstLoad={members:true,channels:true,msgs:true,bannedCheck:true};
const ME={
  id:<?=$uid?>,username:<?=json_encode($uname)?>,
  color:<?=json_encode($meRow['name_color'])?>,
  avatar:<?=$meRow['avatar']?json_encode($meRow['avatar']):'null'?>,
  isAdmin:<?=$isAdmin?'true':'false'?>,
  isSuperAdmin:<?=$isSuperAdmin?'true':'false'?>,
  perms:<?=json_encode($myPerms)?>
};

// ── Boot ───────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded',async()=>{
  loadLayoutState();
  twemoji.parse(document.body);

  const showBlocker = () => {
    document.querySelector('.app-grid').style.display = 'none';
    let blocker = document.getElementById('notif-blocker');
    if(!blocker) {
      blocker = document.createElement('div');
      blocker.id = 'notif-blocker';
      blocker.className = 'fixed inset-0 z-[9999] flex items-center justify-center bg-slate-900/95 backdrop-blur-md text-white p-6 text-center';
      blocker.innerHTML = `
        <div class="bg-slate-800 p-8 rounded-xl shadow-2xl max-w-md w-full border border-slate-700">
          <i class="fa-solid fa-bell-slash text-4xl text-red-400 mb-4"></i>
          <h2 class="text-2xl font-bold mb-2">Notifications Required</h2>
          <p class="text-slate-400 mb-6 text-sm">To ensure you receive messages and updates, you must allow notifications to use BetterChat.</p>
          <button onclick="requestFromBlocker()" class="w-full bg-blue-600 hover:bg-blue-500 text-white px-4 py-3 rounded-lg font-medium transition-colors shadow-lg">Grant Permission</button>
          <p id="notif-help" class="text-xs text-slate-500 mt-4 hidden">If you previously blocked notifications, you need to click the lock icon next to the URL bar and change Notifications to "Allow", then refresh the page.</p>
        </div>
      `;
      document.body.appendChild(blocker);
    }
  };

  const initApp = async () => {
    document.querySelector('.app-grid').style.display = 'grid';
    const blocker = document.getElementById('notif-blocker');
    if(blocker) blocker.remove();

    if('serviceWorker' in navigator) {
      navigator.serviceWorker.register('/sw.js').then(reg => {
        window.swRegistration = reg;
        if ('Notification' in window && Notification.permission === 'granted') {
          subscribeToPush(reg);
        }
      }).catch(e => console.error('SW Error', e));
    }

    await loadChannels();
    await loadMsgs(true);
    loadMembers(); loadFriends(); pollInbox();
    if(ME.isAdmin){checkMaintStatus(); populateClearSelect();}
    setInterval(loadChannels,30000);
    setInterval(async () => {
      await loadMsgs(false);
      if(currentChannel){
        const rT = await api('get_typing', {channel_id: currentChannel});
        if(rT.ok) renderTyping(rT.typing);
      }
    },2000);
    setInterval(loadMembers,15000);
    setInterval(loadFriends,20000);
    setInterval(pollInbox,20000);
    document.querySelectorAll('.modal-bg').forEach(el=>
      el.addEventListener('click',e=>{if(e.target===el)el.classList.remove('open');}));
  };

  window.requestFromBlocker = async () => {
    if (!('Notification' in window)) {
      alert('Your browser does not support notifications.');
      return;
    }
    try {
      const perm = await Notification.requestPermission();
      if (perm === 'granted') {
        initApp();
      } else {
        document.getElementById('notif-help')?.classList.remove('hidden');
      }
    } catch(e) { console.error(e); }
  };

  // Always load the app — notifications are optional, not a gate
  initApp();

  // Softly prompt for notifications after app loads if not yet decided
  if ('Notification' in window && 'PushManager' in window && Notification.permission === 'default') {
    setTimeout(async () => {
      const perm = await Notification.requestPermission().catch(() => 'denied');
      if (perm === 'granted' && window.swRegistration) {
        subscribeToPush(window.swRegistration);
      }
    }, 3000);
  }
});

async function subscribeToPush(reg) {
  try {
    const vapidRes = await api('get_vapid_key');
    if(!vapidRes.ok || !vapidRes.publicKey) return;

    const base64ToUint8Array = base64String => {
      const padding = '='.repeat((4 - base64String.length % 4) % 4);
      const base64 = (base64String + padding).replace(/\-/g, '+').replace(/_/g, '/');
      const rawData = window.atob(base64);
      const outputArray = new Uint8Array(rawData.length);
      for (let i = 0; i < rawData.length; ++i) {
        outputArray[i] = rawData.charCodeAt(i);
      }
      return outputArray;
    };

    const sub = await reg.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: base64ToUint8Array(vapidRes.publicKey)
    });

    const p256dh = btoa(String.fromCharCode.apply(null, new Uint8Array(sub.getKey('p256dh'))));
    const auth = btoa(String.fromCharCode.apply(null, new Uint8Array(sub.getKey('auth'))));

    await api('subscribe_push', {
      endpoint: sub.endpoint,
      p256dh: p256dh,
      auth: auth
    }, 'POST');
    console.log('Subscribed to offline Web Push successfully!');
  } catch(e) {
    console.error('Failed to subscribe to push:', e);
  }
}

// ── Notifications ──────────────────────────────────────────────────────────
function sendPush(title, body) {
  if (!('Notification' in window)) return;
  if (Notification.permission === 'granted') {
    if (document.hidden || !document.hasFocus()) {
      navigator.serviceWorker.ready.then(reg => {
        reg.showNotification(title, { body, icon: '/favicon.ico', badge: '/favicon.ico', autoClose: 5000 });
      }).catch(err => {
        // Fallback if SW not active
        new Notification(title, { body, icon: '/favicon.ico' });
      });
    }
  }
}

// ── API ─────────────────────────────────────────────────────────────────────
async function api(action,data={},method='GET'){
  try{
    let url=`api.php?action=${action}`;
    const opts={method};
    if(method==='POST'){const fd=new FormData();Object.entries(data).forEach(([k,v])=>fd.append(k,v));opts.body=fd;}
    else url+='&'+new URLSearchParams(data);
    const res = await fetch(url,opts);
    if(res.status === 401 || res.status === 403) {
      if(!firstLoad.bannedCheck) sendPush('Access Denied', 'You have been logged out or banned');
      firstLoad.bannedCheck = false;
    }
    const json = await res.json();
    if(json && json.banned_until !== undefined && !firstLoad.bannedCheck) {
      sendPush('Access Denied', 'You have been banned from the server.');
      firstLoad.bannedCheck = false;
      setTimeout(() => location.reload(), 2000);
    }
    firstLoad.bannedCheck = false;
    return json;
  }catch(e){return{ok:false,error:e.message};}
}

// ── Channels ───────────────────────────────────────────────────────────────
async function loadChannels(){
  const r=await api('get_channels');if(!r.ok)return;
  channels=r.channels;
  
  if(!firstLoad.channels) {
    channels.forEach(ch => {
      if(!knownChannelIds.has(ch.id)) {
        sendPush('New Channel Added', `#${ch.name} was just created!`);
        knownChannelIds.add(ch.id);
      }
    });
  } else {
    channels.forEach(ch => knownChannelIds.add(ch.id));
    firstLoad.channels = false;
  }

  const list=document.getElementById('channel-list');list.innerHTML='';
  channels.forEach(ch=>{
    const el=document.createElement('button');
    el.className='channel-btn w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-left transition-colors '+
      (ch.id==currentChannel?'active text-slate-200':'text-slate-400 hover:text-slate-200');
    el.dataset.id=ch.id;
    const icon = ch.type === 'announcement' ? 'fa-bullhorn' : 'fa-hashtag';
    el.innerHTML=`<i class="fa-solid ${icon} text-xs text-slate-600 flex-shrink-0"></i><span class="text-sm font-medium truncate">${esc(ch.name)}</span>`;
    el.onclick=()=>switchChannel(+ch.id,ch.name,ch.type);
    list.appendChild(el);
  });
  twemoji.parse(list);
}

async function switchChannel(id,name,type){
  currentChannel=id;currentChannelName=name||'general';currentChannelType=type||'text';lastMsgId=0;oldestMsgId=Infinity;
  document.querySelectorAll('.channel-btn').forEach(b=>{
    b.className='channel-btn w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-left transition-colors '+
      (b.dataset.id==id?'active text-slate-200':'text-slate-400 hover:text-slate-200');
  });
  
  const icon = type === 'announcement' ? 'fa-bullhorn' : 'fa-hashtag';
  document.getElementById('header-ch-name').previousElementSibling.className = `fa-solid ${icon} text-xs`;
  document.getElementById('header-ch-name').textContent=name;
  twemoji.parse(document.getElementById('header-ch-name'));
  document.getElementById('msg-input').placeholder=`Message #${name}…`;
  document.getElementById('messages').innerHTML='';
  
  if (document.getElementById('call-btn')) document.getElementById('call-btn').classList.add('hidden');

  document.getElementById('messages').classList.remove('hidden');
  document.querySelector('.px-4.pb-4.pt-2.border-t').classList.remove('hidden');
  await loadMsgs(true);
}

// ── Messages ───────────────────────────────────────────────────────────────
async function loadMsgs(initial, fetchOlder=false){
  if(fetchOlder) document.getElementById('load-more-btn').textContent = 'Loading...';
  const params={channel_id:currentChannel};
  if(fetchOlder && oldestMsgId !== Infinity) params.before_id = oldestMsgId;
  else if(!initial&&lastMsgId>0)params.after_id=lastMsgId;
  const r=await api('get_messages',params);
  if(!initial && fetchOlder) {
    if(document.getElementById('load-more-btn')) document.getElementById('load-more-btn').remove();
  }
  if(!r.ok||!r.messages.length) {
    if(initial) { oldestMsgId = Infinity; }
    return;
  }
  const feed=document.getElementById('messages');
  const atBottom=feed.scrollHeight-feed.scrollTop<=feed.clientHeight+60;
  
  if (initial || fetchOlder) {
    const oldestInBatch = Math.min(...r.messages.map(m => +m.id));
    if (oldestInBatch < oldestMsgId) oldestMsgId = oldestInBatch;
  }

  let scrollHeightBefore = feed.scrollHeight;

  const fragment = document.createDocumentFragment();
  r.messages.forEach(m=>{
    if(m.id>lastMsgId)lastMsgId=+m.id;
    if(document.getElementById('msg-'+m.id))return;
    
    if(!initial && !fetchOlder && m.user_id != ME.id && document.hidden) {
      if(!knownMessageIds.has(m.id)) {
        let title = m.username + (currentChannelType === 'dm' ? ' (DM)' : ` in #${currentChannelName}`);
        let body = m.msg_type === 'image' ? 'Sent an image' : (m.msg_type === 'file' ? 'Sent a file' : m.content);
        if (m.msg_type === 'webrtc') {
            try {
                const pj = JSON.parse(m.content);
                if (pj.type === 'call_request') body = '📞 Is calling you...';
                else body = false; // Don't push for ICE or Answer things
            } catch(e) { body = false; }
        }
        if (body !== false) sendPush(title, typeof body === 'string' ? body : 'New message');
        knownMessageIds.add(m.id);
      }
    }

    if (m.msg_type === 'webrtc') {
      let isCallReq = false;
      try {
        const pj = JSON.parse(m.content);
        if (pj.type === 'call_request') isCallReq = true;
      } catch(e) {}

      if (m.user_id != ME.id) {
        try {
          const payload = JSON.parse(m.content);
          handleWebrtcMessage(payload, m.user_id, m.username, m.channel_id);
        } catch(e) {}
      }
      
      if (!isCallReq) return;
    }

    if(+m.is_system||m.msg_type==='system'){
      if(!initial && !fetchOlder) toast(m.content, 'info');
      return;
    }
    
    fragment.appendChild(buildMsg(m));
  });

  if (fetchOlder) feed.insertBefore(fragment, feed.firstChild);
  else feed.appendChild(fragment);

  // Add load more button if we fetched a full batch (meaning there might be more)
  if ((initial || fetchOlder) && r.messages.length >= 20) {
     const btn = document.createElement('button');
     btn.id = 'load-more-btn';
     btn.className = 'w-full py-4 text-xs text-slate-500 hover:text-slate-300 font-semibold mb-4 transition-colors flex items-center justify-center gap-2';
     btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Loading older messages...';
     btn.onclick = () => loadMsgs(false, true);
     feed.insertBefore(btn, feed.firstChild);

     // Auto-trigger when visible
     const observer = new IntersectionObserver((entries) => {
       if (entries[0].isIntersecting) {
         observer.disconnect();
         btn.click();
       }
     }, { root: feed, rootMargin: '100px' });
     observer.observe(btn);
  }

  if(initial||atBottom)feed.scrollTop=feed.scrollHeight;
  else if(fetchOlder) feed.scrollTop = feed.scrollHeight - scrollHeightBefore;
  
  twemoji.parse(feed);
}

function buildMsg(m){
  const el=document.createElement('div');
  el.id='msg-'+m.id;

  const color=m.name_color||'#3b82f6';
  const isAdminSender=m.sender_is_admin==1||m.sender_is_admin===true;
  let overlayHtml = '';
  if (m.avatar_overlay) {
    try {
      const ov = JSON.parse(m.avatar_overlay);
      if(ov.url) {
         overlayHtml = `<img src="${esc(ov.url)}" style="position:absolute; width:100%; height:100%; top:${ov.y||0}%; left:${ov.x||0}%; transform:scale(${ov.scale||1}); pointer-events:none; z-index:10; object-fit:contain;">`;
      }
    } catch(e){}
  }

  const av=m.avatar?`<img src="${m.avatar}" class="w-full h-full object-cover">`
    :`<div class="w-full h-full flex items-center justify-center bg-black/20"><span class="text-xs font-bold" style="color:${color}">${esc((m.username||'?')[0].toUpperCase())}</span></div>`;
  const canDel=ME.isAdmin||m.user_id==ME.id;
  const canEdit=ME.isAdmin||(m.user_id==ME.id&&(m.msg_type==='text'||m.msg_type==='image'));

  // Build body based on type
  let body='';
  const type=m.msg_type||'text';
  let content = esc(m.content);
  
  if (type === 'webrtc') {
    let pj = {};
    try { pj = JSON.parse(m.content); } catch(e){}
    if (pj.type === 'call_request') {
       const isMyCall = m.user_id == ME.id;
       const btnHtml = isMyCall ? `<span class="text-xs text-slate-400 font-semibold bg-slate-800 px-3 py-1 rounded-full text-center mt-2 border border-slate-700 w-full">Outgoing Call</span>` 
          : `<button class="w-full bg-green-500 hover:bg-green-400 text-white px-4 py-2 mt-2 rounded-lg font-bold shadow-lg transition-transform hover:scale-105 flex items-center justify-center gap-2" onclick="joinCallFromChat('${pj.callId}', ${m.user_id}, '${esc(m.username)}', ${m.channel_id})"><i class="fa-solid fa-phone"></i> Join Call</button>`;
          
       el.className='msg-row flex gap-3 w-full group mb-4';
       el.innerHTML=`
          <div class="relative w-10 h-10 flex-shrink-0 self-start">
            <div class="w-full h-full rounded-full bg-slate-800 overflow-hidden shadow-sm">
                ${av}
            </div>
            ${overlayHtml}
          </div>
          <div class="flex flex-col min-w-0" style="max-width:320px; width: 100%;">
             <div class="flex items-baseline gap-2 mb-1">
                <span class="font-bold text-[15px]" style="color:${color}">${esc(m.username)}</span>
             </div>
             <div class="bg-slate-800/80 border border-slate-700/50 rounded-xl p-4 flex flex-col items-center gap-2 shadow-sm">
               <div class="w-16 h-16 rounded-full bg-slate-700 flex items-center justify-center p-1 mb-1 shadow-inner border border-slate-600">
                  ${av}
               </div>
               <div class="text-slate-200 font-medium text-center text-sm leading-tight">${isMyCall ? 'You started a call' : esc(m.username) + ' is calling you'}</div>
               ${btnHtml}
             </div>
          </div>
       `;
       return el;
    }
  }

  // Replace announcement emoji with SVG
  content = content.replace(/📢/g, '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" class="inline-block w-4 h-4 text-red-500 fill-current mr-1"><path d="M480 32c0-12.9-7.8-24.6-19.8-29.6s-25.7-2.2-34.9 6.9L381.7 53c-48 48-113.1 75-181 75H192 160 64c-35.3 0-64 28.7-64 64v96c0 35.3 28.7 64 64 64h96 32 8.7c67.9 0 133 27 181 75l43.6 43.6c9.2 9.2 22.9 11.9 34.9 6.9s19.8-16.6 19.8-29.6V300.4c18.6-8.8 32-32.5 32-60.4s-13.4-51.6-32-60.4V32zm-64 76.7V240 272v131.3c-52.3-49.6-118-77.3-188-77.3H192V186h36c70 0 135.7-27.7 188-77.3zM64 288v-96h96v96H64z"/></svg>');

  if(m.content&&type!=='iframe')body+=`<p class="text-sm text-slate-300 leading-relaxed break-words">${content}</p>`;
  if(m.edited_at)body+=`<span class="text-[10px] text-slate-600 italic"> (edited)</span>`;

  if(type==='image'&&m.image_data) {
    const isGif = m.image_data.includes('giphy.com');
    const imgClass = isGif ? "max-w-full rounded-xl mt-2" : "max-w-xs max-h-64 rounded-xl border border-slate-700 mt-2 cursor-zoom-in hover:scale-[1.02] transition-transform";
    const onClick = isGif ? "" : `onclick="zoomImg(this.src)"`;
    body+=`<img src="${m.image_data}" class="${imgClass}" ${onClick}>`;
  }

  if(type==='audio'&&m.file_data) {
    body+=`<div class="audio-msg-container mt-2 bg-slate-800/50 border border-slate-700/50 rounded-xl p-3 flex items-center gap-3 max-w-[340px]">
      <button onclick="toggleAudioPlay(this, '${m.file_data}')" class="w-10 h-10 rounded-full bg-blue-600 hover:bg-blue-500 flex items-center justify-center text-white flex-shrink-0 transition-colors shadow-lg shadow-blue-900/20">
        <i class="fa-solid fa-play ml-0.5"></i>
      </button>
      <div class="flex-1 min-w-0">
        <div class="h-2 bg-slate-700 rounded-full overflow-hidden mb-1.5 relative cursor-pointer" onclick="seekAudio(event, this)">
          <div class="audio-progress absolute top-0 left-0 h-full bg-blue-500 w-0 rounded-full pointer-events-none"></div>
        </div>
        <div class="flex justify-between items-center text-[10px] text-slate-400 font-medium">
          <span class="audio-time">0:00</span>
          <span class="audio-duration">Voice</span>
        </div>
      </div>
      <div class="flex flex-col gap-1 flex-shrink-0">
        <div class="flex items-center bg-slate-700 rounded px-1">
          <input type="number" step="any" value="1" oninput="changeAudioSpeed(this)" class="audio-speed-input w-10 bg-transparent text-[10px] text-slate-300 text-center outline-none" title="Playback Speed">
          <span class="text-[10px] text-slate-400 pr-0.5">x</span>
        </div>
        <a href="#" onclick="downloadFile(event, '${m.file_data}', 'voice_message.webm')" class="text-[10px] bg-slate-700 hover:bg-slate-600 px-1.5 py-0.5 rounded text-slate-300 transition-colors text-center"><i class="fa-solid fa-download"></i></a>
      </div>
    </div>`;
  }

  if(type==='file'&&m.file_data){
    const icon=fileIcon(m.file_mime||'');
    body+=`<div class="file-msg mt-2">
      <i class="${icon} text-blue-400 text-xl flex-shrink-0"></i>
      <div class="flex-1 min-w-0"><p class="text-sm font-medium text-slate-200 truncate">${esc(m.file_name||'file')}</p>
      <p class="text-xs text-slate-500">${esc(m.file_mime||'')}</p></div>
      <a href="#" onclick="downloadFile(event, '${m.file_data}', '${esc(m.file_name||'file')}')"
        class="bg-blue-600 hover:bg-blue-500 text-white px-3 py-1.5 rounded-lg text-xs font-semibold transition-all flex-shrink-0">
        <i class="fa-solid fa-download mr-1"></i>Download</a>
    </div>`;
  }

  if(type==='iframe'){
    const url=m.content||'';
    const label=m.file_name||url;
    body+=`<div class="iframe-msg mt-2">
      <div class="bg-slate-800 px-3 py-2 flex items-center justify-between border-b border-slate-700">
        <span class="text-xs text-slate-400 truncate flex-1"><i class="fa-solid fa-globe mr-1.5 text-blue-400"></i>${esc(label)}</span>
        <a href="${esc(url)}" target="_blank" class="text-xs text-blue-400 hover:underline ml-2 flex-shrink-0">Open <i class="fa-solid fa-external-link-alt text-[10px]"></i></a>
      </div>
      <iframe src="${esc(url)}" sandbox="allow-scripts allow-same-origin allow-forms allow-popups" loading="lazy"></iframe>
    </div>`;
  }

  const editedLabel=m.edited_at?`<span class="text-[10px] text-slate-600 italic ml-1">(edited)</span>`:'';
  const adminBadge=isAdminSender?`<span class="text-[10px] bg-red-500/20 text-red-400 border border-red-500/30 px-1.5 py-0.5 rounded font-bold ml-1">ADMIN</span>`:'';
  const customTag = m.custom_tag ? `<span class="text-[10px] px-1.5 py-0.5 rounded font-bold ml-1 whitespace-nowrap" style="color:${esc(m.custom_tag_color||'#ef4444')};background-color:${esc(m.custom_tag_color||'#ef4444')}33;border: 1px solid ${esc(m.custom_tag_color||'#ef4444')}40;">${esc(String(m.custom_tag).toUpperCase())}</span>` : '';
  const nitroBadge = m.is_nitro ? `<span class="text-[10px] px-1 py-0.5 rounded ml-1 bg-gradient-to-r from-pink-500 to-purple-500 text-white font-bold inline-flex items-center gap-1 shadow-[0_0_10px_rgba(236,72,153,0.5)]"><i class="fa-solid fa-gem text-[8px]"></i> NITRO</span>` : '';

  let replyUI = '';
  if (m.reply_to) {
    replyUI = `<div class="text-[10px] text-slate-400 font-medium mb-0.5 mt-[-2px] truncate flex items-center gap-1 cursor-pointer hover:text-slate-300" onclick="document.getElementById('msg-${m.reply_to}')?.scrollIntoView({behavior:'smooth',block:'center'})">
                 <i class="fa-solid fa-reply fa-rotate-180 opacity-50 relative top-[1px]"></i> 
                 <b style="color:${color}">${esc(m.reply_username||'Unknown')}</b> <span class="italic opacity-70">${esc(String(m.reply_content||'').substring(0, 40))}</span>
               </div>`;
  }

  el.className='msg-row relative flex gap-3 px-4 py-2 rounded-xl mx-1 group';
  el.innerHTML=`
    <div class="relative w-9 h-9 flex-shrink-0 mt-0.5">
       <div class="w-full h-full rounded-full bg-slate-800 border border-slate-700 overflow-hidden flex items-center justify-center">${av}</div>
       ${overlayHtml}
    </div>
    <div class="flex-1 min-w-0">
      ${replyUI}
      <div class="flex items-baseline gap-1.5 mb-0.5 flex-wrap">
        <span class="text-sm font-semibold" style="color:${color}">${esc(m.username)}</span>
        ${nitroBadge}
        ${adminBadge}
        ${customTag}
        <span class="text-[10px] text-slate-600 font-mono">${fmtTime(m.created_at)}</span>
        ${editedLabel}
      </div>
      <div class="msg-body">${body}</div>
    </div>
    <div class="msg-actions flex items-center gap-1 absolute top-2 right-3">
      <button onclick="startReply(${m.id}, '${esc(m.username)}', '${btoa(encodeURIComponent(m.content)).replace(/'/g, "\\'")}')" class="text-xs text-slate-500 hover:text-blue-400 transition-colors bg-slate-800 border border-slate-700 rounded px-2 py-1"><i class="fa-solid fa-reply text-[10px]"></i></button>
      ${canEdit&&(type==='text')?`<button onclick="startEdit(${m.id},this)" class="text-xs text-slate-500 hover:text-blue-400 transition-colors bg-slate-800 border border-slate-700 rounded px-2 py-1"><i class="fa-solid fa-pen text-[10px]"></i></button>`:''}
      ${canDel?`<button onclick="deleteMsg(${m.id})" class="text-xs text-slate-500 hover:text-red-400 transition-colors bg-slate-800 border border-slate-700 rounded px-2 py-1"><i class="fa-solid fa-trash text-[10px]"></i></button>`:''}
    </div>`;
  return el;
}

function fileIcon(mime){
  if(mime.includes('pdf'))return'fa-solid fa-file-pdf';
  if(mime.includes('zip')||mime.includes('rar'))return'fa-solid fa-file-zipper';
  if(mime.includes('text')||mime.includes('json'))return'fa-solid fa-file-code';
  if(mime.includes('video'))return'fa-solid fa-file-video';
  if(mime.includes('audio'))return'fa-solid fa-file-audio';
  if(mime.includes('word')||mime.includes('document'))return'fa-solid fa-file-word';
  return'fa-solid fa-file';
}

// ── Inline edit ────────────────────────────────────────────────────────────
function startEdit(id,btn){
  const row=document.getElementById('msg-'+id);
  const bodyDiv=row.querySelector('.msg-body');
  const curText=bodyDiv.querySelector('p')?.textContent||'';
  bodyDiv.innerHTML=`<textarea class="edit-area" id="edit-${id}" rows="2">${esc(curText)}</textarea>
    <div class="flex gap-2 mt-1.5">
      <button onclick="saveEdit(${id})" class="bg-blue-600 hover:bg-blue-500 text-white px-3 py-1 rounded-lg text-xs font-semibold transition-all">Save</button>
      <button onclick="cancelEdit(${id},'${encodeURIComponent(curText)}')" class="bg-slate-800 hover:bg-slate-700 text-slate-300 px-3 py-1 rounded-lg text-xs transition-all">Cancel</button>
    </div>`;
  document.getElementById('edit-'+id).focus();
}

async function saveEdit(id){
  const inp=document.getElementById('edit-'+id);
  const content=inp.value.trim();
  if(!content)return;
  const r=await api('edit_message',{message_id:id,content},'POST');
  if(r.ok){lastMsgId=Math.max(0,lastMsgId-1);await loadMsgs(false);}
  else toast(r.error,'error');
}

function cancelEdit(id,encoded){
  const row=document.getElementById('msg-'+id);
  if(row){const bodyDiv=row.querySelector('.msg-body');bodyDiv.innerHTML=`<p class="text-sm text-slate-300 leading-relaxed break-words">${esc(decodeURIComponent(encoded))}</p>`;}
}

let replyToId = null;

function startReply(id, user, textBase64) {
  replyToId = id;
  const decoded = decodeURIComponent(atob(textBase64));
  document.getElementById('reply-preview').classList.remove('hidden');
  document.getElementById('reply-to-user').textContent = user;
  document.getElementById('reply-to-text').textContent = decoded;
  document.getElementById('msg-input').focus();
}

function cancelReply() {
  replyToId = null;
  document.getElementById('reply-preview').classList.add('hidden');
}

// ── Send helpers ───────────────────────────────────────────────────────────
async function sendMessage(){
  const inp=document.getElementById('msg-input');const txt=inp.value.trim();if(!txt)return;
  
  if (txt.toLowerCase().startsWith('/nitro ')) {
    const guess = txt.substring(7).trim();
    inp.value='';inp.style.height='';
    const r = await api('claim_nitro', {guess}, 'POST');
    if (r.ok && r.won) {
        toast('You won the Nitro challenge!', 'success');
        await loadMsgs(false);
    } else {
        toast('Incorrect nitro word or no active challenge!', 'error');
    }
    return;
  }
  
  inp.value='';inp.style.height='';
  const reqData = {channel_id:currentChannel, content:txt};
  if (replyToId) { reqData.reply_to = replyToId; cancelReply(); }
  const r=await api('send_message', reqData, 'POST');
  if(!r.ok)toast(r.error,'error');else await loadMsgs(false);
}

let typingTimeout = null;
function handleKey(e){
  // Send typing status
  if(!typingTimeout && currentChannel && e.key !== 'Enter') {
    api('typing', {channel_id: currentChannel}, 'POST');
    typingTimeout = setTimeout(() => typingTimeout = null, 3000);
  }
  
  if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();sendMessage();}
}

async function renderTyping(typers) {
  const el = document.getElementById('typing-indicator');
  const span = document.getElementById('typing-users');
  if(!typers || typers.length === 0) {
    el.classList.add('hidden');
    return;
  }
  let str = typers.length <= 2 ? typers.join(' and ') : typers.length + ' people';
  span.textContent = str;
  el.classList.remove('hidden');
}

async function deleteMsg(id){
  if(!confirm('Delete this message?'))return;
  const r=await api('delete_message',{message_id:id},'POST');
  if(r.ok)document.getElementById('msg-'+id)?.remove();else toast(r.error,'error');
}

async function sendImage(inp){
  const file=inp.files[0];if(!file)return;
  const reader=new FileReader();
  reader.onload=async e=>{
    const r=await api('send_image',{channel_id:currentChannel,image_data:e.target.result},'POST');
    if(r.ok){await loadMsgs(false);toast('Image sent!','success');}else toast(r.error,'error');
    inp.value='';
  };reader.readAsDataURL(file);
}

// ── Giphy ──────────────────────────────────────────────────────────────────
let gifTimeout = null;
const GIPHY_KEY = '3Pk9BqMEnZ97jg942TKWCLUTYJccGiBB';

async function loadTrendingGifs() {
  const res = document.getElementById('gif-results');
  res.innerHTML = '<div class="col-span-2 text-center text-slate-500 text-sm mt-10"><i class="fa-solid fa-spinner fa-spin"></i> Loading...</div>';
  try {
    const req = await fetch(`https://api.giphy.com/v1/gifs/trending?api_key=${GIPHY_KEY}&limit=20&rating=g`);
    const data = await req.json();
    renderGifs(data.data);
  } catch (e) {
    res.innerHTML = '<div class="col-span-2 text-center text-red-500 text-sm mt-10">Failed to load GIFs</div>';
  }
}

function searchGifs(query) {
  clearTimeout(gifTimeout);
  if (!query.trim()) {
    loadTrendingGifs();
    return;
  }
  gifTimeout = setTimeout(async () => {
    const res = document.getElementById('gif-results');
    res.innerHTML = '<div class="col-span-2 text-center text-slate-500 text-sm mt-10"><i class="fa-solid fa-spinner fa-spin"></i> Searching...</div>';
    try {
      const req = await fetch(`https://api.giphy.com/v1/gifs/search?api_key=${GIPHY_KEY}&q=${encodeURIComponent(query)}&limit=20&rating=g`);
      const data = await req.json();
      renderGifs(data.data);
    } catch (e) {
      res.innerHTML = '<div class="col-span-2 text-center text-red-500 text-sm mt-10">Failed to load GIFs</div>';
    }
  }, 500);
}

function toggleGifPicker() {
  const picker = document.getElementById('gif-picker');
  picker.classList.toggle('hidden');
  picker.classList.toggle('flex');
  if (!picker.classList.contains('hidden')) {
    loadTrendingGifs();
    document.getElementById('gif-search').focus();
  }
}

function renderGifs(gifs) {
  const res = document.getElementById('gif-results');
  if (!gifs || gifs.length === 0) {
    res.innerHTML = '<div class="col-span-2 text-center text-slate-500 text-sm mt-10">No GIFs found</div>';
    return;
  }
  res.innerHTML = gifs.map(g => `
    <div class="relative group cursor-pointer rounded-lg overflow-hidden bg-slate-800 mb-2 break-inside-avoid" onclick="sendGif('${g.images.original.url}')">
      <img src="${g.images.fixed_width.url}" class="w-full object-cover transition-transform group-hover:scale-105">
    </div>
  `).join('');
}

async function sendGif(url) {
  toggleGifPicker();
  const r = await api('send_image', { channel_id: currentChannel, image_data: url }, 'POST');
  if (r.ok) {
    await loadMsgs(false);
  } else {
    toast(r.error || 'Failed to send GIF', 'error');
  }
}

// Close picker when clicking outside
document.addEventListener('click', (e) => {
  const picker = document.getElementById('gif-picker');
  const btn = document.querySelector('button[onclick="toggleGifPicker()"]');
  if (picker && !picker.classList.contains('hidden') && !picker.contains(e.target) && !btn.contains(e.target)) {
    picker.classList.add('hidden');
    picker.classList.remove('flex');
  }
});

async function downloadFile(e, dataUrl, fileName) {
  e.preventDefault();
  try {
    const res = await fetch(dataUrl);
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = fileName;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => {
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
    }, 100);
  } catch(err) {
    toast('Failed to download file', 'error');
  }
}

async function sendFile(inp){
  const file=inp.files[0];if(!file)return;
  toast('Uploading file…','info');
  const reader=new FileReader();
  reader.onload=async e=>{
    const r=await api('send_file',{channel_id:currentChannel,file_data:e.target.result,file_name:file.name,file_mime:file.type||'application/octet-stream'},'POST');
    if(r.ok){await loadMsgs(false);toast('File sent!','success');}else toast(r.error,'error');
    inp.value='';
  };reader.readAsDataURL(file);
}

async function sendIframe(){
  const url=document.getElementById('iframe-url').value.trim();
  const label=document.getElementById('iframe-label').value.trim();
  if(!url){toast('Enter a URL','error');return;}
  const r=await api('send_iframe',{channel_id:currentChannel,url,label},'POST');
  if(r.ok){await loadMsgs(false);toast('Iframe embedded!','success');closeModal('iframe-modal');
    document.getElementById('iframe-url').value='';document.getElementById('iframe-label').value='';}
  else toast(r.error,'error');
}

// ── Custom Audio Player ────────────────────────────────────────────────────
let currentAudio = null;
let currentAudioBtn = null;
let pendingSeek = null;

function toggleAudioPlay(btn, src) {
  const icon = btn.querySelector('i');
  const progress = btn.nextElementSibling.querySelector('.audio-progress');
  const timeDisplay = btn.nextElementSibling.querySelector('.audio-time');
  const durationDisplay = btn.nextElementSibling.querySelector('.audio-duration');

  if (currentAudio && currentAudio.src.endsWith(src)) {
    if (currentAudio.paused) {
      currentAudio.play();
      icon.className = 'fa-solid fa-pause';
    } else {
      currentAudio.pause();
      icon.className = 'fa-solid fa-play ml-0.5';
    }
    return;
  }

  if (currentAudio) {
    currentAudio.pause();
    if (currentAudioBtn) {
      currentAudioBtn.querySelector('i').className = 'fa-solid fa-play ml-0.5';
    }
  }

  currentAudio = new Audio(src);
  currentAudioBtn = btn;
  let isFixingDuration = false;

  const container = btn.closest('.audio-msg-container');
  if (container) {
    const speedInput = container.querySelector('.audio-speed-input');
    if (speedInput) {
      let spd = parseFloat(speedInput.value);
      if (!isNaN(spd) && spd > 0) {
        try { currentAudio.playbackRate = spd; } catch(e) {}
      }
    }
  }
  
  const updateDuration = () => {
    if (!isFinite(currentAudio.duration)) return;
    const m = Math.floor(currentAudio.duration / 60);
    const s = Math.floor(currentAudio.duration % 60);
    durationDisplay.textContent = `${m}:${s.toString().padStart(2, '0')}`;
  };

  currentAudio.addEventListener('loadedmetadata', () => {
    if (currentAudio.duration === Infinity) {
      isFixingDuration = true;
      currentAudio.currentTime = 1e8; // Jump to end to force duration calculation
    } else {
      updateDuration();
      if (pendingSeek !== null) {
        currentAudio.currentTime = pendingSeek * currentAudio.duration;
        pendingSeek = null;
      }
    }
  });

  currentAudio.addEventListener('durationchange', () => {
    if (currentAudio.duration !== Infinity) {
      updateDuration();
      if (isFixingDuration) {
        isFixingDuration = false;
        if (pendingSeek !== null) {
          currentAudio.currentTime = pendingSeek * currentAudio.duration;
          pendingSeek = null;
        } else {
          currentAudio.currentTime = 0;
        }
      }
    }
  });

  currentAudio.addEventListener('timeupdate', () => {
    if (isFixingDuration || !isFinite(currentAudio.duration)) return;
    const p = (currentAudio.currentTime / currentAudio.duration) * 100;
    progress.style.width = `${p}%`;
    const m = Math.floor(currentAudio.currentTime / 60);
    const s = Math.floor(currentAudio.currentTime % 60);
    timeDisplay.textContent = `${m}:${s.toString().padStart(2, '0')}`;
  });

  currentAudio.addEventListener('ended', () => {
    if (isFixingDuration) return;
    icon.className = 'fa-solid fa-play ml-0.5';
    progress.style.width = '0%';
    timeDisplay.textContent = '0:00';
  });

  currentAudio.play();
  icon.className = 'fa-solid fa-pause';
}

function seekAudio(e, el) {
  const btn = el.parentElement.previousElementSibling;
  const rect = el.getBoundingClientRect();
  const x = e.clientX - rect.left;
  const percentage = Math.max(0, Math.min(1, x / rect.width));

  if (btn !== currentAudioBtn) {
    pendingSeek = percentage;
    btn.click();
    return;
  }
  
  if (!currentAudio) return;

  if (isFinite(currentAudio.duration) && currentAudio.duration > 0) {
    currentAudio.currentTime = percentage * currentAudio.duration;
  } else {
    pendingSeek = percentage;
  }
}

function changeAudioSpeed(inp) {
  let speed = parseFloat(inp.value);
  if (isNaN(speed) || speed <= 0) return;
  
  if (!currentAudio) return;
  const container = inp.closest('.audio-msg-container');
  if (!container) return;
  const playBtn = container.querySelector('button');
  if (playBtn !== currentAudioBtn) return;
  
  try {
    currentAudio.playbackRate = speed;
  } catch (e) {
    console.warn('Playback rate not supported by browser:', speed);
  }
}

// ── Voice recording ────────────────────────────────────────────────────────
async function toggleVoice(){
  if(!voiceActive){
    try{
      const stream=await navigator.mediaDevices.getUserMedia({audio:true});
      mediaRecorder=new MediaRecorder(stream);audioChunks=[];
      mediaRecorder.ondataavailable=e=>{if(e.data.size>0)audioChunks.push(e.data);};
      mediaRecorder.onstop=async()=>{
        const mime = mediaRecorder.mimeType || 'audio/webm';
        const blob=new Blob(audioChunks,{type:mime});
        const reader=new FileReader();
        reader.onload=async e=>{
          const r=await api('send_audio',{channel_id:currentChannel,audio_data:e.target.result},'POST');
          if(r.ok){await loadMsgs(false);toast('Voice message sent!','success');}else toast(r.error,'error');
        };reader.readAsDataURL(blob);
        stream.getTracks().forEach(t=>t.stop());
      };
      mediaRecorder.start();voiceActive=true;voiceSeconds=0;
      const btn=document.getElementById('voice-btn');
      btn.classList.add('recording');document.getElementById('voice-label').textContent='Stop';
      document.getElementById('voice-timer').classList.remove('hidden');
      voiceTimer=setInterval(()=>{
        voiceSeconds++;const m=Math.floor(voiceSeconds/60),s=voiceSeconds%60;
        document.getElementById('voice-time').textContent=`${m}:${s.toString().padStart(2,'0')}`;
      },1000);
    }catch(e){toast('Microphone access denied','error');}
  } else {
    mediaRecorder?.stop();voiceActive=false;clearInterval(voiceTimer);
    document.getElementById('voice-btn').classList.remove('recording');
    document.getElementById('voice-label').textContent='Voice';
    document.getElementById('voice-timer').classList.add('hidden');
  }
}

// ── Image zoom ─────────────────────────────────────────────────────────────
function zoomImg(src){document.getElementById('img-zoom-src').src=src;document.getElementById('img-zoom').style.display='flex';}
document.getElementById('img-zoom').addEventListener('click',()=>{document.getElementById('img-zoom').style.display='none';});

// ── WebRTC Voice Calls ─────────────────────────────────────────────────────
const RTC_CONFIG = {
  iceServers: [
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'stun:stun1.l.google.com:19302' }
  ]
};

let callState = {
  pc: null,
  localStream: null,
  remoteStream: null,
  audioContext: null,
  status: 'idle', // idle, incoming, outgoing, connected
  cid: null,
  targetId: null,
  targetName: null,
  callId: null,
  isMuted: false,
  isDeafened: false
};

async function sendWebrtcSignal(payload) {
  const cid = callState.cid || currentChannel;
  if (!cid) return;
  await api('send_webrtc', { channel_id: cid, payload: JSON.stringify(payload) }, 'POST');
}

function resetCallState() {
  if (callState.pc) {
    callState.pc.close();
    callState.pc = null;
  }
  if (callState.localStream) {
    callState.localStream.getTracks().forEach(t => t.stop());
    callState.localStream = null;
  }
  if (callState.audioContext) {
    callState.audioContext.close();
    callState.audioContext = null;
  }
  callState.remoteStream = null;
  callState.status = 'idle';
  callState.cid = null;
  callState.targetId = null;
  callState.targetName = null;
  callState.callId = null;
  document.getElementById('remote-audio').srcObject = null;
  updateCallUI();
}

function updateCallUI() {
  const container = document.getElementById('call-ui-container');
  const acceptBtn = document.getElementById('call-btn-accept');
  const muteBtn = document.getElementById('call-btn-mute');
  const deafenBtn = document.getElementById('call-btn-deafen');
  const title = document.getElementById('call-title');
  const statusEl = document.getElementById('call-status');
  const remoteName = document.getElementById('call-remote-name');

  if (callState.status === 'idle' || callState.status === 'incoming') {
    container.classList.add('hidden');
    container.classList.remove('flex');
    return;
  }
  
  container.classList.remove('hidden');
  container.classList.add('flex');
  title.textContent = `Call with ${callState.targetName || 'User'}`;
  remoteName.textContent = callState.targetName || 'User';
  
  if (callState.status === 'incoming') {
    statusEl.textContent = 'Incoming Call...';
    statusEl.className = 'text-[11px] uppercase tracking-wider text-yellow-400 font-bold px-2 py-1 rounded bg-yellow-400/10 animate-pulse';
    acceptBtn.classList.remove('hidden');
  } else if (callState.status === 'outgoing') {
    statusEl.textContent = 'Ringing...';
    statusEl.className = 'text-[11px] uppercase tracking-wider text-blue-400 font-bold px-2 py-1 rounded bg-blue-400/10 animate-pulse';
    acceptBtn.classList.add('hidden');
  } else if (callState.status === 'connected') {
    statusEl.textContent = 'Connected';
    statusEl.className = 'text-[11px] uppercase tracking-wider text-green-400 font-bold px-2 py-1 rounded bg-green-500/10';
    acceptBtn.classList.add('hidden');
  }

  muteBtn.innerHTML = callState.isMuted ? '<i class="fa-solid fa-microphone-slash"></i>' : '<i class="fa-solid fa-microphone"></i>';
  muteBtn.className = callState.isMuted 
      ? 'w-12 h-12 rounded-full bg-[#3ba55c] hover:bg-[#2d7d46] transition-colors text-white shadow-md flex items-center justify-center text-lg' 
      : 'w-12 h-12 rounded-full bg-[#4f545c] hover:bg-[#3b3e45] transition-colors text-white shadow-md flex items-center justify-center text-lg';

  // Discord has muted=red cross for some states, but we'll use a simpler color switch
  if (callState.isMuted) {
      muteBtn.className = muteBtn.className.replace('bg-[#3ba55c]', 'bg-red-500').replace('hover:bg-[#2d7d46]', 'hover:bg-red-600');
  }

  deafenBtn.innerHTML = callState.isDeafened ? '<i class="fa-solid fa-headphones-simple"></i>' : '<i class="fa-solid fa-headphones"></i>';
  deafenBtn.className = callState.isDeafened 
      ? 'w-12 h-12 rounded-full bg-red-500 hover:bg-red-600 transition-colors text-white shadow-md flex items-center justify-center text-lg' 
      : 'w-12 h-12 rounded-full bg-[#4f545c] hover:bg-[#3b3e45] transition-colors text-white shadow-md flex items-center justify-center text-lg';
}

async function startCall() {
  if (currentChannelType !== 'dm' || callState.status !== 'idle') return;
  try {
    callState.localStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
  } catch(e) {
    return toast('Microphone access denied or not found', 'error');
  }
  
  callState.status = 'outgoing';
  callState.cid = currentChannel;
  callState.targetName = currentChannelName;
  callState.callId = Date.now() + '_' + ME.id;
  updateCallUI();

  await sendWebrtcSignal({ type: 'call_request', callId: callState.callId });
}

window.joinCallFromChat = async function(callId, senderId, senderName, channelId) {
  if (callState.status !== 'idle' && callState.callId !== callId) {
     return toast('You are already in a call!', 'error');
  }
  
  callState.status = 'incoming';
  callState.cid = channelId;
  callState.targetId = senderId;
  callState.targetName = senderName;
  callState.callId = callId;
  await acceptCall();
};

async function handleWebrtcMessage(payload, senderId, senderName, channelId) {
  // Ignore messages too old (>45s) for transient requests, or from different channels
  if (payload.callId && parseInt(payload.callId.split('_')[0]) < Date.now() - 45000) {
    if (payload.type === 'call_request') return; 
  }
  
  if (payload.type === 'call_request') {
    if (callState.status === 'outgoing') {
      // Cross-call collision: both users pressed call at the same time.
      // Resolve deterministically by user ID — lower ID stays as caller,
      // higher ID becomes the callee and auto-accepts.
      if (ME.id < senderId) {
        // I have lower ID: stay as caller, ignore their request.
        // They will receive my call_request and, since their id > mine, switch to incoming.
        return;
      } else {
        // They have lower ID: I become the callee, auto-accept their call.
        callState.status = 'incoming';
        callState.cid = channelId;
        callState.targetId = senderId;
        callState.targetName = senderName;
        callState.callId = payload.callId;
        updateCallUI();
        await acceptCall();
        return;
      }
    }
    if (callState.status !== 'idle' && callState.callId !== payload.callId) {
      // Truly busy (connected/incoming with someone else)
      api('send_webrtc', { channel_id: channelId, payload: JSON.stringify({ type: 'call_reject', reason: 'busy', callId: payload.callId }) }, 'POST');
      return;
    }
    callState.status = 'incoming';
    callState.cid = channelId;
    callState.targetId = senderId;
    callState.targetName = senderName;
    callState.callId = payload.callId;
    updateCallUI();
    return;
  }
  
  if (payload.callId !== callState.callId) return;

  if (payload.type === 'call_reject') {
    if (callState.status === 'outgoing') {
      toast(payload.reason === 'busy' ? `${callState.targetName} is busy` : `${callState.targetName} declined the call`, 'error');
      resetCallState();
    }
    return;
  }

  if (payload.type === 'call_end') {
    toast('Call ended', 'info');
    resetCallState();
    return;
  }

  if (payload.type === 'offer') {
    if (callState.status === 'incoming') return; // We haven't accepted yet, or we're creating answer
    if (!callState.pc) await setupPeerConnection();
    await callState.pc.setRemoteDescription(new RTCSessionDescription(payload.sdp));
    const answer = await callState.pc.createAnswer();
    await callState.pc.setLocalDescription(answer);
    callState.status = 'connected';
    updateCallUI();
    await sendWebrtcSignal({ type: 'answer', sdp: callState.pc.localDescription, callId: callState.callId });
    return;
  }

  if (payload.type === 'answer') {
    if (callState.pc) {
      await callState.pc.setRemoteDescription(new RTCSessionDescription(payload.sdp));
      callState.status = 'connected';
      updateCallUI();
    }
    return;
  }

  if (payload.type === 'ice') {
    if (callState.pc) {
      try {
        await callState.pc.addIceCandidate(new RTCIceCandidate(payload.candidate));
      } catch(e) { console.error('Error adding ICE candidate', e); }
    }
    return;
  }
}

async function setupPeerConnection() {
  callState.pc = new RTCPeerConnection(RTC_CONFIG);
  
  callState.localStream.getTracks().forEach(track => {
    callState.pc.addTrack(track, callState.localStream);
  });

  callState.pc.onicecandidate = (event) => {
    if (event.candidate) {
      sendWebrtcSignal({ type: 'ice', candidate: event.candidate, callId: callState.callId });
    }
  };

  callState.pc.ontrack = (event) => {
    callState.remoteStream = event.streams[0];
    document.getElementById('remote-audio').srcObject = callState.remoteStream;

    // Optional audio speaking indicator
    if (!callState.audioContext) {
      callState.audioContext = new (window.AudioContext || window.webkitAudioContext)();
      const analyzer = callState.audioContext.createAnalyser();
      analyzer.fftSize = 256;
      const source = callState.audioContext.createMediaStreamSource(callState.remoteStream);
      source.connect(analyzer);
      const dataArray = new Uint8Array(analyzer.frequencyBinCount);
      const indicator = document.getElementById('call-remote-speaker');
      
      const checkAudio = () => {
        if (!callState.remoteStream) return;
        analyzer.getByteFrequencyData(dataArray);
        let sum = 0;
        for (let i = 0; i < dataArray.length; i++) sum += dataArray[i];
        let average = sum / dataArray.length;
        if (average > 10) {
          if (indicator) {
              indicator.classList.remove('hidden');
              indicator.classList.add('flex');
          }
          document.getElementById('call-remote-name').parentElement.parentElement.classList.add('ring-2', 'ring-green-500');
        } else {
          if (indicator) {
              indicator.classList.add('hidden');
              indicator.classList.remove('flex');
          }
          document.getElementById('call-remote-name').parentElement.parentElement.classList.remove('ring-2', 'ring-green-500');
        }
        requestAnimationFrame(checkAudio);
      };
      checkAudio();
    }
  };

  callState.pc.onconnectionstatechange = () => {
    if (callState.pc && (callState.pc.connectionState === 'disconnected' || callState.pc.connectionState === 'failed' || callState.pc.connectionState === 'closed')) {
      toast('Call disconnected', 'error');
      resetCallState();
    }
  };
}

async function acceptCall() {
  if (callState.status !== 'incoming') return;
  
  if (currentChannel !== callState.cid) {
    // Attempt to switch to the DM channel if we aren't there yet
    // Need target details though. We have targetName, but not targetId to fetch DM properly if not loaded.
    // Assuming they click it when they see it, they usually are in the DM or switch to it globally.
    // If we're not in the DM, switch to it manually:
    await switchChannel(callState.cid, callState.targetName, 'dm_0_0'); // we don't have exactly the type, but it doesn't matter much purely for UI
  }

  try {
    if (!callState.localStream) {
      callState.localStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
    }
  } catch(e) {
    sendWebrtcSignal({ type: 'call_reject', reason: 'declined', callId: callState.callId });
    resetCallState();
    return toast('Microphone access required', 'error');
  }

  callState.status = 'connected';
  updateCallUI();
  
  await setupPeerConnection();
  const offer = await callState.pc.createOffer({ offerToReceiveAudio: true });
  await callState.pc.setLocalDescription(offer);
  
  await sendWebrtcSignal({ type: 'offer', sdp: callState.pc.localDescription, callId: callState.callId });
}

function declineCall() {
  if (callState.status === 'incoming') {
    sendWebrtcSignal({ type: 'call_reject', reason: 'declined', callId: callState.callId });
    resetCallState();
  }
}

function endCall() {
  if (callState.status !== 'idle') {
    if (callState.status === 'incoming') return declineCall();
    sendWebrtcSignal({ type: 'call_end', callId: callState.callId });
    resetCallState();
  }
}

function toggleMute() {
  if (!callState.localStream) return;
  callState.isMuted = !callState.isMuted;
  callState.localStream.getAudioTracks().forEach(t => t.enabled = !callState.isMuted);
  updateCallUI();
}

function toggleDeafen() {
  callState.isDeafened = !callState.isDeafened;
  document.getElementById('remote-audio').muted = callState.isDeafened;
  // Deafen should also mute mic
  if (callState.isDeafened && !callState.isMuted) toggleMute();
  updateCallUI();
}

// ── Search ─────────────────────────────────────────────────────────────────
function filterMessages(q){
  const lq=q.toLowerCase();
  document.querySelectorAll('#messages>div').forEach(el=>{el.style.display=(!q||el.textContent.toLowerCase().includes(lq))?'':'none';});
}

// ── Wordle game logic ──────────────────────────────────────────────────────
let wordleData = {
  word: '',
  guesses: [],
  currentGuess: '',
  maxGuesses: 6,
  status: 'playing' // playing, won, lost
};

async function openWordle() {
  openModal('wordle-modal');
  let fetchedWord = '';
  let fetchedDate = '';
  try {
     const r = await api('get_wordle');
     if (r.ok && r.word && r.word.length === 5) {
         fetchedWord = r.word;
         fetchedDate = r.date || new Date().toISOString().split('T')[0];
     } else {
         fetchedWord = 'APPLE'; // Fallback
         fetchedDate = new Date().toISOString().split('T')[0];
     }
  } catch(e) { 
      fetchedWord = 'APPLE'; 
      fetchedDate = new Date().toISOString().split('T')[0];
  }
  
  const savedState = localStorage.getItem('betterchat_wordle_state');
  let loadSaved = false;
  if (savedState) {
      try {
          const parsed = JSON.parse(savedState);
          // Only load saved game if the word is the same AND the date is the same 
          // (date check ensures daily reset even if custom word remains same)
          if (parsed.word === fetchedWord && (parsed.date === fetchedDate || (!parsed.date && !fetchedDate))) {
              wordleData = parsed;
              loadSaved = true;
          }
      } catch(e) {}
  }
  
  if (!loadSaved) {
      wordleData = {
        word: fetchedWord,
        date: fetchedDate,
        guesses: [],
        currentGuess: '',
        maxGuesses: 6,
        status: 'playing'
      };
      localStorage.setItem('betterchat_wordle_state', JSON.stringify(wordleData));
  }
  
  // Display initial status if already won or lost
  if (wordleData.status === 'won') {
      showWordleMsg('You already won today!', 'text-emerald-400');
  } else if (wordleData.status === 'lost') {
      showWordleMsg(wordleData.word, 'text-white');
  }
  
  renderWordle();
}

async function handleWordleKey(key) {
  if (wordleData.status !== 'playing' || wordleData.isChecking) return;
  const k = key.toUpperCase();
  
  if (k === 'ENTER') {
     if (wordleData.currentGuess.length === 5) {
        if (wordleData.guesses.includes(wordleData.currentGuess)) {
            showWordleMsg('Already guessed', 'text-yellow-400', 1500);
            return;
        }
        
        if (wordleData.currentGuess !== wordleData.word) {
            wordleData.isChecking = true;
            try {
                const res = await fetch(`https://api.dictionaryapi.dev/api/v2/entries/en/${wordleData.currentGuess}`);
                if (!res.ok) {
                    let reject = false;
                    try {
                        const data = await res.json();
                        if (data.title === "No Definitions Found") reject = true;
                    } catch(e) { reject = true; }
                    
                    if (reject) {
                        showWordleMsg('Not in word list', 'text-yellow-400', 1500);
                        wordleData.isChecking = false;
                        return;
                    }
                }
            } catch (e) {
                // Ignore network errors so it doesn't hard lock gameplay if API crashes
            }
            wordleData.isChecking = false;
        }

        wordleData.guesses.push(wordleData.currentGuess);
        if (wordleData.currentGuess === wordleData.word) {
            wordleData.status = 'won';
            showWordleMsg('Genius!', 'text-emerald-400', -1);
        } else if (wordleData.guesses.length >= wordleData.maxGuesses) {
            wordleData.status = 'lost';
            showWordleMsg(wordleData.word, 'text-white', -1);
        }
        wordleData.currentGuess = '';
        localStorage.setItem('betterchat_wordle_state', JSON.stringify(wordleData));
        renderWordle();
     } else {
        showWordleMsg('Not enough letters', 'text-yellow-400', 1500);
     }
  } else if (k === 'BACKSPACE' || k === 'DEL') {
      wordleData.currentGuess = wordleData.currentGuess.slice(0, -1);
      renderWordle();
  } else if (/^[A-Z]$/.test(k)) {
      if (wordleData.currentGuess.length < 5) {
          wordleData.currentGuess += k;
          renderWordle();
      }
  }
}

// Map real keyboard
document.addEventListener('keydown', (e) => {
    if (!document.getElementById('wordle-modal').classList.contains('open')) return;
    if (e.key === 'Enter') handleWordleKey('ENTER');
    else if (e.key === 'Backspace') handleWordleKey('BACKSPACE');
    else if (/^[A-Za-z]$/.test(e.key)) handleWordleKey(e.key);
});

function getLetterStatus(guess, targetWord) {
     const res = Array(5).fill('grey');
     const targetArr = targetWord.split('');
     const guessArr = guess.split('');
     
     // Pass 1: exact matches
     for(let i=0; i<5; i++) {
        if (guessArr[i] === targetArr[i]) {
            res[i] = 'green';
            targetArr[i] = null;
        }
     }
     // Pass 2: partial matches
     for(let i=0; i<5; i++) {
        if (res[i] !== 'green' && targetArr.includes(guessArr[i])) {
            res[i] = 'yellow';
            targetArr[targetArr.indexOf(guessArr[i])] = null;
        }
     }
     return res;
}

function renderWordle() {
     const grid = document.getElementById('wordle-grid');
     grid.innerHTML = '';
     
     // Get keyboard state
     const kbState = {};
     wordleData.guesses.forEach(g => {
         const statuses = getLetterStatus(g, wordleData.word);
         for(let i=0; i<5; i++) {
            const letter = g[i];
            const s = statuses[i];
            if (!kbState[letter] || s === 'green' || (s === 'yellow' && kbState[letter] !== 'green')) {
                kbState[letter] = s;
            }
         }
     });

     // Render grid
     for(let i=0; i<6; i++) {
         const rowDiv = document.createElement('div');
         rowDiv.className = 'grid grid-cols-5 gap-2';
         
         if (i < wordleData.guesses.length) {
            // Submitted guess
            const statuses = getLetterStatus(wordleData.guesses[i], wordleData.word);
            for(let j=0; j<5; j++) {
                let bg = 'bg-slate-700 border-slate-600';
                if (statuses[j] === 'green') bg = 'bg-emerald-500 border-emerald-500';
                else if (statuses[j] === 'yellow') bg = 'bg-yellow-500 border-yellow-500';
                else bg = 'bg-slate-800 border-slate-700 text-slate-500';
                
                const char = (wordleData.guesses[i] && wordleData.guesses[i].length > j) ? wordleData.guesses[i].charAt(j) : '';
                rowDiv.innerHTML += `<div class="w-12 h-12 flex items-center justify-center text-2xl font-bold text-white border-2 ${bg} uppercase">${char}</div>`;
            }
         } else if (i === wordleData.guesses.length && wordleData.status === 'playing') {
             // Current guess
             for(let j=0; j<5; j++) {
                const l = (wordleData.currentGuess && wordleData.currentGuess.length > j) ? wordleData.currentGuess.charAt(j) : '';
                const baseClass = l ? 'border-slate-400' : 'border-slate-700';
                rowDiv.innerHTML += `<div class="w-12 h-12 flex items-center justify-center text-2xl font-bold text-white border-2 border-slate-700 ${baseClass} bg-slate-900 uppercase">${l}</div>`;
             }
         } else {
             // Empty row
             for(let j=0; j<5; j++) {
                 rowDiv.innerHTML += `<div class="w-12 h-12 border-2 border-slate-800 bg-slate-900"></div>`;
             }
         }
         grid.appendChild(rowDiv);
     }
     
     // Render Keyboard
     const kbLayout = [
         ['Q','W','E','R','T','Y','U','I','O','P'],
         ['A','S','D','F','G','H','J','K','L'],
         ['ENTER','Z','X','C','V','B','N','M','DEL']
     ];
     const kbHtml = kbLayout.map(row => {
         return `<div class="flex gap-1 justify-center w-full">` + row.map(key => {
             const isWide = key.length > 1;
             const wCls = isWide ? 'px-3 font-semibold text-xs' : 'w-8 font-bold text-sm';
             let bgCls = 'bg-slate-600 hover:bg-slate-500 cursor-pointer';
             if (kbState[key] === 'green') bgCls = 'bg-emerald-500 text-white';
             else if (kbState[key] === 'yellow') bgCls = 'bg-yellow-500 text-white';
             else if (kbState[key] === 'grey') bgCls = 'bg-slate-800 text-slate-500';
             
             return `<button onclick="handleWordleKey('${key}')" class="h-10 rounded ${wCls} ${bgCls} flex items-center justify-center transition-colors select-none">${key}</button>`;
         }).join('') + `</div>`;
     }).join('');
     document.getElementById('wordle-keyboard').innerHTML = kbHtml;
     
     // Toggle Play Again Button
     const replayBtn = document.getElementById('wordle-replay-btn');
     if (replayBtn) {
       if (wordleData.status !== 'playing') replayBtn.classList.remove('hidden');
       else replayBtn.classList.add('hidden');
     }
}

function forceWordleReset() {
    localStorage.removeItem('betterchat_wordle_state');
    document.getElementById('wordle-feedback').classList.add('opacity-0');
    openWordle();
}

let wordleTimer;
function showWordleMsg(msg, colorCls="text-white", ms=2000) {
    const el = document.getElementById('wordle-feedback');
    el.innerHTML = `<span class="${colorCls}">${msg}</span>`;
    el.classList.remove('opacity-0');
    clearTimeout(wordleTimer);
    if (ms > 0) {
       wordleTimer = setTimeout(() => el.classList.add('opacity-0'), ms);
    }
}

// ── Members ─────────────────────────────────────────────────────────────────
let membersVisible=true;
function toggleMembers(){const m=document.getElementById('members');membersVisible=!membersVisible;m.style.display=membersVisible?'':' none';}

async function loadMembers(){
  const r=await api('get_members');if(!r.ok)return;
  const online=r.members.filter(m=>m.is_online==1||m.is_online===true);
  const offline=r.members.filter(m=>!(m.is_online==1||m.is_online===true));
  
  if(!firstLoad.members) {
    online.forEach(m => {
      if(!knownOnlineIds.has(m.id) && m.id != ME.id) {
        sendPush(`${m.username} is online`, `${m.username} just came online!`);
      }
      knownOnlineIds.add(m.id);
    });
    offline.forEach(m => knownOnlineIds.delete(m.id));
  } else {
    online.forEach(m => knownOnlineIds.add(m.id));
    firstLoad.members = false;
  }

  let html='';
  if(online.length){html+=`<p class="text-[10px] uppercase tracking-widest text-slate-600 px-2 pt-2 pb-1">Online — ${online.length}</p>`;online.forEach(m=>html+=memberRow(m,true));}
  if(offline.length){html+=`<p class="text-[10px] uppercase tracking-widest text-slate-600 px-2 pt-3 pb-1">Offline — ${offline.length}</p>`;offline.forEach(m=>html+=memberRow(m,false));}
  const list = document.getElementById('members-list');
  list.innerHTML=html;
  twemoji.parse(list);
}

function memberRow(m,online){
  const col=m.name_color||'#3b82f6';
  const tagColor = m.custom_tag_color || '#ef4444';
  const customTag = m.custom_tag ? `<span class="text-[9px] px-1 py-0 rounded font-bold ml-1 whitespace-nowrap" style="color:${esc(tagColor)};background-color:${esc(tagColor)}22;border:1px solid ${esc(tagColor)}40;">${esc(String(m.custom_tag).toUpperCase())}</span>` : '';
  const av=m.avatar?`<img src="${m.avatar}" class="w-full h-full object-cover">`:`<span class="text-xs font-bold" style="color:${col}">${m.username[0].toUpperCase()}</span>`;
  let overlayHtml = '';
  if (m.avatar_overlay) {
    try {
      const ov = JSON.parse(m.avatar_overlay);
      if(ov.url) {
         overlayHtml = `<img src="${esc(ov.url)}" style="position:absolute; width:100%; height:100%; top:${ov.y||0}%; left:${ov.x||0}%; transform:scale(${ov.scale||1}); pointer-events:none; z-index:10; object-fit:contain;">`;
      }
    } catch(e){}
  }
  const adminBadge=m.is_admin?`<i class="fa-solid fa-shield-halved text-[9px] text-red-400 ml-auto flex-shrink-0"></i>`:'';
  return `<button class="w-full flex items-center gap-2.5 px-2 py-1.5 rounded-lg text-left hover:bg-slate-800/60 transition-colors">
    <div class="relative w-8 h-8 flex-shrink-0">
      <div class="w-full h-full rounded-full bg-slate-800 border border-slate-700 overflow-hidden flex items-center justify-center">${av}</div>
      ${overlayHtml}
      <span class="absolute -bottom-0.5 -right-0.5 w-2.5 h-2.5 ${online?'bg-emerald-400 z-20':'bg-slate-600 z-20'} rounded-full border-2 border-slate-900"></span>
    </div>
    <span class="text-sm font-medium truncate flex-1" style="color:${col}">${esc(m.username)}${customTag}</span>
    ${adminBadge}
  </button>`;
}

// ── Friends ──────────────────────────────────────────────────────────────────
async function loadFriends(){
  const r=await api('get_friends');
  const list=document.getElementById('dm-list');
  if(!r.ok||!r.friends.length){list.innerHTML=`<p class="text-xs text-slate-600 italic px-3 py-2">No friends yet. Click <i class="fa-solid fa-plus"></i> to add.</p>`;return;}
  list.innerHTML=r.friends.map(f=>{
    const col=f.name_color||'#3b82f6';
    const av=f.avatar?`<img src="${f.avatar}" class="w-full h-full object-cover">`:`<span class="text-xs font-bold" style="color:${col}">${f.username[0].toUpperCase()}</span>`;
    const dot=(f.is_online==1||f.is_online===true)?'bg-emerald-400':'bg-slate-600';
    
    let overlayHtml = '';
    if (f.avatar_overlay) {
      try {
        const ov = JSON.parse(f.avatar_overlay);
        if(ov.url) {
           overlayHtml = `<img src="${esc(ov.url)}" style="position:absolute; width:100%; height:100%; top:${ov.y||0}%; left:${ov.x||0}%; transform:scale(${ov.scale||1}); pointer-events:none; z-index:10; object-fit:contain;">`;
        }
      } catch(e){}
    }
    
    return `<div onclick="openDM(${f.id}, '${esc(f.username).replace(/'/g, "\\'")}', '${col}')" class="cursor-pointer flex items-center gap-2.5 px-3 py-2 rounded-lg hover:bg-slate-800/60 group transition-colors">
      <div class="relative w-7 h-7 flex-shrink-0">
        <div class="w-full h-full rounded-full bg-slate-800 border border-slate-700 overflow-hidden flex items-center justify-center">${av}</div>
        ${overlayHtml}
        <span class="absolute -bottom-0.5 -right-0.5 w-2 h-2 ${dot} rounded-full border-2 border-slate-900 z-20"></span>
      </div>
      <span class="text-sm font-medium flex-1 truncate" style="color:${col}">${esc(f.username)}</span>
      <button onclick="event.stopPropagation(); removeFriend(${f.id},'${esc(f.username).replace(/'/g, "\\'")}')" title="Remove friend"
        class="opacity-0 group-hover:opacity-100 text-slate-600 hover:text-red-400 transition-all text-xs"><i class="fa-solid fa-user-minus"></i></button>
    </div>`;
  }).join('');
}

async function openDM(targetId, targetName, color) {
  const r = await api('get_or_create_dm', {target_id: targetId}, 'POST');
  if (!r.ok) { toast(r.error || 'Failed to open DM', 'error'); return; }
  
  currentChannel = r.channel_id;
  currentChannelName = targetName;
  currentChannelType = 'dm';
  
  document.getElementById('header-ch-name').previousElementSibling.className = 'fa-solid fa-at text-xs';
  document.getElementById('header-ch-name').innerHTML = `<span style="color:${color}">${targetName}</span>`;
  twemoji.parse(document.getElementById('header-ch-name'));
  document.getElementById('msg-input').placeholder=`Message @${targetName}…`;
  
  if (document.getElementById('call-btn')) document.getElementById('call-btn').classList.remove('hidden');

  document.querySelectorAll('.channel-btn').forEach(b => {
    b.classList.remove('active','text-slate-200');
    b.classList.add('text-slate-400');
  });
  
  document.getElementById('messages').classList.remove('hidden');
  document.querySelector('.px-4.pb-4.pt-2.border-t').classList.remove('hidden');
  
  lastMsgId = 0;
  oldestMsgId = Infinity;
  document.getElementById('messages').innerHTML = '';
  if(window.innerWidth < 768) toggleSidebar();
  await loadMsgs(true);
}

async function removeFriend(id,name){
  if(!confirm(`Remove ${name} from friends?`))return;
  const r=await api('remove_friend',{user_id:id},'POST');
  if(r.ok){toast(`Removed ${name}`,'info');loadFriends();}else toast(r.error,'error');
}

// ── Inbox ─────────────────────────────────────────────────────────────────
async function pollInbox(){
  const r=await api('get_inbox');if(!r.ok)return;
  const b=document.getElementById('inbox-badge');
  if(r.unread>0){b.textContent=r.unread>99?'99+':r.unread;b.classList.remove('hidden');}else b.classList.add('hidden');
}

async function openInbox(){
  openModal('inbox-modal');
  const r=await api('get_inbox');
  const div=document.getElementById('inbox-content');
  if(!r.ok){div.innerHTML=`<p class="text-red-400">${esc(r.error)}</p>`;return;}
  let html='';
  if(r.friend_requests.length){
    html+=`<p class="text-[10px] uppercase tracking-widest text-blue-400/70 font-semibold mb-3"><i class="fa-solid fa-user-plus mr-1"></i>Friend Requests (${r.friend_requests.length})</p>`;
    r.friend_requests.forEach(fr=>{
      html+=`<div class="bg-slate-800 border border-slate-700 rounded-xl p-3.5 mb-2">
        <p class="text-sm text-slate-200 font-medium mb-2.5"><span class="text-blue-400">${esc(fr.from_name)}</span> wants to be your friend</p>
        <div class="flex gap-2">
          <button onclick="respondFR(${fr.id},'yes',this.closest('[class*=rounded-xl]'))"
            class="flex-1 bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-400 border border-emerald-500/30 rounded-lg py-2 text-xs font-semibold flex items-center justify-center gap-1.5">
            <i class="fa-solid fa-check"></i> Accept</button>
          <button onclick="respondFR(${fr.id},'no',this.closest('[class*=rounded-xl]'))"
            class="flex-1 bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/20 rounded-lg py-2 text-xs font-semibold flex items-center justify-center gap-1.5">
            <i class="fa-solid fa-xmark"></i> Decline</button>
        </div>
        <p class="text-[10px] text-slate-600 mt-2 font-mono">${fr.created_at}</p>
      </div>`;
    });
  }
  if(r.messages.length){
    html+=`<p class="text-[10px] uppercase tracking-widest text-slate-600 font-semibold mb-3 ${r.friend_requests.length?'mt-4':''}"><i class="fa-solid fa-bell mr-1"></i>Notifications</p>`;
    r.messages.forEach(m=>{html+=`<div class="bg-slate-800/50 border border-slate-700/50 rounded-xl p-3 mb-2 text-sm text-slate-300">${esc(m.content)}<p class="text-[10px] text-slate-600 mt-1 font-mono">${m.created_at}</p></div>`;});
  }
  if(!html)html='<div class="text-center py-8"><i class="fa-solid fa-inbox text-4xl text-slate-700 mb-3 block"></i><p class="text-slate-500 text-sm">Inbox is empty</p></div>';
  div.innerHTML=html;
  twemoji.parse(div);
  await api('mark_inbox_read',{},'POST');
  document.getElementById('inbox-badge').classList.add('hidden');
}

async function respondFR(id,accept,el){
  const r=await api('respond_friend_request',{fr_id:id,accept},'POST');
  if(r.ok){el?.remove();if(accept==='yes'){toast('Friend added! 🎉','success');loadFriends();}else toast('Declined.','info');}
  else toast(r.error,'error');
}

// ── Friend request send ────────────────────────────────────────────────────
async function sendFriendRequest(){
  const name=document.getElementById('friend-name').value.trim();if(!name)return;
  const r=await api('send_friend_request',{to_username:name},'POST');
  if(r.ok){toast('Request sent!','success');closeModal('friend-modal');document.getElementById('friend-name').value='';}
  else toast(r.error,'error');
}

// ── Profile ────────────────────────────────────────────────────────────────
function profileTab(btn,section){
  document.querySelectorAll('.profile-tab').forEach(b=>b.className='profile-tab flex-1 py-1.5 md:py-2 rounded-md text-[10px] md:text-xs font-semibold text-slate-400 hover:text-white');
  btn.className='profile-tab flex-1 py-1.5 md:py-2 rounded-md text-[10px] md:text-xs font-semibold bg-blue-600 text-white';
  document.querySelectorAll('.profile-section').forEach(s=>s.classList.add('hidden'));
  document.getElementById(section).classList.remove('hidden');
}

function saveLayout() {
  const nw = document.getElementById('nav-w').value;
  const mw = document.getElementById('mem-w').value;
  localStorage.setItem('bc_nav_w', nw);
  localStorage.setItem('bc_mem_w', mw);
  toast('Layout settings saved', 'success');
  closeModal('profile-modal');
}

function resetLayout() {
  document.getElementById('nav-w').value = 240;
  document.getElementById('mem-w').value = 220;
  document.getElementById('nav-w-val').innerText = '240px';
  document.getElementById('mem-w-val').innerText = '220px';
  document.documentElement.style.setProperty('--nav-w', '240px');
  document.documentElement.style.setProperty('--mem-w', '220px');
  localStorage.removeItem('bc_nav_w');
  localStorage.removeItem('bc_mem_w');
  toast('Layout reset', 'success');
}

function loadLayoutState() {
  let nw = localStorage.getItem('bc_nav_w') || '240';
  let mw = localStorage.getItem('bc_mem_w') || '220';
  document.documentElement.style.setProperty('--nav-w', nw + 'px');
  document.documentElement.style.setProperty('--mem-w', mw + 'px');
  const nwEl = document.getElementById('nav-w');
  const mwEl = document.getElementById('mem-w');
  if(nwEl) { nwEl.value = nw; document.getElementById('nav-w-val').innerText = nw + 'px'; }
  if(mwEl) { mwEl.value = mw; document.getElementById('mem-w-val').innerText = mw + 'px'; }
}

function previewAvatar(inp){
  const file=inp.files[0];if(!file)return;
  const reader=new FileReader();
  reader.onload=e=>{newAvatar=e.target.result;document.getElementById('av-preview').innerHTML=`<img src="${newAvatar}" class="w-full h-full object-cover">`;};
  reader.readAsDataURL(file);
}
function updateColorPreview(c){document.getElementById('color-preview-name').style.color=c;}
function setColor(c){document.getElementById('name-color').value=c;updateColorPreview(c);}
function resetVipTheme(){
  if(document.getElementById('vip-theme')) {
    document.getElementById('vip-theme').value = '#0f172a';
    document.getElementById('vip-theme2').value = '#0f172a';
    document.getElementById('vip-accent').value = '#2563eb';
  }
}

async function saveProfile(){
  const color=document.getElementById('name-color').value;
  const data={name_color:color};
  if(newAvatar)data.avatar=newAvatar;
  
  const vUrl = document.getElementById('vip-avatar-url');
  if(vUrl !== null) data.avatar_url = vUrl.value;
  const vTag = document.getElementById('vip-tag');
  if(vTag !== null) data.vip_tag = vTag.value;
  const vTheme = document.getElementById('vip-theme');
  if(vTheme !== null) data.vip_theme = vTheme.value;
  const vTheme2 = document.getElementById('vip-theme2');
  if(vTheme2 !== null) data.vip_theme2 = vTheme2.value;
  const vAccent = document.getElementById('vip-accent');
  if(vAccent !== null) data.vip_accent = vAccent.value;

  const r=await api('update_profile',data,'POST');
  if(r.ok){
    ME.color=color;document.getElementById('self-name').style.color=color;
    if(newAvatar){const h=`<img src="${newAvatar}" class="w-full h-full object-cover" onerror="this.style.display='none'">`;document.getElementById('self-av-wrap').innerHTML=h;newAvatar=null;}
    toast('Profile saved! Loading changes...','success');
    setTimeout(() => location.reload(), 1000);
  }else toast(r.error,'error');
}

async function changePassword(){
  const oldPw=document.getElementById('pw-old').value;
  const newPw=document.getElementById('pw-new').value;
  const confirm=document.getElementById('pw-confirm').value;
  if(newPw!==confirm){toast('Passwords do not match','error');return;}
  const r=await api('change_password',{old_password:oldPw,new_password:newPw},'POST');
  if(r.ok){toast('Password changed!','success');document.getElementById('pw-old').value='';document.getElementById('pw-new').value='';document.getElementById('pw-confirm').value='';}
  else toast(r.error,'error');
}

// ── Admin panel ────────────────────────────────────────────────────────────
function openAdminPanel(){openModal('admin-modal');loadAdminUsers();checkMaintStatus();}

function adminTab(btn,section){
  document.querySelectorAll('.admin-tab').forEach(b=>b.className='admin-tab flex-1 py-2 px-2 rounded-md text-[11px] font-semibold text-slate-400 hover:text-white');
  btn.className='admin-tab flex-1 py-2 px-2 rounded-md text-[11px] font-semibold bg-red-500/20 text-red-400';
  document.querySelectorAll('.admin-section').forEach(s=>s.classList.add('hidden'));
  document.getElementById(section).classList.remove('hidden');
  if(section==='a-users')loadAdminUsers();
  if(section==='a-bans')loadAdminBans();
  if(section==='a-maintenance')checkMaintStatus();
  if(section==='a-channels-mgr')loadAdminChannels();
  if(section==='a-stats')loadAdminStats();
  if(section==='a-settings')loadAdminSettings();
  if(section==='a-sessions')loadAdminSessions();
  if(section==='a-feedback')loadAdminFeedback();
  if(section==='a-roles')loadAdminRoles();
}

async function loadAdminBans(q=''){
  const div=document.getElementById('admin-bans-list');
  const r=await api('admin_get_bans',{q});
  if(!r.ok||!r.bans.length){div.innerHTML='<p class="text-slate-500 italic text-sm py-4 text-center">No active bans found.</p>';return;}
  div.innerHTML=r.bans.map(b=>{
    const av=b.avatar?`<img src="${b.avatar}" class="w-full h-full object-cover">`:`<span class="text-xs font-bold" style="color:${b.name_color||'#3b82f6'}">${b.username[0].toUpperCase()}</span>`;
    
    let overlayHtml = '';
    if (b.avatar_overlay) {
      try {
        const ov = JSON.parse(b.avatar_overlay);
        if(ov.url) {
           overlayHtml = `<img src="${esc(ov.url)}" style="position:absolute; width:100%; height:100%; top:${ov.y||0}%; left:${ov.x||0}%; transform:scale(${ov.scale||1}); pointer-events:none; z-index:10; object-fit:contain;">`;
        }
      } catch(e){}
    }
    
    return `<div class="user-table-row flex items-center gap-3 px-3 py-2.5 rounded-lg border border-slate-800 hover:border-slate-700 transition-colors">
      <div class="relative w-8 h-8 flex-shrink-0">
        <div class="w-full h-full rounded-full bg-slate-800 border border-slate-700 overflow-hidden flex items-center justify-center flex-shrink-0">${av}</div>
        ${overlayHtml}
      </div>
      <div class="flex-1 min-w-0">
        <div class="flex items-center gap-1.5 flex-wrap">
          <span class="text-sm font-medium text-slate-200 truncate">${esc(b.username)}</span>
          <span class="text-xs text-slate-600 font-mono">#${b.id}</span>
        </div>
        <p class="text-[10px] text-red-400/70 mt-0.5">⛔ ${esc(b.duration)} · ${esc(b.reason||'No reason')} · By: ${esc(b.banned_by_name||'Unknown')}</p>
      </div>
      <button onclick="doAction('admin_unban',{user_id:${b.id}},'User unbanned'); setTimeout(loadAdminBans, 300);"
        class="text-xs bg-emerald-600/15 hover:bg-emerald-600/25 text-emerald-400 border border-emerald-500/25 px-2.5 py-1.5 rounded-lg transition-all flex-shrink-0 flex items-center gap-1.5">
        <i class="fa-solid fa-unlock"></i> Unban
      </button>
    </div>`;
  }).join('');
}

// Admin users table
async function loadAdminUsers(q=''){
  const div=document.getElementById('admin-users-list');
  const r=await api('admin_get_users',{q});
  if(!r.ok||!r.users.length){div.innerHTML='<p class="text-slate-500 italic text-sm py-4 text-center">No users found.</p>';return;}
  div.innerHTML=r.users.map(u=>{
    const bannedBadge=u.is_banned
      ?`<span class="text-[10px] bg-red-500/20 text-red-400 px-1.5 py-0.5 rounded font-semibold flex-shrink-0">BANNED</span>`
      :'';
    const adminBadge=u.is_admin
      ?`<span class="text-[10px] bg-blue-500/20 text-blue-400 px-1.5 py-0.5 rounded font-semibold flex-shrink-0">ADMIN</span>`
      :'';
    const selfBadge=u.id==ME.id
      ?`<span class="text-[10px] bg-emerald-500/20 text-emerald-400 px-1.5 py-0.5 rounded font-semibold flex-shrink-0">YOU</span>`
      :'';
    const onlineDot=u.is_online
      ?'<span class="w-2 h-2 bg-emerald-400 rounded-full flex-shrink-0"></span>'
      :'<span class="w-2 h-2 bg-slate-700 rounded-full flex-shrink-0"></span>';

    // Ban expiry calculation
    let banLine='';
    if(u.is_banned&&u.duration){
      if(u.duration==='permanent'){
        banLine=`<p class="text-[10px] text-red-400/70 mt-0.5">⛔ Permanent ban · ${esc(u.reason||'no reason')}</p>`;
      } else {
        banLine=`<p class="text-[10px] text-orange-400/80 mt-0.5">⏱ ${esc(u.duration)} ban · ${esc(u.reason||'no reason')}</p>`;
      }
    }
    
    let overlayHtml = '';
    if (u.avatar_overlay) {
      try {
        const ov = JSON.parse(u.avatar_overlay);
        if(ov.url) {
           overlayHtml = `<img src="${esc(ov.url)}" style="position:absolute; width:100%; height:100%; top:${ov.y||0}%; left:${ov.x||0}%; transform:scale(${ov.scale||1}); pointer-events:none; z-index:10; object-fit:contain;">`;
        }
      } catch(e){}
    }
    
    const av=u.avatar?`<img src="${u.avatar}" class="w-full h-full object-cover">`:`<span class="text-xs font-bold" style="color:${u.name_color||'#3b82f6'}">${u.username[0].toUpperCase()}</span>`;

    return `<div class="user-table-row flex items-center gap-2.5 px-3 py-2.5 rounded-lg border border-slate-800 hover:border-slate-700 transition-colors">
      <div class="relative w-8 h-8 flex-shrink-0">
        <div class="w-full h-full rounded-full bg-slate-800 border border-slate-700 overflow-hidden flex items-center justify-center flex-shrink-0">${av}</div>
        ${overlayHtml}
        <div class="absolute -bottom-1 -right-1 flex items-center justify-center bg-slate-900 border border-slate-800 rounded-full p-0.5">${onlineDot}</div>
      </div>
      <div class="flex-1 min-w-0">
        <div class="flex items-center gap-1.5 flex-wrap">
          <span class="text-sm font-medium text-slate-200 truncate">${esc(u.username)}</span>
          <span class="text-xs text-slate-600 font-mono">#${u.id}</span>
          ${adminBadge}${bannedBadge}${selfBadge}
        </div>
        ${banLine}
      </div>
      <button onclick="openUserActions(${JSON.stringify(u).replace(/"/g,'&quot;')})"
        class="text-xs bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 px-2.5 py-1.5 rounded-lg transition-all flex-shrink-0 flex items-center gap-1.5">
        <i class="fa-solid fa-ellipsis"></i> Actions
      </button>
    </div>`;
  }).join('');
}

// Open per-user action modal
function openUserActions(u){
  actionTargetUser=u;

  // Hide all sub-sections on open
  document.getElementById('ua-pw-section').classList.add('hidden');
  document.getElementById('ua-ban-section').classList.add('hidden');
  document.getElementById('ua-ban-info').classList.add('hidden');
  document.getElementById('ua-ext-section').classList.add('hidden');
  document.getElementById('ua-new-pw').value='';
  document.getElementById('ua-ban-reason-inp').value='';
  document.getElementById('ua-ban-type').value='permanent';
  document.getElementById('ua-ban-time-wrap').classList.add('hidden');
  document.getElementById('ua-ban-preview').classList.add('hidden');

  // User info card
  const onlineDot=u.is_online?'<span class="inline-block w-2 h-2 bg-emerald-400 rounded-full mr-1"></span>':'';
  const statusLabel=u.is_banned
    ?'<span class="text-red-400 font-semibold">⛔ Banned</span>'
    :(u.is_online?'<span class="text-emerald-400">● Online</span>':'<span class="text-slate-500">○ Offline</span>');
  const adminLabel=u.is_admin?'<span class="ml-1 text-[10px] bg-blue-500/20 text-blue-400 px-1.5 py-0.5 rounded font-semibold">ADMIN</span>':'';
  
  let overlayHtml = '';
  if (u.avatar_overlay) {
    try {
      const ov = JSON.parse(u.avatar_overlay);
      if(ov.url) {
         overlayHtml = `<img src="${esc(ov.url)}" style="position:absolute; width:100%; height:100%; top:${ov.y||0}%; left:${ov.x||0}%; transform:scale(${ov.scale||1}); pointer-events:none; z-index:10; object-fit:contain;">`;
      }
    } catch(e){}
  }

  document.getElementById('ua-info').innerHTML=
    `<div class="flex items-center gap-3">
      <div class="relative w-10 h-10 flex-shrink-0">
        <div class="w-full h-full rounded-full bg-blue-600 flex-shrink-0 overflow-hidden flex items-center justify-center text-sm font-bold text-white border-2 border-slate-700">
          ${u.avatar?`<img src="${u.avatar}" class="w-full h-full object-cover">`:(u.username||'?')[0].toUpperCase()}
        </div>
        ${overlayHtml}
      </div>
      <div class="flex-1 min-w-0">
        <p class="font-semibold text-slate-100">${esc(u.username)}${adminLabel} <span class="text-slate-600 font-mono text-xs">#${u.id}</span></p>
        <p class="text-xs text-slate-500 mt-0.5">Joined ${(u.created_at||'').slice(0,10)} · ${statusLabel}</p>
        ${u.last_seen?`<p class="text-xs text-slate-600 mt-0.5">Last seen ${fmtTime(u.last_seen)||u.last_seen.slice(0,16)}</p>`:''}
      </div>
    </div>`;

  // Show ban details if banned
  if(u.is_banned && (u.reason||u.duration)){
    const banInfo=document.getElementById('ua-ban-info');
    banInfo.classList.remove('hidden');
    document.getElementById('ua-ban-reason').textContent=u.reason||'No reason given';
    document.getElementById('ua-ban-duration').textContent=u.duration||'permanent';
    // Calculate expiry
    let expiresText='Never (permanent)';
    if(u.duration&&u.duration!=='permanent'&&u.ban_created_at){
      const m=u.duration.match(/^(\d+)\s*(\w+)$/);
      if(m){
        const exp=new Date(u.ban_created_at.replace(' ','T')+'Z');
        const unit=m[2].toLowerCase();
        const amt=parseInt(m[1]);
        if(unit.startsWith('minute'))exp.setMinutes(exp.getMinutes()+amt);
        else if(unit.startsWith('hour'))exp.setHours(exp.getHours()+amt);
        else if(unit.startsWith('day'))exp.setDate(exp.getDate()+amt);
        else if(unit.startsWith('week'))exp.setDate(exp.getDate()+amt*7);
        const now=new Date();
        if(exp<now){expiresText='<span class="text-yellow-400">Expired (auto-unban pending)</span>';}
        else{expiresText=exp.toLocaleString();}
      }
    }
    document.getElementById('ua-ban-expires').innerHTML=expiresText;
    document.getElementById('ua-ban-by').textContent=u.banned_by_name||'Unknown';
  }

  const isSelf=u.id==ME.id;
  const isTargetGollclock=u.username==='gollclock';
  const btns=[];
  const hP = (p) => ME.isSuperAdmin || (ME.perms && ME.perms[p]);

  if(!isSelf&&!isTargetGollclock){
    if(u.is_banned){
      if(hP('ua-unban')||hP('ua-ban')) btns.push(actionBtn('✓ Unban User','fa-circle-check','emerald', `doAction('admin_unban', {user_id: ${u.id}}, 'User unbanned')`));
    } else {
      if(hP('ua-ban')) btns.push(actionBtn('Ban User','fa-ban','red', `document.getElementById('ua-ban-section').classList.toggle('hidden'); document.getElementById('ua-pw-section').classList.add('hidden'); document.getElementById('ua-ext-section').classList.add('hidden');`));
    }
    
    btns.push(actionBtn('Extended Actions...','fa-ellipsis-h','blue', `document.getElementById('ua-ext-section').classList.toggle('hidden'); document.getElementById('ua-ban-section').classList.add('hidden'); document.getElementById('ua-pw-section').classList.add('hidden');`));

    if(hP('ua-promote')){
      if(u.is_admin){
        btns.push(actionBtn('Remove Admin Role','fa-user-minus','orange', `doGenericAction('demote',${u.id},'Admin role removed')`));
      } else {
        btns.push(actionBtn('Make Admin','fa-shield-halved','blue', `doGenericAction('promote',${u.id},'User promoted to admin!')`));
      }
    }
    if(hP('ua-reset')) btns.push(actionBtn('Reset Password','fa-key','purple', `promptAction('reset_pass', ${u.id}, 'Enter new password (min 6 chars):')`));
    if(hP('ua-delete')) btns.push(actionBtn('Delete Account','fa-user-xmark','red', `if(confirm('Permanently delete ${esc(u.username)}? Cannot be undone.')) doGenericAction('delete',${u.id},'Account deleted')`));
  }
  if(isSelf||isTargetGollclock){
    btns.push(`<p class="text-xs text-slate-500 italic py-2 text-center">No standard actions available for this account.</p>`);
  }

  document.getElementById('ua-buttons').innerHTML=btns.join('');
  
  // Render extended actions
  const extBtns = [];
  if(!isSelf&&!isTargetGollclock) {
      if(ME.isSuperAdmin) extBtns.push(actionBtn('Assign Role','fa-user-tag','blue', `assignRolePrompt(${u.id})`));
      if(hP('ua-control')) extBtns.push(actionBtn('Control User Account','fa-user-secret','red', `doGenericAction('control', ${u.id}, 'Taking control...')`));
      if(hP('ua-kick')) extBtns.push(actionBtn('Kick (Force Logout)','fa-person-through-window','orange', `doGenericAction('kick', ${u.id}, 'User kicked')`));
      if(hP('ua-mute')) {
        extBtns.push(actionBtn('Mute User','fa-microphone-lines-slash','red', `doGenericAction('mute', ${u.id}, 'User muted')`));
        extBtns.push(actionBtn('Unmute User','fa-microphone','emerald', `doGenericAction('unmute', ${u.id}, 'User unmuted')`));
      }
      if(hP('ua-avatar')) extBtns.push(actionBtn('Remove Avatar','fa-image-portrait','orange', `doGenericAction('remove_avatar', ${u.id}, 'Avatar removed')`));
      if(hP('ua-color')) extBtns.push(actionBtn('Reset Name Color','fa-palette','blue', `doGenericAction('reset_color', ${u.id}, 'Color reset')`));
      if(hP('ua-tag')) {
        extBtns.push(actionBtn('Set Custom Tag','fa-tag','purple', `promptAction('set_tag', ${u.id}, 'Enter tag name (leave blank to clear):')`));
        extBtns.push(actionBtn('Set Tag Color','fa-fill-drip','purple', `promptAction('set_tag_color', ${u.id}, 'Enter hex color (e.g., #ff0000):')`));
      }
      if(hP('ua-warn')) extBtns.push(actionBtn('Send Warning Alert','fa-triangle-exclamation','orange', `promptAction('warn', ${u.id}, 'Warning message:')`));
      if(hP('ua-mute')) extBtns.push(actionBtn('Wipe Inbox','fa-envelope-open-text','red', `doGenericAction('wipe_inbox', ${u.id}, 'Inbox wiped')`)); // or a separate perm, but mute/wipe are similar admin tools
      if(hP('ua-media')) {
        extBtns.push(actionBtn('Revoke Image Perms','fa-image','red', `doGenericAction('revoke_img', ${u.id}, 'Image permission revoked')`));
        extBtns.push(actionBtn('Restore Image Perms','fa-image','emerald', `doGenericAction('allow_img', ${u.id}, 'Image permission restored')`));
        extBtns.push(actionBtn('Revoke Audio Perms','fa-microphone','red', `doGenericAction('revoke_audio', ${u.id}, 'Audio permission revoked')`));
        extBtns.push(actionBtn('Restore Audio Perms','fa-microphone','emerald', `doGenericAction('allow_audio', ${u.id}, 'Audio permission restored')`));
      }
      if(hP('ua-delete')) extBtns.push(actionBtn('Remove All Friends','fa-user-group','red', `if(confirm('Wipe all friends?')) doGenericAction('del_friends', ${u.id}, 'Friends wiped')`));
      if(hP('ua-shadowban')) {
        extBtns.push(actionBtn('Shadowban','fa-ghost','purple', `doGenericAction('shadowban', ${u.id}, 'User shadowbanned')`));
        extBtns.push(actionBtn('Un-shadowban','fa-eye','emerald', `doGenericAction('unshadowban', ${u.id}, 'Shadowban lifted')`));
      }
      if(hP('ua-vip')) {
        extBtns.push(actionBtn('Mark VIP User','fa-crown','purple', `doGenericAction('mark_vip', ${u.id}, 'VIP marked')`));
        extBtns.push(actionBtn('Remove VIP User','fa-chess-pawn','slate', `doGenericAction('remove_vip', ${u.id}, 'VIP removed')`));
      }
      if(hP('ua-reset')) extBtns.push(actionBtn('Change Username','fa-id-card','blue', `promptAction('change_username', ${u.id}, 'New username (2-32 chars):')`));
      if(hP('ua-control')) extBtns.push(actionBtn('Force Say Message','fa-comment-dots','emerald', `promptAction('force_say', ${u.id}, 'Message to force user to send in General:\\n(Note: Does not bypass ratelimits)')`));
      if(hP('ua-purge')) extBtns.push(actionBtn('Purge All Messages','fa-fire','orange', `if(confirm('Purge all ${esc(u.username)} messages?')) doGenericAction('purge_user',${u.id},'Messages purged')`));
  }
  document.getElementById('ua-extended-buttons').innerHTML = extBtns.join('');
  
  closeModal('admin-modal');
  openModal('user-action-modal');
}

async function doGenericAction(act, uid, msg) {
    const r = await api('admin_action', {user_id: uid, act: act}, 'POST');
    if (r.ok) {
        toast(msg || 'Action completed', 'success');
        if (act === 'control') setTimeout(() => window.location.reload(), 800);
        closeModal('user-action-modal');
        loadAdminUsers(document.getElementById('user-search')?.value||'');
    } else {
        toast(r.error, 'error');
    }
}

async function promptAction(act, uid, promptMsg) {
    const val = prompt(promptMsg);
    if (val !== null && val.trim() !== '') {
        const r = await api('admin_action', {user_id: uid, act: act, val: val.trim()}, 'POST');
        if (r.ok) {
            toast('Action applied', 'success');
            closeModal('user-action-modal');
            loadAdminUsers(document.getElementById('user-search')?.value||'');
        } else {
            toast(r.error, 'error');
        }
    }
}

async function leaveControl() {
    const r = await api('admin_action', {user_id: ME.id, act: 'leave_control'}, 'POST');
    if (r.ok) {
        window.location.reload();
    }
}

function actionBtn(label,icon,color,onclickStr){
  const colors={
    slate:'bg-slate-700 hover:bg-slate-600 text-slate-300 border-slate-600',
    red:'bg-red-600/15 hover:bg-red-600/25 text-red-400 border-red-500/25',
    emerald:'bg-emerald-600/15 hover:bg-emerald-600/25 text-emerald-400 border-emerald-500/25',
    blue:'bg-blue-600/15 hover:bg-blue-600/25 text-blue-400 border-blue-500/25',
    orange:'bg-orange-600/15 hover:bg-orange-600/25 text-orange-400 border-orange-500/25',
    purple:'bg-purple-600/15 hover:bg-purple-600/25 text-purple-400 border-purple-500/25',
  };
  return `<button onclick="${onclickStr}" class="w-full flex items-center justify-start gap-3 px-4 py-2.5 rounded-lg border text-sm font-medium transition-all ${colors[color]||colors.blue}"><i class="fa-solid ${icon} w-4 text-center"></i><span class="truncate">${label}</span></button>`;
}

async function doAction(action,data,successMsg){
  const r=await api(action,data,'POST');
  if(r.ok){
    toast(successMsg,'success');
    closeModal('user-action-modal');
    loadAdminUsers(document.getElementById('user-search')?.value||'');
    if(document.getElementById('a-bans') && !document.getElementById('a-bans').classList.contains('hidden')) {
      loadAdminBans(document.getElementById('ban-search')?.value||'');
    }
  }
  else toast(r.error,'error');
}

async function submitBug(e) {
  const msgEl = document.getElementById('bug-message');
  const msg = msgEl.value.trim();
  if(!msg) return;
  const btn = e ? e.currentTarget : document.querySelector('#bug-modal button.bg-orange-600'); 
  if(btn) { btn.disabled = true; btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i>'; }
  const r = await api('submit_feedback', {message: msg}, 'POST');
  if(btn) { btn.disabled = false; btn.innerHTML = '<i class="fa-solid fa-paper-plane"></i> Send Report'; }
  if(r.ok) {
     toast('Feedback sent to developer!', 'success');
     closeModal('bug-modal');
     msgEl.value = '';
  } else toast(r.error, 'error');
}

async function loadAdminFeedback() {
  const list = document.getElementById('admin-feedback-list');
  list.innerHTML = '<p class="text-slate-500 italic text-sm">Loading feedbacks...</p>';
  const r = await api('admin_get_feedback');
  if(!r.ok) { list.innerHTML = `<p class="text-red-400 text-sm">Could not load.</p>`; return; }
  if(!r.feedbacks.length) { list.innerHTML = '<p class="text-slate-500 italic text-sm">No feedback received</p>'; return; }
  
  list.innerHTML = r.feedbacks.map(f => {
    const color = f.name_color || '#3b82f6';
    const av = f.avatar ? `<img src="${f.avatar}" class="w-full h-full object-cover">` : `<span class="text-[10px] font-bold" style="color:${color}">${f.username[0].toUpperCase()}</span>`;
    return `<div class="bg-slate-800 rounded-lg p-3 text-sm text-slate-300 relative group border border-slate-700 hover:border-slate-600 transition-colors">
       <button onclick="delFeedback(${f.id})" class="absolute top-2 right-2 text-slate-500 hover:text-red-400 opacity-0 group-hover:opacity-100 transition-all"><i class="fa-solid fa-trash"></i></button>
       <div class="flex items-center gap-2 mb-2">
         <div class="w-5 h-5 rounded-full overflow-hidden bg-slate-900 border border-slate-700 flex items-center justify-center flex-shrink-0">${av}</div>
         <span class="font-bold text-xs" style="color:${color}">${esc(f.username)}</span>
         <span class="text-[10px] text-slate-500">${new Date(f.created_at).toLocaleString()}</span>
       </div>
       <div class="whitespace-pre-wrap text-xs text-slate-200">${esc(f.message)}</div>
    </div>`;
  }).join('');
}

async function delFeedback(id) {
  if(!confirm('Delete this feedback?')) return;
  const r = await api('admin_action', {act: 'del_feedback', val: id.toString()}, 'POST');
  if(r.ok) loadAdminFeedback();
  else toast('Error deleting', 'error');
}

function toggleBanTime(){
  const timed=document.getElementById('ua-ban-type').value==='timed';
  document.getElementById('ua-ban-time-wrap').classList.toggle('hidden',!timed);
  updateBanPreview();
}

function updateBanPreview(){
  const preview=document.getElementById('ua-ban-preview');
  const type=document.getElementById('ua-ban-type').value;
  const reason=document.getElementById('ua-ban-reason-inp').value.trim();
  if(type==='permanent'){
    preview.textContent=`Account will be banned permanently${reason?` · Reason: "${reason}"`:' · No reason given'}`;
    preview.classList.remove('hidden');
  } else if(type==='ip') {
    preview.textContent=`Target IP will be network-banned permanently${reason?` · Reason: "${reason}"`:' · No reason given'}`;
    preview.classList.remove('hidden');
  } else if(type==='cookie') {
    preview.textContent=`Target device will be cookie-banned permanently${reason?` · Reason: "${reason}"`:' · No reason given'}`;
    preview.classList.remove('hidden');
  } else {
    const amt=document.getElementById('ua-ban-amount').value;
    const unit=document.getElementById('ua-ban-unit').value;
    if(amt>0){
      preview.textContent=`Will be banned for ${amt} ${unit}${reason?` · Reason: "${reason}"`:' · No reason given'}`;
      preview.classList.remove('hidden');
    }
  }
}

// Wire up live preview
document.addEventListener('DOMContentLoaded',()=>{
  ['ua-ban-reason-inp','ua-ban-amount','ua-ban-unit','ua-ban-type'].forEach(id=>{
    document.getElementById(id)?.addEventListener('input',updateBanPreview);
    document.getElementById(id)?.addEventListener('change',updateBanPreview);
  });
});

async function submitBan(){
  const id=actionTargetUser?.id;
  if(!id){toast('No user selected','error');return;}
  const reason=document.getElementById('ua-ban-reason-inp').value.trim()||'No reason given';
  const icon=document.getElementById('ua-ban-icon-inp').value.trim()||'fa-gavel';
  const type=document.getElementById('ua-ban-type').value;
  const data={user_id:id,reason,ban_icon:icon};
  if(type==='permanent' || type==='ip' || type==='cookie'){
    data.duration=type;
  } else {
    const amt=parseInt(document.getElementById('ua-ban-amount').value)||1;
    const unit=document.getElementById('ua-ban-unit').value;
    data.duration='timed';
    data.time_amount=amt;
    data.time_unit=unit;
  }
  const r=await api('admin_ban',data,'POST');
  if(r.ok){
    toast(`${actionTargetUser.username} banned (${type})`, 'success');
    document.getElementById('ua-ban-section').classList.add('hidden');
    closeModal('user-action-modal');
    loadAdminUsers(document.getElementById('user-search')?.value||'');
    if(document.getElementById('a-bans') && !document.getElementById('a-bans').classList.contains('hidden')) {
      loadAdminBans(document.getElementById('ban-search')?.value||'');
    }
  } else toast(r.error,'error');
}

async function doResetPw(){
  const pw=document.getElementById('ua-new-pw').value;
  if(!pw||pw.length<6){toast('Min 6 chars','error');return;}
  const r=await api('admin_reset_password',{user_id:actionTargetUser.id,new_password:pw},'POST');
  if(r.ok){toast('Password reset!','success');document.getElementById('ua-pw-section').classList.add('hidden');}else toast(r.error,'error');
}

// Announce
async function adminAnnounce(){
  const text=document.getElementById('admin-msg').value.trim();if(!text)return;
  const r=await api('admin_announce',{content:text},'POST');
  if(r.ok){toast('Announced!','success');document.getElementById('admin-msg').value='';closeModal('admin-modal');lastMsgId=0;oldestMsgId=Infinity;document.getElementById('messages').innerHTML='';await loadMsgs(true);}
  else toast(r.error,'error');
}

// 5 New Admin Features
async function loadAdminChannels() {
  const r = await api('get_channels');
  if(!r.ok) return;
  document.getElementById('admin-channels-list').innerHTML = r.channels.map(c => `
    <div class="flex items-center justify-between bg-slate-800 p-3 rounded-lg border border-slate-700">
      <span class="text-sm font-medium text-slate-200"><i class="fa-solid fa-hashtag text-slate-500 mr-2 text-xs"></i>${esc(c.name)}</span>
      <button onclick="adminDelChannel(${c.id})" class="text-red-400 hover:text-red-300 text-xs p-1"><i class="fa-solid fa-trash"></i></button>
    </div>
  `).join('');
}
async function adminAddChannel() {
  const name = document.getElementById('new-channel-name').value.trim();
  if(!name) return;
  const r = await api('admin_add_channel', {name}, 'POST');
  if(r.ok) { toast('Channel added', 'success'); document.getElementById('new-channel-name').value=''; loadAdminChannels(); loadChannels(); }
  else toast(r.error, 'error');
}
async function adminDelChannel(id) {
  if(!confirm('Delete this channel and all its messages?')) return;
  const r = await api('admin_del_channel', {id}, 'POST');
  if(r.ok) { toast('Channel deleted', 'success'); loadAdminChannels(); loadChannels(); }
  else toast(r.error, 'error');
}

async function loadAdminStats() {
  const r = await api('admin_get_stats');
  if(!r.ok) return;
  document.getElementById('admin-stats-grid').innerHTML = `
    <div class="bg-slate-800 p-4 rounded-lg border border-slate-700"><p class="text-xs text-slate-500 uppercase tracking-wider mb-1">Total Users</p><p class="text-2xl font-bold text-blue-400">${r.stats.users}</p></div>
    <div class="bg-slate-800 p-4 rounded-lg border border-slate-700"><p class="text-xs text-slate-500 uppercase tracking-wider mb-1">Total Messages</p><p class="text-2xl font-bold text-emerald-400">${r.stats.messages}</p></div>
    <div class="bg-slate-800 p-4 rounded-lg border border-slate-700"><p class="text-xs text-slate-500 uppercase tracking-wider mb-1">Channels</p><p class="text-2xl font-bold text-purple-400">${r.stats.channels}</p></div>
    <div class="bg-slate-800 p-4 rounded-lg border border-slate-700"><p class="text-xs text-slate-500 uppercase tracking-wider mb-1">Active Bans</p><p class="text-2xl font-bold text-red-400">${r.stats.bans}</p></div>
  `;
}

async function adminPurgeUser() {
  const uid = document.getElementById('purge-user-id').value;
  if(!uid) return;
  if(!confirm('Delete ALL messages from user ID ' + uid + '?')) return;
  const r = await api('admin_purge_user', {user_id: uid}, 'POST');
  if(r.ok) { toast(`Purged ${r.deleted} messages`, 'success'); document.getElementById('purge-user-id').value=''; await loadMsgs(true); }
  else toast(r.error, 'error');
}

async function loadAdminSettings() {
  const r = await api('admin_get_settings');
  if(!r.ok) return;
  const s = r.settings;
  document.getElementById('admin-settings-list').innerHTML = `
    <div class="flex items-center justify-between bg-slate-800 p-3 rounded-lg border border-slate-700">
      <span class="text-sm text-slate-200">Allow Image Uploads</span>
      <input type="checkbox" id="set-allow-images" ${s.allow_images==='1'?'checked':''} class="w-4 h-4 accent-blue-500">
    </div>
    <div class="flex items-center justify-between bg-slate-800 p-3 rounded-lg border border-slate-700">
      <span class="text-sm text-slate-200">Allow Audio Uploads</span>
      <input type="checkbox" id="set-allow-audio" ${s.allow_audio==='1'?'checked':''} class="w-4 h-4 accent-blue-500">
    </div>
    <div class="bg-slate-800 p-3 rounded-lg border border-slate-700">
      <label class="block text-sm font-semibold text-slate-200 mb-1">Custom Wordle Word</label>
      <p class="text-xs text-slate-400 mb-2">Leave blank to fetch from the official Wordle Answers API automatically. If set, must be exactly 5 letters.</p>
      <input type="text" id="set-custom-wordle" maxlength="5" placeholder="APPLE" class="w-full bg-slate-900 border border-slate-700 rounded p-2 text-white outline-none focus:border-blue-500 transition-colors uppercase font-mono" value="${s.custom_wordle || ''}">
    </div>
  `;
}
async function adminSaveSettings() {
  const wordle = (document.getElementById('set-custom-wordle')?.value || '').toUpperCase().trim();
  if (wordle && wordle.length !== 5) return toast('Custom Wordle word must be exactly 5 letters', 'error');

  const data = {
    allow_images: document.getElementById('set-allow-images').checked ? '1' : '0',
    allow_audio: document.getElementById('set-allow-audio').checked ? '1' : '0',
    custom_wordle: wordle
  };
  const r = await api('admin_save_settings', data, 'POST');
  if(r.ok) toast('Settings saved', 'success');
  else toast(r.error, 'error');
}

async function loadAdminSessions() {
  const r = await api('admin_get_sessions');
  if(!r.ok) return;
  document.getElementById('admin-sessions-list').innerHTML = r.sessions.map(s => `
    <div class="flex items-center justify-between bg-slate-800 p-3 rounded-lg border border-slate-700">
      <div class="flex items-center gap-2">
        <span class="text-sm font-medium text-slate-200">${esc(s.username)}</span>
        <span class="text-[10px] text-slate-500 font-mono">#${s.id}</span>
      </div>
      <span class="text-xs text-slate-400">${s.last_seen}</span>
    </div>
  `).join('');
}

// Clear channel
function populateClearSelect(){
  const sel=document.getElementById('clear-channel');if(!sel)return;
  loadChannels().then(()=>{
    sel.innerHTML=channels.map(c=>`<option value="${c.id}">#${esc(c.name)}</option>`).join('');
  });
}
async function clearChannel(){
  const cid=document.getElementById('clear-channel').value;
  const ch=channels.find(c=>c.id==cid);
  if(!confirm(`Clear all messages in #${ch?.name||cid}? This is permanent.`))return;
  const r=await api('admin_clear_channel',{channel_id:cid},'POST');
  if(r.ok){toast('Channel cleared','success');if(currentChannel==cid){document.getElementById('messages').innerHTML='';lastMsgId=0;oldestMsgId=Infinity;}}
  else toast(r.error,'error');
}

// Maintenance
async function checkMaintStatus(){
  const r=await api('admin_get_maintenance');if(!r.ok)return;
  maintOn=r.on;applyMaintUI(r.on,r.message);
}
function applyMaintUI(on,msg){
  maintOn=on;
  const toggle=document.getElementById('maint-toggle');
  const knob=document.getElementById('maint-knob');
  const status=document.getElementById('maint-status-text');
  const banner=document.getElementById('maint-banner');
  if(!toggle)return;
  toggle.className='relative inline-flex w-12 h-6 rounded-full transition-colors '+(on?'bg-yellow-500':'bg-slate-700');
  if(knob)knob.style.transform=on?'translateX(24px)':'translateX(0)';
  if(status){status.textContent=on?'⚠ Maintenance ON — users see maintenance page':'✓ Maintenance OFF — users can access chat';
  status.className='text-xs font-semibold '+(on?'text-yellow-400':'text-emerald-400');}
  if(banner)on?banner.classList.remove('hidden'):banner.classList.add('hidden');
  const msgEl=document.getElementById('maint-msg');if(msgEl&&msg)msgEl.value=msg;
}
async function toggleMaintenance(){
  const newVal=maintOn?'0':'1';
  const msg=document.getElementById('maint-msg')?.value||'';
  const r=await api('admin_set_maintenance',{on:newVal,message:msg},'POST');
  if(r.ok){applyMaintUI(!maintOn,msg);toast(maintOn?'Maintenance OFF':'⚠ Maintenance ON',maintOn?'success':'info');}
  else toast(r.error,'error');
}
async function saveMaintMsg(){
  const msg=document.getElementById('maint-msg').value;
  const r=await api('admin_set_maintenance',{on:maintOn?'1':'0',message:msg},'POST');
  if(r.ok)toast('Message saved!','success');else toast(r.error,'error');
}

// New admin functions
async function adminSaveBanTemplate(){
  const type=document.getElementById('adm-tpl-type').value;
  const html=document.getElementById('adm-tpl-html').value;
  const r=await api('admin_set_ban_template',{ban_type:type,html},'POST');
  if(r.ok)toast('Ban template saved!','success');else toast(r.error,'error');
}
async function adminStartChallenge(){
  const word=document.getElementById('nitro-word-input').value;
  const r=await api('admin_start_challenge',{word},'POST');
  if(r.ok)toast('Challenge updated!','success');else toast(r.error,'error');
}
async function adminCreateRole(){
  const name=document.getElementById('role-name-input').value;
  const color=document.getElementById('role-color-input').value;
  const perms = {};
  document.querySelectorAll('#role-perms-boxes input:checked, #role-perms-actions input:checked').forEach(cb => {
    perms[cb.value] = true;
  });
  const r=await api('admin_create_role',{name,color,permissions:JSON.stringify(perms)},'POST');
  if(r.ok){toast('Role created','success');loadAdminRoles();}else toast(r.error,'error');
}
async function loadAdminRoles(){
  const list=document.getElementById('admin-roles-list');
  if(!list) return;
  const r=await api('admin_get_roles');
  if(r.ok){
    window.allAdminRoles = r.roles;
    list.innerHTML=r.roles.map(rr=>`<div class="flex justify-between items-center bg-slate-800 p-2 rounded border border-slate-700">
      <span style="color:${esc(rr.color)}">${esc(rr.name)}</span>
      <span class="text-xs text-slate-500">ID: ${rr.id}</span>
    </div>`).join('');
  }
}
async function adminSetOverlay(){
  const uid=document.getElementById('overlay-uid').value;
  const url=document.getElementById('overlay-url').value;
  const scale=document.getElementById('overlay-scale').value;
  const x=document.getElementById('overlay-x').value;
  const y=document.getElementById('overlay-y').value;
  const r=await api('admin_set_overlay',{user_id:uid,overlay:url,scale,offset_x:x,offset_y:y},'POST');
  if(r.ok)toast('Overlay applied','success');else toast(r.error,'error');
}

function updateOverlayPreview() {
  const url = document.getElementById('overlay-url').value;
  const scale = document.getElementById('overlay-scale').value;
  const x = document.getElementById('overlay-x').value;
  const y = document.getElementById('overlay-y').value;
  const img = document.getElementById('overlay-preview-img');
  
  if (url) {
    img.src = url;
    img.style.transform = `scale(${scale || 1})`;
    img.style.left = `${x || 0}%`;
    img.style.top = `${y || 0}%`;
    img.classList.remove('hidden');
  } else {
    img.classList.add('hidden');
  }
}
async function assignRolePrompt(uid){
  let msg = 'Enter role ID to assign, or 0 to remove.\nAvailable Roles:\n';
  if (window.allAdminRoles) {
    window.allAdminRoles.forEach(r => { msg += `ID: ${r.id} - ${r.name}\n`; });
  } else { msg += '(Load roles tab first to see IDs)'; }
  const val = prompt(msg);
  if(val !== null && val.trim() !== ''){
    const r=await api('admin_assign_role',{user_id:uid,role_id:val},'POST');
    if(r.ok)toast('Role assigned','success');else toast(r.error,'error');
  }
}

// ── Modals ─────────────────────────────────────────────────────────────────
function openModal(id){document.getElementById(id)?.classList.add('open');}
function closeModal(id){document.getElementById(id)?.classList.remove('open');}

// ── Toast ──────────────────────────────────────────────────────────────────
function toast(msg,type='info'){
  const styles={success:'border-emerald-500/40 text-emerald-300',error:'border-red-500/40 text-red-400',info:'border-blue-500/20 text-slate-300'};
  const el=document.createElement('div');el.className=`toast ${styles[type]||styles.info}`;el.textContent=msg;
  document.body.appendChild(el);
  twemoji.parse(el);
  setTimeout(()=>el.remove(),3500);
}

// ── Utils ──────────────────────────────────────────────────────────────────
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function fmtTime(ts){if(!ts)return'';const d=new Date(ts.replace(' ','T')+'Z');return d.toLocaleTimeString([],{hour:'2-digit',minute:'2-digit',hour12:true});}
function autoGrow(el){el.style.height='auto';el.style.height=Math.min(el.scrollHeight,112)+'px';}
</script>
</body>
</html>
