<?php
$reason = $_GET['reason'] ?? 'Violation of Terms of Service';
$iconParam = $_GET['icon'] ?? 'fa-gavel';
$isEmoji = false;
$parsedIcon = $iconParam;
if (!preg_match('/^fa-/', $iconParam) && urlencode($iconParam) !== $iconParam && strlen($iconParam) > 0) {
    // If it's not a fontawesome icon string, and it has special characters, assume it's an emoji
    $isEmoji = true;
} else if (!preg_match('/^fa-/', $iconParam) && strlen($iconParam) <= 4) {
    // Or if it's very short
    $isEmoji = true;
} else if (preg_match('/^fa-[a-z0-9\-]+$/', $iconParam)) {
    // fontawesome valid
    $isEmoji = false;
    $parsedIcon = htmlspecialchars($iconParam);
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Banned - BetterChat</title>
<script src="https://cdn.tailwindcss.com"></script>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<style>
body { background-color: #050505; color: #f8fafc; font-family: ui-sans-serif, system-ui, -apple-system, sans-serif; overflow: hidden; }
.glitch { animation: glitch 1.5s linear infinite; position: relative; }
@keyframes glitch {
  2%,64% { transform: translate(2px,0) skew(0deg); }
  4%,60% { transform: translate(-2px,0) skew(0deg); }
  62% { transform: translate(0,0) skew(5deg); }
}
.scanlines {
  position: fixed; top: 0; left: 0; width: 100vw; height: 100vh;
  background: linear-gradient(to bottom, rgba(255,255,255,0), rgba(255,255,255,0) 50%, rgba(0,0,0,0.2) 50%, rgba(0,0,0,0.2));
  background-size: 100% 4px; pointer-events: none; z-index: 50;
}
.vignette {
  position: fixed; inset: 0;
  background: radial-gradient(circle, transparent 50%, #000 150%);
  pointer-events: none; z-index: 40;
}
</style>
</head>
<body class="min-h-screen flex items-center justify-center p-4">
  <div class="scanlines"></div>
  <div class="vignette"></div>
  
  <div class="text-center relative z-10 w-full max-w-4xl mx-auto px-4">
    <div class="text-[8rem] md:text-[12rem] mb-2 leading-none relative">
      <?php if ($isEmoji): ?>
        <span class="drop-shadow-[0_0_40px_rgba(220,38,38,0.8)] leading-none"><?= htmlspecialchars($iconParam) ?></span>
      <?php else: ?>
        <i class="fa-solid <?= $parsedIcon ?> text-red-600 drop-shadow-[0_0_40px_rgba(220,38,38,0.8)]"></i>
      <?php endif; ?>
    </div>
    
    <h1 class="text-6xl md:text-8xl font-black text-red-600 mb-6 tracking-tighter glitch drop-shadow-2xl uppercase" style="text-shadow: 6px 6px 0px #450a0a;">
      You've Been Banned
    </h1>
    
    <div class="bg-red-950/40 border border-red-500/30 rounded-xl p-6 md:p-8 max-w-3xl mx-auto backdrop-blur-md shadow-2xl shadow-red-500/10">
      <p class="text-[10px] uppercase tracking-[0.3em] font-bold text-red-500/70 mb-3">Ban Reason</p>
      <p class="text-xl md:text-3xl text-red-100 font-medium">
        <?= htmlspecialchars($reason) ?>
      </p>
    </div>
    
    <div class="mt-12 opacity-50 font-mono text-xs text-red-400 space-y-1">
      <p>Connection Terminated.</p>
      <p>Access to BetterChat services has been completely disabled.</p>
      <p>ID: <?= htmlspecialchars(strtoupper(substr(md5($_SERVER['REMOTE_ADDR']), 0, 8))) ?></p>
    </div>
  </div>

  <script>
    // Add additional scary red flashes randomly
    setInterval(() => {
      document.body.style.backgroundColor = Math.random() > 0.95 ? '#240000' : '#050505';
      setTimeout(() => { document.body.style.backgroundColor = '#050505'; }, 50);
    }, 200);
  </script>
</body>
</html>
