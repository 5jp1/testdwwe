<?php
session_set_cookie_params(["samesite" => "None", "secure" => true]);
session_start();
header("Content-Security-Policy: frame-ancestors *");
header("X-Frame-Options: ALLOWALL");

$ip = '';
if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
    $ip = trim($ips[0]);
} else {
    $ip = $_SERVER['REMOTE_ADDR'] ?? '';
}

$city = '';
$countryCode = '';
if ($ip && $ip !== '127.0.0.1' && $ip !== '::1') {
    $ctx = stream_context_create(['http' => ['timeout' => 2]]);
    $geoStr = @file_get_contents("http://ip-api.com/json/{$ip}", false, $ctx);
    if ($geoStr) {
        $geo = json_decode($geoStr, true);
        if (isset($geo['status']) && $geo['status'] === 'success') {
            $city = $geo['city'] ?? '';
            $countryCode = $geo['countryCode'] ?? '';
        }
    }
}

$q = $_GET['q'] ?? '';
$tab = $_GET['tab'] ?? 'web';
$results = [];

if ($q !== '') {
    // Generate market code (setmkt) based on the user's country (defaulting to English for simplicity)
    $marketQuery = '';
    if ($countryCode) {
        $marketQuery = "&setmkt=en-" . strtoupper($countryCode);
    }

    $ctx = stream_context_create(['http' => ['header' => "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36\r\n"]]);
    
    if ($tab === 'web' || $tab === 'news') {
        $baseUrl = "https://www.bing.com/search";
        if ($tab === 'news') $baseUrl = "https://www.bing.com/news/search";
        
        $url = $baseUrl . "?format=rss&q=" . urlencode($q) . "&FORM=QBLH" . $marketQuery;
        $xmlStr = @file_get_contents($url, false, $ctx);
        if ($xmlStr) {
            $xml = @simplexml_load_string($xmlStr);
            if ($xml && isset($xml->channel->item)) {
                foreach ($xml->channel->item as $item) {
                    $results[] = [
                        'type' => 'rss',
                        'title' => (string)$item->title,
                        'link' => (string)$item->link,
                        'description' => (string)$item->description
                    ];
                }
            }
        }
    } elseif ($tab === 'images') {
        $url = "https://www.bing.com/images/search?q=" . urlencode($q) . $marketQuery;
        $htmlStr = @file_get_contents($url, false, $ctx);
        if ($htmlStr) {
            preg_match_all('/<a[^>]+class="[^"]*iusc[^"]*"[^>]*m="([^"]+)"/i', $htmlStr, $matches);
            foreach ($matches[1] as $m) {
                $json = html_entity_decode($m, ENT_QUOTES);
                $data = json_decode($json, true);
                if ($data && isset($data['murl']) && isset($data['turl'])) {
                    $results[] = [
                        'type' => 'image',
                        'title' => $data['desc'] ?? 'Image',
                        'link' => $data['murl'],
                        // Fix &amp; and similar entities in thumbnail url to prevent broken images
                        'thumb' => htmlspecialchars_decode($data['turl']), 
                        'source' => $data['purl'] ?? '#'
                    ];
                }
            }
        }
    } elseif ($tab === 'videos') {
        $url = "https://www.bing.com/videos/search?q=" . urlencode($q) . $marketQuery;
        $htmlStr = @file_get_contents($url, false, $ctx);
        if ($htmlStr) {
            preg_match_all('/vrhm="([^"]+)"/i', $htmlStr, $matches);
            foreach ($matches[1] as $m) {
                $json = html_entity_decode($m, ENT_QUOTES);
                $data = json_decode($json, true);
                if ($data && isset($data['murl']) && isset($data['vt'])) {
                    $results[] = [
                        'type' => 'video',
                        'title' => $data['vt'],
                        'link' => $data['pgurl'] ?? $data['murl'],
                        // Route through proxy to prevent broken images
                        'thumb' => htmlspecialchars_decode($data['smturl'] ?? ''),
                        'duration' => $data['du'] ?? ''
                    ];
                }
            }
        }
    }
}

$isSearch = ($q !== '');
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<meta name="referrer" content="no-referrer">
<title><?= $isSearch ? htmlspecialchars($q) . ' - BetGle Search' : 'BetGle' ?></title>
<script src="https://cdn.tailwindcss.com"></script>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<style>
body{background-color:#0f172a;color:#f8fafc;font-family:ui-sans-serif,system-ui,-apple-system,sans-serif}
.gradient-text{background:linear-gradient(to right,#3b82f6,#10b981);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
a { color: #60a5fa; text-decoration: none; }
a:hover { text-decoration: underline; }
</style>
</head>
<body class="min-h-screen flex flex-col">

<?php if (!$isSearch): ?>
    <!-- Home Page -->
    <header class="px-4 py-4 flex justify-end">
        <a href="/" class="text-sm text-slate-400 hover:text-white transition-colors bg-slate-800 py-1.5 px-3 rounded-full border border-slate-700">Back to BetterChat</a>
    </header>
    <main class="flex-1 flex flex-col items-center mt-32 px-4">
        <div class="mb-8">
            <h1 class="text-6xl sm:text-7xl font-extrabold gradient-text tracking-tighter text-center">BetGle</h1>
            <?php if ($city): ?>
            <p class="text-center text-slate-500 text-sm mt-2"><i class="fa-solid fa-location-dot mr-1"></i> Based in <?= htmlspecialchars($city) ?></p>
            <?php endif; ?>
        </div>
        
        <form action="" method="GET" class="w-full max-w-xl">
            <div class="relative flex items-center bg-slate-800 rounded-full border border-slate-700 hover:border-slate-500 focus-within:border-blue-500 focus-within:bg-slate-900 transition-all shadow-lg overflow-hidden h-12 sm:h-14">
                <i class="fa-solid fa-magnifying-glass text-slate-400 ml-4 sm:ml-5 text-sm sm:text-base"></i>
                <input type="text" name="q" placeholder="Search the web..." class="w-full bg-transparent border-none outline-none text-slate-200 px-4 h-full text-[16px]" autofocus required>
            </div>
            <div class="flex justify-center flex-wrap gap-3 mt-6">
                <button type="submit" class="bg-slate-800 hover:bg-slate-700 text-slate-300 text-sm font-medium py-2 px-5 rounded-md border border-slate-700 transition-colors">BetGle Search</button>
                <button type="button" class="bg-slate-800 hover:bg-slate-700 text-slate-300 text-sm font-medium py-2 px-5 rounded-md border border-slate-700 transition-colors" onclick="alert('I\'m feeling lucky!')">I'm Feeling Lucky</button>
            </div>
        </form>
    </main>
<?php else: ?>
    <!-- Search Results Page -->
    <header class="sticky top-0 z-50 bg-slate-900/90 backdrop-blur-md border-b border-slate-800 flex flex-col">
        <div class="px-4 py-3 sm:py-4 flex flex-col sm:flex-row items-start sm:items-center gap-4">
            <a href="index.php" class="text-3xl font-extrabold gradient-text tracking-tighter flex-shrink-0">BetGle</a>
            <form action="" method="GET" class="w-full max-w-2xl flex-1 relative flex items-center bg-slate-800 rounded-full border border-slate-700 focus-within:border-blue-500 focus-within:bg-slate-900 transition-all overflow-hidden h-10 sm:h-11">
                <input type="text" name="q" value="<?= htmlspecialchars($_GET['q']) ?>" class="w-full bg-transparent border-none outline-none text-slate-200 pl-4 sm:pl-5 pr-10 h-full text-base">
                <?php if ($tab !== 'web'): ?><input type="hidden" name="tab" value="<?= htmlspecialchars($tab) ?>"><?php endif; ?>
                <button type="submit" class="absolute right-0 top-0 bottom-0 px-4 text-blue-500 hover:text-blue-400">
                    <i class="fa-solid fa-magnifying-glass"></i>
                </button>
            </form>
            <div class="hidden sm:block ml-auto">
                <a href="/" class="w-9 h-9 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-slate-400 hover:text-white transition-colors" title="Back to BetterChat">
                    <i class="fa-solid fa-comments"></i>
                </a>
            </div>
        </div>
        
        <!-- Navigation Tabs -->
        <div class="flex items-center gap-6 px-4 sm:pl-[120px] overflow-x-auto no-scrollbar border-t border-slate-800/50 pt-2">
            <a href="?q=<?= urlencode($q) ?>&tab=web" class="pb-3 text-sm font-medium whitespace-nowrap transition-colors <?= $tab === 'web' ? 'text-blue-400 border-b-2 border-blue-400' : 'text-slate-400 hover:text-slate-200' ?>">
                <i class="fa-solid fa-magnifying-glass mr-1.5 opacity-75"></i>Web
            </a>
            <a href="?q=<?= urlencode($q) ?>&tab=images" class="pb-3 text-sm font-medium whitespace-nowrap transition-colors <?= $tab === 'images' ? 'text-blue-400 border-b-2 border-blue-400' : 'text-slate-400 hover:text-slate-200' ?>">
                <i class="fa-regular fa-image mr-1.5 opacity-75"></i>Images
            </a>
            <a href="?q=<?= urlencode($q) ?>&tab=videos" class="pb-3 text-sm font-medium whitespace-nowrap transition-colors <?= $tab === 'videos' ? 'text-blue-400 border-b-2 border-blue-400' : 'text-slate-400 hover:text-slate-200' ?>">
                <i class="fa-solid fa-play mr-1.5 opacity-75"></i>Videos
            </a>
            <a href="?q=<?= urlencode($q) ?>&tab=news" class="pb-3 text-sm font-medium whitespace-nowrap transition-colors <?= $tab === 'news' ? 'text-blue-400 border-b-2 border-blue-400' : 'text-slate-400 hover:text-slate-200' ?>">
                <i class="fa-regular fa-newspaper mr-1.5 opacity-75"></i>News
            </a>
            <a href="?q=<?= urlencode($q) ?>&tab=maps" class="pb-3 text-sm font-medium whitespace-nowrap transition-colors <?= $tab === 'maps' ? 'text-blue-400 border-b-2 border-blue-400' : 'text-slate-400 hover:text-slate-200' ?>">
                <i class="fa-solid fa-map-location-dot mr-1.5 opacity-75"></i>Maps
            </a>
        </div>
    </header>

    <main class="flex-1 w-full max-w-4xl max-w-4xl pl-4 pr-4 sm:pl-[120px] py-8">
        <div class="mb-6 flex items-center gap-2 text-sm text-slate-400">
            <?php if ($city): ?>
                <span class="flex items-center gap-1"><i class="fa-solid fa-location-dot"></i> Enhanced for <?= htmlspecialchars($city) ?></span>
            <?php endif; ?>
            <?php if ($tab === 'news'): ?>
                <span class="flex items-center gap-1 ml-4 border-l border-slate-700 pl-4"><i class="fa-regular fa-newspaper"></i> Top News articles</span>
            <?php endif; ?>
        </div>

        <div class="space-y-8">
            <?php if ($tab === 'maps'): ?>
                <div class="w-full h-[600px] rounded-xl overflow-hidden shadow-lg border border-slate-700 bg-slate-800">
                    <iframe width="100%" height="100%" frameborder="0" src="https://www.bing.com/maps/embed?h=600&w=1200&cp=<?= htmlspecialchars($q) ?>&lvl=11&typ=d&sty=r&src=SHELL&FORM=MBEDV8<?php if($city) echo '&where1='.urlencode($city); ?>"></iframe>
                </div>
            <?php elseif (empty($results) && $tab !== 'maps'): ?>
                <div class="text-slate-300">
                    <p>Your search - <b class="text-white"><?= htmlspecialchars($q) ?></b> - did not match any documents.</p>
                    <p class="mt-4 text-slate-400">Suggestions:</p>
                    <ul class="list-disc pl-5 mt-2 text-slate-400">
                        <li>Make sure all words are spelled correctly.</li>
                        <li>Try different keywords.</li>
                        <li>Try more general keywords.</li>
                    </ul>
                </div>
            <?php else: ?>
                <?php if ($tab === 'images'): ?>
                    <div class="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-4">
                        <?php foreach ($results as $res): ?>
                            <a href="<?= htmlspecialchars($res['link']) ?>" target="_blank" class="group block relative rounded-lg overflow-hidden border border-slate-700 bg-slate-800 hover:border-blue-500 transition-all aspect-square">
                                <img src="<?= htmlspecialchars($res['thumb']) ?>" alt="<?= htmlspecialchars($res['title']) ?>" class="w-full h-full object-cover group-hover:scale-105 transition-transform duration-300">
                                <div class="absolute inset-x-0 bottom-0 bg-slate-900/80 backdrop-blur-sm p-2 transform translate-y-full group-hover:translate-y-0 transition-transform">
                                    <p class="text-xs text-white truncate font-medium"><?= htmlspecialchars($res['title']) ?></p>
                                    <div class="flex items-center gap-1.5 mt-0.5">
                                        <?php $domain = parse_url($res['source'], PHP_URL_HOST) ?? ''; if($domain): ?>
                                            <img src="https://www.google.com/s2/favicons?domain=<?= urlencode($domain) ?>&sz=16" class="w-3 h-3 rounded-sm opacity-80" alt="">
                                            <p class="text-[10px] text-slate-400 truncate"><?= htmlspecialchars($domain) ?></p>
                                        <?php endif; ?>
                                    </div>
                                </div>
                            </a>
                        <?php endforeach; ?>
                    </div>
                <?php elseif ($tab === 'videos'): ?>
                    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
                        <?php foreach ($results as $res): ?>
                            <a href="<?= htmlspecialchars($res['link']) ?>" target="_blank" class="group block border border-transparent hover:border-slate-700 rounded-lg p-2 -m-2 transition-colors">
                                <div class="relative rounded-lg overflow-hidden border border-slate-700 bg-slate-800 aspect-video mb-3">
                                    <img src="<?= htmlspecialchars($res['thumb']) ?>" alt="<?= htmlspecialchars($res['title']) ?>" class="w-full h-full object-cover">
                                    <div class="absolute bottom-2 right-2 bg-black/80 backdrop-blur-md px-1.5 py-0.5 rounded text-[11px] text-white font-mono">
                                        <?= htmlspecialchars($res['duration']) ?>
                                    </div>
                                    <div class="absolute inset-0 bg-blue-500/20 opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center">
                                        <div class="w-12 h-12 rounded-full bg-blue-500 text-white flex items-center justify-center shadow-lg transform scale-75 group-hover:scale-100 transition-transform">
                                            <i class="fa-solid fa-play ml-1"></i>
                                        </div>
                                    </div>
                                </div>
                                <h3 class="text-[15px] font-medium text-slate-200 group-hover:text-blue-400 line-clamp-2 leading-snug">
                                    <?= htmlspecialchars($res['title']) ?>
                                </h3>
                                <div class="text-xs text-slate-400 mt-1.5 truncate flex items-center gap-2">
                                    <?php $domain = parse_url($res['link'], PHP_URL_HOST) ?? ''; if($domain): ?>
                                        <img src="https://www.google.com/s2/favicons?domain=<?= urlencode($domain) ?>&sz=16" class="w-3.5 h-3.5 rounded-sm" alt="">
                                        <?= htmlspecialchars($domain) ?>
                                    <?php endif; ?>
                                </div>
                            </a>
                        <?php endforeach; ?>
                    </div>
                <?php else: ?>
                    <?php foreach ($results as $res): ?>
                        <div class="search-result max-w-2xl">
                            <div class="text-sm text-slate-300 mb-1.5 truncate flex items-center gap-2">
                                <?php 
                                    $domain = parse_url($res['link'], PHP_URL_HOST); 
                                    if($domain): 
                                ?>
                                    <img src="https://www.google.com/s2/favicons?domain=<?= urlencode($domain) ?>&sz=16" class="w-4 h-4 rounded-sm" alt="">
                                    <?= htmlspecialchars($domain) ?>
                                <?php endif; ?>
                            </div>
                            <h3 class="text-xl font-medium mb-1 line-clamp-2">
                                <a href="<?= htmlspecialchars($res['link']) ?>" target="_blank" rel="noopener noreferrer" class="text-blue-400 hover:text-blue-300 hover:underline">
                                    <?= htmlspecialchars($res['title']) ?>
                                </a>
                            </h3>
                            <p class="text-slate-400 text-sm leading-snug line-clamp-3">
                                <?= htmlspecialchars($res['description']) ?>
                            </p>
                        </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            <?php endif; ?>
        </div>
    </main>
<?php endif; ?>

<footer class="bg-slate-900 border-t border-slate-800 py-4 px-6 text-sm text-slate-500 mt-auto">
    <div class="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4">
        <div>
            &copy; <?= date('Y') ?> BetGle (BetterHub Network)
        </div>
        <div class="flex items-center gap-4">
            <?php if ($city): ?>
                <span class="flex items-center gap-1"><i class="fa-solid fa-map-pin"></i> <?= htmlspecialchars($city) ?></span>
            <?php else: ?>
                <span class="flex items-center gap-1"><i class="fa-solid fa-earth-americas"></i> Unknown Location</span>
            <?php endif; ?>
            <span>·</span>
            <a href="#" class="hover:text-slate-300 transition-colors">Privacy</a>
            <span>·</span>
            <a href="#" class="hover:text-slate-300 transition-colors">Terms</a>
        </div>
    </div>
</footer>

</body>
</html>
