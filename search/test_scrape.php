<?php
$q = 'image test';
$marketQuery = '';
$ctx = stream_context_create(['http' => ['header' => "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36\r\n"]]);
$url = "https://www.bing.com/images/search?q=" . urlencode($q) . $marketQuery;
$htmlStr = @file_get_contents($url, false, $ctx);
if ($htmlStr) {
    preg_match_all('/<a[^>]+class="[^"]*iusc[^"]*"[^>]*m="([^"]+)"/i', $htmlStr, $matches);
    echo "Found images: " . count($matches[1]) . "\n";
    foreach ($matches[1] as $m) {
        $json = html_entity_decode($m, ENT_QUOTES);
        $data = json_decode($json, true);
        echo "Turl: " . ($data['turl'] ?? '') . "\n";
        break;
    }
} else {
    echo "Failed to fetch\n";
}
