<?php
$q = 'image test';
$marketQuery = '';
$ctx = stream_context_create(['http' => ['header' => "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36\r\n"]]);
$url = "https://www.bing.com/videos/search?q=" . urlencode($q) . $marketQuery;
$htmlStr = file_get_contents($url, false, $ctx);
preg_match_all('/vrhm="([^"]+)"/i', $htmlStr, $matches);
$results = [];
foreach ($matches[1] as $m) {
    $json = html_entity_decode($m, ENT_QUOTES);
    $data = json_decode($json, true);
    if ($data && isset($data['murl']) && isset($data['vt'])) {
        $results[] = $data['vt'];
    }
}
echo "Found " . count($matches[1]) . " videos\n";
echo "Decoded " . count($results) . " videos\n";
if (empty($results) && !empty($matches[1])) {
    echo "First JSON error: " . json_last_error_msg() . "\n";
    echo "Raw M: " . substr($matches[1][0], 0, 100) . "\n";
    echo "Decoded JSON: " . substr(html_entity_decode($matches[1][0], ENT_QUOTES), 0, 100) . "\n";
}
