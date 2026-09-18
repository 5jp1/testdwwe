<?php
$q = 'cats';
$ctx = stream_context_create(['http' => ['header' => "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"]]);
$htmlStr = file_get_contents("https://www.bing.com/images/search?q=cats", false, $ctx);
preg_match_all('/<a[^>]+class="[^"]*iusc[^"]*"[^>]*m="([^"]+)"/i', $htmlStr, $matches);
foreach ($matches[1] as $m) {
    echo $m . "\n\n";
    $json = html_entity_decode($m, ENT_QUOTES);
    echo $json . "\n\n";
    $data = json_decode($json, true);
    print_r($data);
    break;
}
