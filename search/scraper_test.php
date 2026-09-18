<?php
// Test script for bing scraping
$q = "cats";
$url = "https://www.bing.com/images/search?q=" . urlencode($q);
$ctx = stream_context_create(['http' => ['header' => "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36\r\n"]]);
$html = @file_get_contents($url, false, $ctx);
preg_match_all('/<a class="iusc"[^>]*m="([^"]+)"/', $html, $matches);
$res = [];
foreach ($matches[1] as $m) {
    $json = html_entity_decode($m);
    $data = json_decode($json, true);
    if ($data && isset($data['murl']) && isset($data['turl'])) {
        $res[] = ['murl' => $data['murl'], 'turl' => $data['turl']];
    }
}
file_put_contents('test_img_output.txt', print_r($res, true));

// Test for videos
$url = "https://www.bing.com/videos/search?q=" . urlencode($q);
$html = @file_get_contents($url, false, $ctx);
// Videos usually have <div class="mc_vtvc_title">Title</div> or <div class="mc_vtvc_meta">...
preg_match_all('/<div class="mc_vtvc_title"[^>]*>(.*?)<\/div>/', $html, $titles);
file_put_contents('test_vid_output.txt', print_r($titles[1], true));
