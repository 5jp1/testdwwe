<?php
$q = 'cats';
$ctx = stream_context_create(['http' => ['header' => "User-Agent: Mozilla/5.0\r\n"]]);
$htmlStr = @file_get_contents("https://www.bing.com/images/search?q=cats", false, $ctx);
file_put_contents('bing_dump.html', $htmlStr);
echo "Dumped " . strlen($htmlStr) . " bytes\n";
