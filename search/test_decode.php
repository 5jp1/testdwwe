<?php
$m = '{&quot;sid&quot;:&quot;&quot;,&quot;turl&quot;:&quot;https://ts2.mm.bing.net/th?id=OIP.abc&amp;pid=15.1&quot;}';
$json = html_entity_decode($m, ENT_QUOTES);
$data = json_decode($json, true);
echo "JSON: $json\n";
echo "Type: " . gettype($data) . "\n";
if ($data) {
    echo "Turl: " . $data['turl'] . "\n";
    echo "Thumb: " . htmlspecialchars_decode($data['turl']) . "\n";
} else {
    echo "JSON decode error: " . json_last_error_msg() . "\n";
}
