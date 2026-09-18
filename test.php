<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
$content = file_get_contents('chat.php');
if(eval("?>".$content) === false) {
    echo "Evaluation failed";
}
