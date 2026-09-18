<?php
session_set_cookie_params(["samesite" => "None", "secure" => true]);
session_start();
session_destroy();
header('Location: index.php');
exit;
