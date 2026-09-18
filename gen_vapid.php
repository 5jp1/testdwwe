<?php
$config = array(
    "digest_alg" => "sha256",
    "private_key_bits" => 2048,
    "private_key_type" => OPENSSL_KEYTYPE_EC,
    "curve_name" => "prime256v1"
);
$res = openssl_pkey_new($config);
openssl_pkey_export($res, $privkey);
$details = openssl_pkey_get_details($res);
$pubkey_pem = $details["key"];

// Extracting 65 bytes of uncompressed public key from PEM
// PEM is base64 encoded DER.
// A prime256v1 public key in DER is an ObjectIdentifier followed by a BIT STRING.
// The BIT STRING contains 0x04 followed by 32 bytes X and 32 bytes Y.
$pem_lines = explode("\n", trim($pubkey_pem));
array_shift($pem_lines); array_pop($pem_lines);
$der = base64_decode(implode("", $pem_lines));
$raw_public_key = substr($der, -65);

function base64url_encode($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

echo "PRIVATE:\n" . $privkey . "\n";
echo "PUBLIC VAPID:\n" . base64url_encode($raw_public_key) . "\n";
