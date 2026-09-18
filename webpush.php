<?php
class WebPush {
    private $pdo;
    private $vapid_private;
    private $vapid_public;

    public function __construct($pdo) {
        $this->pdo = $pdo;
        $this->loadOrGenerateKeys();
    }

    private function loadOrGenerateKeys() {
        $stmt = $this->pdo->query("SELECT public_key, private_key FROM vapid_keys WHERE id=1");
        $keys = $stmt->fetch();

        if (empty($keys['private_key']) || empty($keys['public_key'])) {
            $res = openssl_pkey_new([
                "digest_alg" => "sha256",
                "private_key_bits" => 2048,
                "private_key_type" => OPENSSL_KEYTYPE_EC,
                "curve_name" => "prime256v1"
            ]);
            openssl_pkey_export($res, $privkey);
            $details = openssl_pkey_get_details($res);
            $pubkey_pem = $details["key"];

            $pem_lines = explode("\n", trim($pubkey_pem));
            array_shift($pem_lines); array_pop($pem_lines);
            $der = base64_decode(implode("", $pem_lines));
            $raw_public_key = substr($der, -65);

            $this->vapid_private = $privkey;
            $this->vapid_public = self::base64url_encode($raw_public_key);

            $this->pdo->prepare("INSERT INTO vapid_keys(id, public_key, private_key) VALUES (1, ?, ?) ON DUPLICATE KEY UPDATE public_key=VALUES(public_key), private_key=VALUES(private_key)")->execute([$this->vapid_public, $this->vapid_private]);
        } else {
            $this->vapid_private = $keys['private_key'];
            $this->vapid_public = $keys['public_key'];
        }
    }

    public static function base64url_encode($data) {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    public function getPublicKey() {
        return $this->vapid_public;
    }

    public function sendPush($endpoint, $auth, $p256dh, $payload = null) {
        // Without full AES128GCM implementation in raw PHP, we cannot send a payload securely
        // according to Web Push specs (requires ecdh, hkdf, salt, etc.)
        // But RFC8030 permits push *without* payload. The SW receives it and fetches from server!
        
        $urlParts = parse_url($endpoint);
        $audience = $urlParts['scheme'] . '://' . $urlParts['host'];

        $header = ['typ' => 'JWT', 'alg' => 'ES256'];
        $claims = [
            'aud' => $audience,
            'exp' => time() + 43200, // 12h
            'sub' => 'mailto:admin@localhost'
        ];

        $encHeader = self::base64url_encode(json_encode($header));
        $encClaims = self::base64url_encode(json_encode($claims));
        $unsignedToken = $encHeader . '.' . $encClaims;

        openssl_sign($unsignedToken, $signature, $this->vapid_private, 'sha256');
        
        // ECDSA signature from openssl needs to be r||s (64 bytes). PHP returns it in ASN.1 DER format.
        $signatureRs = self::der_to_rs($signature);
        $jwt = $unsignedToken . '.' . self::base64url_encode($signatureRs);

        $headers = [
            "Authorization: vapid t=$jwt, k=" . $this->vapid_public,
            "TTL: 86400",
            "Content-Length: 0"
        ];

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $endpoint);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        $res = curl_exec($ch);
        $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        return $status;
    }

    private static function der_to_rs($der) {
        // Parse ASN.1 structure to extract R and S, and pad to 32 bytes each.
        $hex = bin2hex($der);
        if (substr($hex, 0, 2) !== '30') return str_repeat("\x00", 64);
        
        $len = hexdec(substr($hex, 2, 2));
        if ($len > 127 || $len * 2 + 4 !== strlen($hex)) return str_repeat("\x00", 64);

        if (substr($hex, 4, 2) !== '02') return str_repeat("\x00", 64);
        $rlen = hexdec(substr($hex, 6, 2));
        $r = substr($hex, 8, $rlen * 2);

        $spos = 8 + $rlen * 2;
        if (substr($hex, $spos, 2) !== '02') return str_repeat("\x00", 64);
        $slen = hexdec(substr($hex, $spos + 2, 2));
        $s = substr($hex, $spos + 4, $slen * 2);

        // R and S might have a leading zero byte to prevent negative interpretation (since ASN.1 uses signed integers)
        if (strlen($r) > 64 && substr($r, 0, 2) === '00') $r = substr($r, 2);
        if (strlen($s) > 64 && substr($s, 0, 2) === '00') $s = substr($s, 2);

        $r_bin = str_pad(hex2bin($r), 32, "\x00", STR_PAD_LEFT);
        $s_bin = str_pad(hex2bin($s), 32, "\x00", STR_PAD_LEFT);

        return $r_bin . $s_bin;
    }
}
