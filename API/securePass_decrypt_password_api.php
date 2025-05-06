<?php
header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(["success" => false, "error" => "Invalid request"]);
    exit;
}

$data = json_decode(file_get_contents("php://input"), true);
$enc_password = $data['encrypted'] ?? '';
$enc_key = $data['key'] ?? '';

if (!$enc_password || !$enc_key) {
    echo json_encode(["success" => false, "error" => "Missing fields"]);
    exit;
}

// --- decryptString logic from your existing helper ---
function decryptString($encryptedString, $encryptionKey) {
    $encryptedData = base64_decode($encryptedString);
    $iv = substr($encryptedData, 0, 16);
    $encryptedString = substr($encryptedData, 16);
    $decryptedString = openssl_decrypt($encryptedString, 'aes-256-cbc', $encryptionKey, 0, $iv);
    return $decryptedString;
}

$decrypted = decryptString($enc_password, $enc_key);

if ($decrypted === false) {
    echo json_encode(["success" => false, "error" => "Decryption failed"]);
} else {
    echo json_encode(["success" => true, "decrypted" => $decrypted]);
}
