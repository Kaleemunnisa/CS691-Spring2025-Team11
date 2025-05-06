<?php
include "sql_conn.php";
include "myfunctions.php";

header('Content-Type: application/json');

$user_email = DecryptSessionsandCookies($_SESSION['passed_user_email']) ?? null;

if (!$user_email) {
    echo json_encode(['success' => false, 'message' => 'Not logged in']);
    exit;
}

// Start scan in background (use shell exec "&" to run asynchronously)
$cmd = "python D:\\Xampp\\HTTPS\\Bots\\Services\\SERVICE_password_leak_scan.py --user " . escapeshellarg($user_email) . " > NUL 2>&1 &";
pclose(popen("start /B " . $cmd, "r")); // For Windows (non-blocking)
echo json_encode(['success' => true, 'message' => 'Scan started']);
?>
