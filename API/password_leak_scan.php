<?php
header("Content-Type: application/json");
function parse_leak_output($output) {
    $lines = explode("\n", trim($output));
    $results = [];
    foreach ($lines as $line) {
        if (strpos($line, 'LEAK_FOUND') !== false || strpos($line, 'NO_LEAK') !== false) {
            $parts = explode(':', $line);
            $result = [
                "vault_unique_id" => $parts[0],
                "AppName" => $parts[1],
                "UserName" => $parts[2],
                "status" => (strpos($line, 'LEAK_FOUND') !== false) ? "LEAK_FOUND" : "NO_LEAK",
                "leak_count" => (strpos($line, 'LEAK_FOUND') !== false) ? intval($parts[4]) : 0
            ];
            $results[] = $result;
        }
    }
    return $results;
}

if (isset($_POST['vault_unique_id'])) {
    $unique_id = escapeshellarg($_POST['vault_unique_id']);
    $output = shell_exec("python D:\\Xampp\\HTTPS\\Bots\\Services\\SERVICE_password_leak_scan.py --one $unique_id 2>&1");
    $results = parse_leak_output($output);
    echo json_encode(["results" => $results]);
    exit;
} else if (isset($_POST['UserEmailId'])) {
    $user_email_id = escapeshellarg($_POST['UserEmailId']);
    $output = shell_exec("python D:\\Xampp\\HTTPS\\Bots\\Services\\SERVICE_password_leak_scan.py --user $user_email_id 2>&1");
    $results = parse_leak_output($output);
    echo json_encode(["results" => $results]);
    exit;
} else {
    echo json_encode(["status" => "error", "message" => "Missing parameter"]);
    exit;
}
?>