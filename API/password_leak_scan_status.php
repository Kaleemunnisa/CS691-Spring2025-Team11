<?php
include "sql_conn.php";
include "myfunctions.php";

header('Content-Type: application/json');

$user_email = DecryptSessionsandCookies($_SESSION['passed_user_email']) ?? null;

if (!$user_email) {
    echo json_encode(['success' => false, 'message' => 'Not logged in']);
    exit;
}

// Get all vault entries for this user
$stmt = $conn->prepare("SELECT UniqueId, AppName, UserName FROM vault WHERE UserEmailId=? AND DeleteFlag=0 AND ActiveFlag=1");
$stmt->bind_param("s", $user_email);
$stmt->execute();
$stmt->bind_result($unique_id, $appname, $username);

$vaults = [];
while ($stmt->fetch()) {
    $vaults[] = ['UniqueId'=>$unique_id, 'AppName'=>$appname, 'UserName'=>$username];
}
$stmt->close();

if (!$vaults) {
    echo json_encode(['success'=>false, 'message'=>'No vault entries']);
    exit;
}

// Now fetch scan results
$pending = false; $results = [];
foreach ($vaults as $v) {
    $sql = "SELECT leak_found, leak_count, last_checked FROM password_leak_scan WHERE vault_unique_id=?";
    $scan_stmt = $conn->prepare($sql);
    $scan_stmt->bind_param("s", $v['UniqueId']);
    $scan_stmt->execute();
    $scan_stmt->bind_result($found, $count, $last_checked);
    if ($scan_stmt->fetch()) {
        $results[] = [
            'UniqueId'=>$v['UniqueId'],
            'AppName'=>$v['AppName'],
            'UserName'=>$v['UserName'],
            'status'=> ($found === 1) ? "LEAK_FOUND" : "NO_LEAK",
            'leak_count'=>$count,
            'last_checked'=>$last_checked
        ];
    } else {
        $pending = true;
        $results[] = [
            'UniqueId'=>$v['UniqueId'],
            'AppName'=>$v['AppName'],
            'UserName'=>$v['UserName'],
            'status'=>'PENDING',
            'leak_count'=>null,
            'last_checked'=>null
        ];
    }
    $scan_stmt->close();
}

echo json_encode([
    'success'=>true,
    'pending'=>$pending,
    'results'=>$results
]);
?>
