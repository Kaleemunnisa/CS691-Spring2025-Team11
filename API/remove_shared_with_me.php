<?php
include "sql_conn.php";
include "myfunctions.php";

$target_email = DecryptSessionsandCookies($_SESSION['passed_user_email']);

if (!$target_email) {
    echo json_encode(["success" => false, "error" => "Not authenticated"]);
    exit;
}

$share_uuid = $_POST['share_uuid'] ?? '';
if (!$share_uuid) {
    echo json_encode(["success" => false, "error" => "Missing share_uuid"]);
    exit;
}

$stmt = $conn->prepare("UPDATE shared_account SET delete_flag = 1 WHERE share_uuid = ? AND target_email = ?");
$stmt->bind_param("ss", $share_uuid, $target_email);
$success = $stmt->execute();

echo json_encode(["success" => $success]);
?>
