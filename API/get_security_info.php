<?php   
error_reporting(E_ALL ^ E_WARNING);
error_reporting(E_ERROR | E_PARSE);
?>

<?php
include "sql_conn.php";
include 'myfunctions.php';

if (isset($_SESSION['passed_user_email'])) {

$userEmail = DecryptSessionsandCookies($_SESSION['passed_user_email']);

// Get last master password changed
$res = $conn->query("SELECT password_modified_on FROM login WHERE EmailId = '$userEmail' LIMIT 1");
$row = $res->fetch_assoc();
$lastChanged = $row ? $row['password_modified_on'] : "";

// Get 2FA status
$res = $conn->query("SELECT TwoFactorAuthentication FROM login WHERE EmailId = '$userEmail' LIMIT 1");
$row = $res->fetch_assoc();
$twoFA = ($row && intval($row['TwoFactorAuthentication']) === 1) ? "enabled" : "disabled";

// Get notifications preferences 
$notificationPrefs = [];
$res = $conn->query("SELECT AccountInfoUpdate, AccountLogin, NewAccountAdded, SharedWithOthers, SharedWithYou FROM notifications WHERE UserEmailId = '$userEmail' LIMIT 1");
if ($row = $res->fetch_assoc()) {
    $notificationPrefs = $row;
}

// Get trusted devices
$trustedDevices = [];
$res = $conn->query("SELECT ID, DeviceName, IPAddress, TrustedAt, LastUsedAt, DeviceToken FROM trusted_devices WHERE UserEmail = '$userEmail' AND IsActive=1");
while ($row = $res->fetch_assoc()) {
    $trustedDevices[] = [
        'id' => $row['ID'],
        'device' => $row['DeviceName'],
        'ip' => $row['IPAddress'],
        'trusted_at' => $row['TrustedAt'],
        'last_used_at' => $row['LastUsedAt'],
        'device_token' => $row['DeviceToken']
    ];
}

// Get active sessions
$sessions = [];
$res = $conn->query("SELECT DeviceName, IPAddress, LastActive, SessionID FROM sessions WHERE UserEmail = '$userEmail' AND IsActive = 1");
while ($row = $res->fetch_assoc()) {
    $sessions[] = [
        'device' => $row['DeviceName'],
        'ip' => $row['IPAddress'],
        'last_active' => $row['LastActive'],
        'session_token' => $row['SessionID']
    ];
}

// Get login activity
$loginActivity = [];
$res = $conn->query("SELECT IPAddress, LoginTimestamp FROM login_activity WHERE UserEmail = '$userEmail' ORDER BY LoginTimestamp DESC LIMIT 10");
while ($row = $res->fetch_assoc()) {
    $loginActivity[] = [
        'ip' => $row['IPAddress'],
        'timestamp' => $row['LoginTimestamp']
    ];
}

// Output JSON
echo json_encode([
    "last_master_password_changed" => $lastChanged,
    "two_factor_status" => $twoFA,
    "notification_prefs" => $notificationPrefs,
    "trusted_devices" => $trustedDevices,
    "sessions" => $sessions,
    "login_activity" => $loginActivity
]);

}
else {
    header("location:../login.html");
}
?>
