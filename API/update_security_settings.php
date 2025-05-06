<?php   
error_reporting(E_ALL ^ E_WARNING);
error_reporting(E_ERROR | E_PARSE);
?>

<?php
include "sql_conn.php";
include 'myfunctions.php';

// Helper for responses
function sendResponse($success, $message) {
    echo json_encode(['success' => $success, 'message' => $message]);
    exit();
}

header("Content-Type: application/json");

// Get user context
$userEmailEncrypted = $_SESSION['passed_user_email'] ?? $_COOKIE['user_login'] ?? '';
$sessionToken = $_SESSION['user_session_token'] ?? $_COOKIE['user_session_token'] ?? '';
$action = $_POST['action'] ?? '';

// Decrypted Email
$userEmail = DecryptSessionsandCookies($_SESSION['passed_user_email']);

// SECURITY: Make sure user is authenticated
if (!$userEmailEncrypted) {
    sendResponse(false, "Not authenticated");
}

// Handle actions
switch ($action) {
    case "change_password":
        $currentPassword = $_POST['current_password'] ?? '';
        $newPassword = $_POST['new_password'] ?? '';
        // Fetch current password hash
        $res = $conn->query("SELECT Password FROM login WHERE EmailId='$userEmail' LIMIT 1");
        if ($row = $res->fetch_assoc()) {
            if (password_verify($currentPassword, $row['Password'])) {
                // Update new password
                $newHash = password_hash($newPassword, PASSWORD_DEFAULT);
                $conn->query("UPDATE login SET Password='$newHash', password_modified_on=NOW() WHERE EmailId='$userEmail'");
                $response = ["success" => true, "message" => "Password changed successfully"];
            } else {
                $response = ["success" => false, "message" => "Current password is incorrect"];
            }
        } else {
            $response = ["success" => false, "message" => "User not found"];
        }
        break;

    case "enable_2fa":
        $conn->query("UPDATE login SET TwoFactorAuthentication=1 WHERE EmailId='$userEmail'");
        $response = ["success" => true, "message" => "2FA enabled"];
        break;

    case "disable_2fa":
        $conn->query("UPDATE login SET TwoFactorAuthentication=0 WHERE EmailId='$userEmail'");
        $response = ["success" => true, "message" => "2FA disabled"];
        break;

    case "update_notification_prefs":
        $AccountInfoUpdate = intval($_POST['AccountInfoUpdate'] ?? 0);
        $AccountLogin = intval($_POST['AccountLogin'] ?? 0);
        $NewAccountAdded = intval($_POST['NewAccountAdded'] ?? 0);
        $SharedWithOthers = intval($_POST['SharedWithOthers'] ?? 0);
        $SharedWithYou = intval($_POST['SharedWithYou'] ?? 0);

        // Insert or update (if exists)
        $stmt = $conn->prepare("INSERT INTO notifications (UserEmailId, AccountInfoUpdate, AccountLogin, NewAccountAdded, SharedWithOthers, SharedWithYou) VALUES (?, ?, ?, ?, ?, ?) 
            ON DUPLICATE KEY UPDATE AccountInfoUpdate=VALUES(AccountInfoUpdate), AccountLogin=VALUES(AccountLogin), NewAccountAdded=VALUES(NewAccountAdded), SharedWithOthers=VALUES(SharedWithOthers), SharedWithYou=VALUES(SharedWithYou)");
        $stmt->bind_param("siiiii", $userEmail, $AccountInfoUpdate, $AccountLogin, $NewAccountAdded, $SharedWithOthers, $SharedWithYou);

        if ($stmt->execute()) {
            sendResponse(true, "Preferences updated");
        } else {
            sendResponse(false, "Failed to update preferences");
        }
        break;

    case "add_trusted_device":
        // Only add if no trusted_device cookie already set
        if (!isset($_COOKIE['trusted_device'])) {
            $deviceToken = bin2hex(random_bytes(32));
            $deviceName = $_POST['device_name'] ?? $_SERVER['HTTP_USER_AGENT'];
            $ip = $_POST['public_ip'];
            // Insert in DB
            $stmt = $conn->prepare("INSERT INTO trusted_devices (UserEmail, DeviceToken, DeviceName, IPAddress) VALUES (?, ?, ?, ?)");
            $stmt->bind_param("ssss", $userEmail, $deviceToken, $deviceName, $ip);
            if ($stmt->execute()) {
                setcookie("trusted_device", $deviceToken, time() + (86400 * 90), "/", "", true, true);
                sendResponse(true, "Device trusted");
            } else {
                sendResponse(false, "Failed to save device");
            }
        } else {
            sendResponse(false, "Device already trusted");
        }
        break;

    case "logout_session":
        // Log out a specific session by token (from Security page)
        $targetSessionToken = $_POST['session_token'] ?? '';
        if ($targetSessionToken) {
            $stmt = $conn->prepare("UPDATE sessions SET IsActive=0 WHERE UserEmail=? AND SessionID=?");
            $stmt->bind_param("ss", $userEmail, $targetSessionToken);
            if ($stmt->execute()) {
                sendResponse(true, "Session logged out successfully");
            } else {
                sendResponse(false, "Failed to update session");
            }
        } else {
            sendResponse(false, "Session token required");
        }
        break;

    default:
        sendResponse(false, "Invalid action");
}
?>
