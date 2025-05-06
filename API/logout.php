<?php
include 'myfunctions.php';
include 'sql_conn.php';

// Get encrypted email and session token from session/cookie
$user_login_cookie = $_SESSION['passed_user_email'] ?? $_COOKIE['user_login'] ?? '';
$session_token = $_SESSION['user_session_token'] ?? $_COOKIE['user_session_token'] ?? '';

// Decrypted session email
$userEmailID = DecryptSessionsandCookies($user_login_cookie);

// Mark the session as inactive in the database
if ($user_login_cookie && $session_token) {
    $stmt = $conn->prepare("UPDATE sessions SET IsActive=0 WHERE UserEmail=? AND SessionID=?");
    $stmt->bind_param("ss", $userEmailID, $session_token);
    $stmt->execute();
}

// Destroy all session data
session_unset();
session_destroy();

// Remove both cookies
setcookie('user_login', '', time() - (86400 * 7), '/');
setcookie('user_session_token', '', time() - (86400 * 7), '/');
unset($_COOKIE['user_login']);
unset($_COOKIE['user_session_token']);

echo "<script> sessionStorage.removeItem('trustDevicePromptShown'); </script>";

// Redirect to login page
header("Location: ../index.html");
exit();
?>
