<?php
include 'myfunctions.php';
include 'sql_conn.php';

// Get encrypted email from session/cookie
$user_login_cookie = $_SESSION['passed_user_email'] ?? $_COOKIE['user_login'] ?? '';
$session_token = $_SESSION['user_session_token'] ?? $_COOKIE['user_session_token'] ?? '';

// If both new and old session variables exist, validate new token in DB
if ($user_login_cookie && $session_token) {
    // Decrypted session email
    $userEmailID = DecryptSessionsandCookies($user_login_cookie);
    // $user_login_cookie is already encrypted
    $stmt = $conn->prepare("SELECT * FROM sessions WHERE UserEmail=? AND SessionID=? AND IsActive=1 LIMIT 1");
    $stmt->bind_param("ss", $userEmailID, $session_token);
    $stmt->execute();
    $res = $stmt->get_result();

    if ($row = $res->fetch_assoc()) {
        // Session is valid!
        // Refresh cookies for sliding expiration
        setcookie("user_login", $user_login_cookie, time() + (86400 * 7), "/");
        setcookie("user_session_token", $session_token, time() + (86400 * 7), "/");
        // Update session variable
        $_SESSION['passed_user_email'] = $_COOKIE['user_login'];
        // Also update LastActive in DB
        $stmt2 = $conn->prepare("UPDATE sessions SET LastActive=NOW() WHERE UserEmail=? AND SessionID=?");
        $stmt2->bind_param("ss", $userEmailID, $session_token);
        $stmt2->execute();

        // User is authenticated and session is valid!
        echo json_encode(['success' => true, 'message' => 'logged_in']);
        exit;

    } else {
        // Session record not found or marked inactive — invalidate session and cookie
        setcookie("user_session_token", "", time() - (86400 * 7), "/");
        setcookie("user_login", "", time() - (86400 * 7), "/");
        unset($_SESSION['user_session_token']);
        unset($_SESSION['passed_user_email']);
        session_destroy();

        echo json_encode(['success' => false, 'message' => 'not_logged_in']);
    }
}
// If new session is missing, but old session/cookie exists (legacy fallback)
elseif ($user_login_cookie && !$session_token) {
    setcookie("user_login", $user_login_cookie, time() + (86400 * 7), "/");
    // Update session variable
    $_SESSION['passed_user_email'] = $_COOKIE['user_login'];
    // User is still "authenticated" (legacy_logged_in), but not in active sessions list
    echo json_encode(['success' => true, 'message' => 'logged_in']);
}
else {
    // No valid session — treat as not logged in
    echo json_encode(['success' => true, 'message' => 'not_logged_in']);
}
?>
