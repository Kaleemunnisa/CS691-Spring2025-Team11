<?php

if (isset($_SESSION['passed_user_email']) != NULL) {
    // session variable is available and not NULL

    $cookie_name = "user_login";
    $cookie_value = $_SESSION['passed_user_email'];
    setcookie($cookie_name, $cookie_value, time() + (86400 * 7), "/"); // 86400 = 1 day  

    echo json_encode(['success' => true, 'message' => 'logged_in']);
}
else {
    if (isset($_COOKIE['user_login']) != NULL) {
        // Cookie variable is available and not NULL

        $_SESSION['passed_user_email'] = $_COOKIE['user_login'];
    }
    else {
        echo json_encode(['success' => true, 'message' => 'not_logged_in']);
    }
}

?>