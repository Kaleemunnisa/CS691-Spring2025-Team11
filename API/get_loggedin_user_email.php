<?php   
error_reporting(E_ALL ^ E_WARNING);
error_reporting(E_ERROR | E_PARSE);
?>

<?php
// Database connection 
include "sql_conn.php";
include 'myfunctions.php';

header('Content-Type: application/json');

if (isset($_SESSION['passed_user_email'])) {
    echo json_encode(['UserEmailId' => DecryptSessionsandCookies($_SESSION['passed_user_email'])]);
} else {
    echo json_encode(['UserEmailId' => null]);
}
?>
