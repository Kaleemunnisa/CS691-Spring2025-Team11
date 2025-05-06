<?php
include "sql_conn.php";
include 'myfunctions.php';
header('Content-Type: application/json');

// Check if user is logged in
if (isset($_SESSION['passed_user_email'])) {

    $myEmail = DecryptSessionsandCookies($_SESSION['passed_user_email']);
    $email = $_POST['email'] ?? '';

    $response = ['exists' => false];

    if ($email !== '') {
        $stmt = $conn->prepare("SELECT 1 FROM users WHERE EmailId = ? AND EmailId <> ? LIMIT 1");
        $stmt->bind_param("ss", $email, $myEmail);
        $stmt->execute();
        $stmt->store_result();

        $response['exists'] = $stmt->num_rows > 0;
    }

    echo json_encode($response);
}
else {
    echo json_encode(['success' => false, 'message' => 'You need to login first to access data.']);
    exit;
}