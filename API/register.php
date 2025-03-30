<?php   
error_reporting(E_ALL ^ E_WARNING);
error_reporting(E_ERROR | E_PARSE);
?>

<?php
include 'myfunctions.php';
// Database connection 
include "sql_conn.php";

// Handle login logic
if (isset($_POST['firstname']) && isset($_POST['lastname']) && isset($_POST['useremail']) && isset($_POST['password'])) {
    // Get encrypted data from POST
    $encryptedPassword = $_POST['password'];

    // Decrypt the password
    $password = decryptRSA($encryptedPassword);

    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

    $currentdatetimestamp = date("Y-m-d H:i:s");

    $firstname = $_POST['firstname'];
    $lastname = $_POST['lastname'];
    $useremail = $_POST['useremail'];

    // check if user exists 
    $stmt = $conn->prepare("SELECT * FROM users WHERE EmailId = ?");
    $stmt->bind_param("s", $useremail);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        echo json_encode(['success' => true, 'message' => 'user already exists']);
    }
    else {
        // Insert user details into database table users
        $stmt = $conn->prepare("INSERT INTO users (FirstName, LastName, EmailId, CreatedOn) VALUES (?, ?, ?, ?)");
        $stmt->bind_param("ssss", $firstname, $lastname, $useremail, $currentdatetimestamp);

        // Insert user details into database table login
        $fpstmt = $conn->prepare("INSERT INTO login (EmailId, Password, CreatedOn) VALUES (?, ?, ?)");
        $fpstmt->bind_param("sss", $useremail, $hashedPassword, $currentdatetimestamp);

        // Insert into notifications table in database
        $nstmt = $conn->prepare("INSERT INTO notifications (UserEmailId) VALUES (?)");
        $nstmt->bind_param("s", $useremail);

        // Generate a new encryption key for signed up user
        $GeneratedNewEncryptionKey = generateEncryptionkey();

        // Insert into encryption table
        $encstmt = $conn->prepare("INSERT INTO encryption (EncryptionKey, UserEmailId) VALUES (?, ?)");
        $encstmt->bind_param("ss", $GeneratedNewEncryptionKey, $useremail);

        if ($stmt->execute() === true && $fpstmt->execute() === true && $nstmt->execute() === true && $encstmt->execute() === true) {
            //send mail
            $emailStatus = sendSignupEmail($useremail, $lastname, $firstname);

            echo json_encode(['success' => true, 'message' => 'user registration sucessful']);
        }
        else {
            echo json_encode(['success' => false, 'message' => 'user registration failed']);
        }

        // Close statement and database connection
        $stmt->close();
        $fpstmt->close();
        $nstmt->close();
        $encstmt->close();
        $conn->close();
    }
}
else {
    die();
}
?>