<?php   
error_reporting(E_ALL ^ E_WARNING);
error_reporting(E_ERROR | E_PARSE);
?>

<?php
include 'myfunctions.php';
// Database connection 
include "sql_conn.php";

// Handle Send Reset Password request logic
if (isset($_POST['useremail']) != NULL) {
    $userEmail = $_POST['useremail'];

    // Check if the email exists in the database
    $stmt = $conn->prepare("SELECT * FROM login WHERE EmailId = ?");
    $stmt->bind_param("s", $userEmail);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows === 1) {
        // Generate a unique token for password reset
        $resetToken = bin2hex(random_bytes(32));

        // Store the reset token and its expiration time in the database
        $resetExpiration = date('Y-m-d H:i:s', strtotime('+1 hour'));
        $updateStmt = $conn->prepare("UPDATE login SET ResetToken = ?, ResetTokenExpiration = ? WHERE EmailId = ?");
        $updateStmt->bind_param("sss", $resetToken, $resetExpiration, $userEmail);

        if ($updateStmt->execute()) {
            // Send a password reset email with a link containing the resetToken
            $resetPasswordUrl = $DomainURL . "/forgotpassword.html?token=" . $resetToken . '';

            //send mail
            $sentRequestResult = sendForgotPasswordEmail($userEmail, $resetPasswordUrl);

            if ($sentRequestResult == 'Success'){
                // log this event into db as mail sent success 
            }
            else {
                // log this event into db as mail sent failed 
            }
            echo json_encode(['success' => true, 'message' => 'reset password request success']);
        } else {
            echo json_encode(['success' => false, 'message' => 'Failed to generate a password reset token. Please try again later']);
        }
    } else {
        echo json_encode(['success' => false, 'message' => 'Email not found in our system']);
    }
}
// Handle Validate reset token logic
elseif ((isset($_POST['resetToken']) != NULL) && isset($_POST['checkResetTokenStatus']) == true) {
    $resetToken = $_POST['resetToken'];

    // Check if the reset token exists in the database
    $stmt = $conn->prepare("SELECT * FROM login WHERE ResetToken = ? AND ResetTokenExpiration  > NOW()");
    $stmt->bind_param("s", $resetToken);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows === 1) {
        echo json_encode(['success' => true, 'message' => 'Reset token is valid']);
    } else {
        echo json_encode(['success' => false, 'message' => 'Reset token expired']);
    }
}
// Handle Reset Password logic
elseif ((isset($_POST['Password']) != NULL) && isset($_POST['resetToken']) != NULL) {
    $encryptedPassword = $_POST['Password'];
    $resetToken = $_POST['resetToken'];
    $password = decryptRSA($encryptedPassword);

    // Hash the new password
    $HashedPassword = password_hash($password, PASSWORD_DEFAULT);

    // Check if the reset token is not expired in the database
    $stmt = $conn->prepare("SELECT * FROM login WHERE ResetToken = ? AND ResetTokenExpiration  > NOW()");
    $stmt->bind_param("s", $resetToken);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows === 1) {

        $updateStmt = $conn->prepare("UPDATE login SET Password = ?, LockoutCount = NULL, ResetToken = NULL, ResetTokenExpiration = NULL WHERE ResetToken = ?");
        $updateStmt->bind_param("ss", $HashedPassword, $resetToken);

        if ($updateStmt->execute()) {
            echo json_encode(['success' => true, 'message' => 'Reset Password Success']);
        }
        else {
            echo json_encode(['success' => false, 'message' => 'Reset Password Failed']);
        }

    } else {
        echo json_encode(['success' => false, 'message' => 'Reset token expired']);
    }

}
else {
    die();
}
?>