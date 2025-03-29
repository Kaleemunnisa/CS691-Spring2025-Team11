<?php   
error_reporting(E_ALL ^ E_WARNING);
error_reporting(E_ERROR | E_PARSE);
?>

<?php
include 'myfunctions.php';
// Database connection 
include "sql_conn.php";

// Handle login logic
if (isset($_POST['username']) && isset($_POST['password'])) {

    // Get encrypted data from POST
    $encryptedEmail = $_POST['username'];
    $encryptedPassword = $_POST['password'];

    // Decrypt the email and password
    $email = decryptRSA($encryptedEmail);
    $password = decryptRSA($encryptedPassword);

    // Prepare SQL statement to fetch user details based on email
    $stmt = $conn->prepare("SELECT * FROM login WHERE EmailId = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows === 1) {
        // User found, verify password
        $user = $result->fetch_assoc();

        if ($user['ActiveFlag'] == 1){
            if($user['DeleteFlag'] == 0){

                if (password_verify($password, $user['Password'])) {

                    // Send notification(s) via mail if email notifications are enabled.
                    $CheckUserEmailId = $email;

                    $checknotificationssql = "SELECT * FROM notifications WHERE UserEmailId = '$CheckUserEmailId' ";
                    $checknotificationsresult = $conn->query($checknotificationssql);
                    if ($checknotificationsresult->num_rows > 0){
                        while ($checknotificationsrow = $checknotificationsresult->fetch_assoc()){
                            $AccountLoginFlag = $checknotificationsrow['AccountLogin'];
                        }
                    }

                    $TwoFactorAuthenticationFlag = $user['TwoFactorAuthentication'];

                    if ($user['LockoutFlag'] == 1 && $user['LockoutCount'] > 5){

                        echo json_encode(['success' => true, 'message' => 'Your account has been Locked out, Please reset your password using forgot password.']);

                    }else{
                        if ($user['LockoutFlag'] == 1){
                            $stmtUpdateLockOutFlag = $conn->prepare("UPDATE login SET LockoutCount = 0 WHERE EmailId = ?");
                            $stmtUpdateLockOutFlag->bind_param("s", $CheckUserEmailId);
                            $stmtUpdateLockOutFlag->execute();
                        } else{}
                    
                        if ($TwoFactorAuthenticationFlag == '1'){
                            // Generate Otp
                            $OtpCode = mt_rand(10000000, 99999999);

                            // Insert OtpCode into Database 

                            $otpupdateStmt = $conn->prepare("UPDATE login SET TwoFactorAuthenticationCode = ? WHERE EmailId = ?");
                            $otpupdateStmt->bind_param("ss", $OtpCode, $CheckUserEmailId);
                            $otpupdateStmt->execute();

                            //Send 2FA Otp mail

                            $sentRequestResult = sendLoginOTPEmail($CheckUserEmailId, $OtpCode);

                            if ($sentRequestResult == 'Success'){
                                
                                $_SESSION['twofa_check_user_email'] = $CheckUserEmailId;
                                echo json_encode(['success' => true, 'message' => 'twofactorvalidation=true', 'twofauseremail' => $CheckUserEmailId ]);
                                exit();

                            }

                        } else{
                            if ($AccountLoginFlag == 1){

                                // send mail if notifications is enabled
                                $sqlAccountLogin = "SELECT * FROM message_templates WHERE TemplateName = 'login' and DeleteFlag = 0 ";
                                $resultAccountLogin = $conn->query($sqlAccountLogin);
                            
                                if ($resultAccountLogin->num_rows > 0) {
                                    while($rowAccountLogin = $resultAccountLogin->fetch_assoc()){
                                        $emailSubject = $rowAccountLogin['Subject'];
                                        $strmessagebody1 = $rowAccountLogin['Body1'];
                                        $strmessagebody2 = $rowAccountLogin['Body2'];
                                    }
                                }

                                $emailMessage = $strmessagebody1 .''. $strmessagebody2;
                                $ToUserEmail = $CheckUserEmailId;
                            
                                // send mail

                                $sentRequestResult = sendEmail($ToUserEmail, $emailSubject, $emailMessage);

                                if ($sentRequestResult == 'Success'){
                                    $_SESSION['passed_user_email'] = EncryptSessionsandCookies($email);

                                    $cookie_name = "user_login";
                                    $cookie_value = $_SESSION['passed_user_email'];
                                    setcookie($cookie_name, $cookie_value, time() + (86400 * 7), "/"); // 86400 = 1 day  
                                    echo json_encode(['success' => true, 'message' => 'Login Success']);
                                    exit();
                                }
                            } else{            
                                // IF notifications for login alert is disabled
                                $_SESSION['passed_user_email'] = EncryptSessionsandCookies($email);

                                $cookie_name = "user_login";
                                $cookie_value = $_SESSION['passed_user_email'];
                                setcookie($cookie_name, $cookie_value, time() + (86400 * 7), "/"); // 86400 = 1 day  
                                echo json_encode(['success' => true, 'message' => 'Login Success']);
                                exit();
                                }
                            // IF 2FA for login is disabled
                            session_start();
                            $_SESSION['passed_user_email'] = EncryptSessionsandCookies($email);

                            $cookie_name = "user_login";
                            $cookie_value = $_SESSION['passed_user_email'];
                            setcookie($cookie_name, $cookie_value, time() + (86400 * 7), "/"); // 86400 = 1 day  
                            echo json_encode(['success' => true, 'message' => 'Login Success']);
                            exit();
                            }
                        }
                    } 
                    else {
                        // Invalid password

                        $NewLockOutCount = $user['LockoutCount'] + 1;

                        $LockoutCountStmt = $conn->prepare("UPDATE login SET LockoutCount = ? WHERE EmailId = ?");
                        $LockoutCountStmt->bind_param("ss", $NewLockOutCount, $email);
                        $LockoutCountStmt->execute();
                        echo json_encode(['success' => true, 'message' => 'Invalid password']);
                    }
            }
            else {
            // User is deleted
            echo json_encode(['success' => true, 'message' => 'User Deleted']);
            }
        }
        else{
            // user is locked
            echo json_encode(['success' => true, 'message' => 'User locked']);
        }
    } 
    else {
        // User not found
        echo json_encode(['success' => true, 'message' => 'User not found']);
    }

}
else {
    die();
}


?>