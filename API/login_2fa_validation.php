<?php

include 'myfunctions.php';

if (isset($_SESSION['twofa_check_user_email'])) {

    include 'sql_conn.php';
    // Handle 2FA logic

    if (isset($_POST['validateTwofaCode'])) {

        $encryptedotp2fa = $_POST['validateTwofaCode'];

        // Decrypt 2fa code
        $otp2fa = decryptRSA($encryptedotp2fa);

        $check_passed_email = $_SESSION['twofa_check_user_email'];

        // Check for Two Factor Authentication Code in database

        $checkotpsql = "SELECT * FROM login WHERE EmailId = '$check_passed_email' ";
        $checkotpresult = $conn->query($checkotpsql);
        if ($checkotpresult->num_rows > 0){
            while ($checkotprow = $checkotpresult->fetch_assoc()){
                $LoginCode = $checkotprow['TwoFactorAuthenticationCode'];
            }
        }

        if($LoginCode == $otp2fa){

            // Login, start session and redirect to home
            $_SESSION['passed_user_email'] = EncryptSessionsandCookies($check_passed_email);

            $cookie_name = "user_login";
            $cookie_value = $_SESSION['passed_user_email'];
            setcookie($cookie_name, $cookie_value, time() + (86400 * 7), "/"); // 86400 = 1 day  
            
            // header('Location: home.php');
            echo json_encode(['success' => true, 'message' => 'twofactorvalidation=success']);

            // Update OtpCode in the Database 

            $otpupdateStmt = $conn->prepare("UPDATE login SET TwoFactorAuthenticationCode = NULL WHERE EmailId = ?");
            $otpupdateStmt->bind_param("s", $check_passed_email);
            $otpupdateStmt->execute();

            exit();

        } else{
            // $error = "Entered Two Factor Authentication Code is Invalid";
            echo json_encode(['success' => false, 'message' => 'Entered Two Factor Authentication Code is Invalid']);
        }
    } else{}

} else{
    header('Location: ../login.html');
    exit();
}
?>