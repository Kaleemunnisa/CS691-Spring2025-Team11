<?php

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

// Fetch data from config file
$file = '../config.env';
$lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

foreach ($lines as $line) {
    $parts = explode('=', $line, 2);
    if (count($parts) == 2) {
        $key = trim($parts[0]);
        $value = trim($parts[1], '"'); // Remove quotes if present
        $$key = $value; // Dynamically create variables
    }
}

/* Handle encryption and decryption of Vault starts here */

// Encryption function
function encryptString($inputString, $encryptionKey) {

    // Check if the input string is within the specified length limit
    if (strlen($inputString) > 255) {
        return false;
    }

    // Generate a random initialization vector (IV)
    $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length('aes-256-cbc'));

    // Encrypt the input string using AES-256 encryption
    $encryptedString = openssl_encrypt($inputString, 'aes-256-cbc', $encryptionKey, 0, $iv);

    // Combine IV and encrypted string
    $encryptedData = $iv . $encryptedString;

    // Encode the result to make it safe for storage or transmission
    return base64_encode($encryptedData);
}

// Decryption function
function decryptString($encryptedString, $encryptionKey) {

    // Decode the base64 encoded input
    $encryptedData = base64_decode($encryptedString);

    // Extract the IV (first 16 bytes)
    $iv = substr($encryptedData, 0, 16);

    // Extract the encrypted string (remaining bytes)
    $encryptedString = substr($encryptedData, 16);

    // Decrypt the string using AES-256 decryption
    $decryptedString = openssl_decrypt($encryptedString, 'aes-256-cbc', $encryptionKey, 0, $iv);

    // Return the decrypted string
    return $decryptedString;
}

// Generate new encryption key for registerd new users
 function generateEncryptionkey() {
    $count = 0;
    $characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#%&*-_=+?';
    $randomString = '';

    for ($i = 0; $i < 20; $i++) {
        $randomString .= $characters[rand(0, strlen($characters) - 1)];
    }

    include 'sql_conn.php';

    $selectencstmt = $conn->prepare("SELECT * FROM encryption ");
    $selectencstmt->execute();
    $selectencresult = $selectencstmt->get_result();

    if ($selectencresult->num_rows === 1) {
      $selectencdata = $selectencresult->fetch_assoc();

      // check if this encryption key is being used by someone
      if ($selectencdata['EncryptionKey'] == $randomString){
        $count = $count + 1;
        } else{}
    }

    if ($count > 0 || strlen($randomString) < 20 ){
        // closing connection before calling function recursively to avoid reaching maximum sql connections 
        $selectencstmt->close();
        $conn->close();

        generateEncryptionkey();
    } else{
        return $randomString;
    }  
 }

 /* Handle encryption and decryption of Vault Ends here */


 function escapeHtml($input) {
    // Convert special characters to HTML entities
    return htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
}

function processString($input) {
    // Remove unwanted characters and trim whitespace
    $sanitizedString = filter_var(trim($input), FILTER_SANITIZE_STRING);

    return $sanitizedString;
}




    // Decrypt RSA function
    function decryptRSA($data) {
        // Load the private key
        $privateKey = file_get_contents('login_private_key.pem');

        // Convert base64 to binary
        $data = base64_decode($data);

        // Decrypt the data
        $decrypted = '';
        if (openssl_private_decrypt($data, $decrypted, $privateKey)) {
            // echo '<script> console.log("RSA Decryption Success!"); </script>';
        } else {
            // echo '<script> console.log("RSA Decryption Failed! Please contact administrator"); </script>';
        }
        return $decrypted;
    }

/* Handle encryption and decryption of session variables and cookie variables starts here */

function EncryptSessionsandCookies ($plainText) {
    $key1 = "8wRtrGVqcpFuk#?Xj6j-ZXeQ=-pu3IsL";
    $key2 = "1DFE#TrGMtx5KGYQpjk#ned1YYQrgtbe";
    // First Level Encryption: AES-256-CBC
    $method = 'AES-256-CBC';
    $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($method));
    $encrypted = openssl_encrypt($plainText, $method, $key1, 0, $iv);
    $encryptedWithIv = base64_encode($encrypted . '::' . $iv);

    // Second Level Encryption: Base64 Encoding
    $finalEncrypted = base64_encode($encryptedWithIv . '::' . $key2);

    return $finalEncrypted;
}

function DecryptSessionsandCookies ($encryptedText) {
    $key1 = "8wRtrGVqcpFuk#?Xj6j-ZXeQ=-pu3IsL";
    $key2 = "1DFE#TrGMtx5KGYQpjk#ned1YYQrgtbe";
    // First Level Decryption: Base64 Decoding
    $decodedText = base64_decode($encryptedText);
    list($encryptedWithIv, $retrievedKey2) = explode('::', $decodedText, 2);

    // Verify key2
    if ($retrievedKey2 !== $key2 && $retrievedKey2 != NULL && $key2 != NULL) {
        throw new Exception("Invalid key2 for decryption");
    }

    // Second Level Decryption: AES-256-CBC
    $method = 'AES-256-CBC';
    $encryptedWithIvDecoded = base64_decode($encryptedWithIv);
    list($encrypted, $iv) = explode('::', $encryptedWithIvDecoded, 2);
    $decrypted = openssl_decrypt($encrypted, $method, $key1, 0, $iv);

    return $decrypted;
}

/* Handle encryption and decryption of session variables and cookie variables Ends here */




/* Emails Section starts Here */

//send email when an user signup
function sendSignupEmail($signUpEmailId, $SignUpLastName, $SignUpFirstName) {

    include 'sql_conn.php';

    $TemplateName = 'welcome mail';

    $sqltemplates = "SELECT * FROM mail_templates WHERE TemplateName = '$TemplateName' and DeleteFlag = 0 ";
    $resulttemplates = $conn->query($sqltemplates);

    if ($resulttemplates->num_rows > 0) {
        while($row = $resulttemplates->fetch_assoc()){
            $strsubject = $row['Subject'];
            $fetchedMessageBody1 = $row['Body1'];
        }
    }

    $values = [
        '{$userEmail}' => $signUpEmailId,
        '{$lastName}' => $SignUpLastName,
        '{$firstName}' => $SignUpFirstName
    ];

    // Replacing placeholders with actual values
    $MessageTemplateBody = str_replace(array_keys($values), array_values($values), $fetchedMessageBody1);

    // Format the Email using Email template
    $MailMessageBody = getMailTemplate($TemplateName, $MessageTemplateBody);

    // Send mail
    return send_Email_to_Queue($signUpEmailId, $strsubject, $MailMessageBody);
}

// send email when forgot password is initiated
function sendForgotPasswordEmail($userEmail, $resetPasswordUrl) {

    include 'sql_conn.php';

    $TemplateName = 'otp mail';

    $sqlForgotPassword = "SELECT * FROM mail_templates WHERE TemplateName = 'otp mail' and DeleteFlag = 0 ";
    $resultForgotPassword = $conn->query($sqlForgotPassword);

    if ($resultForgotPassword->num_rows > 0) {
        while($row = $resultForgotPassword->fetch_assoc()){
            $strsubject = $row['Subject'];
            $fetchedMessageBody1 = $row['Body1'];
        }
    }

    $values = [
        '{$Reset_password_URL}' => $resetPasswordUrl
    ];

    // Replacing placeholders with actual values
    $MessageTemplateBody = str_replace(array_keys($values), array_values($values), $fetchedMessageBody1);

    // Format the Email using Email template
    $MailMessageBody = getMailTemplate($TemplateName, $MessageTemplateBody);

    // Send mail
    return send_Email_to_Queue($userEmail, $strsubject, $MailMessageBody);

}

// send OTP mail if it is initiated
function sendLoginOTPEmail($CheckUserEmailId, $OtpCode) {

    include 'sql_conn.php';

    $TemplateName = '2fa otp mail';

    $sqlForgotPassword = "SELECT * FROM `password_manager`.`mail_templates` WHERE TemplateName = '$TemplateName' and DeleteFlag = 0 ";
    $resultForgotPassword = $conn->query($sqlForgotPassword);

    if ($resultForgotPassword->num_rows > 0) {
        while($row = $resultForgotPassword->fetch_assoc()){
            $strsubject = $row['Subject'];
            $fetchedMessageBody1 = $row['Body1'];
        }
    }

    $values = [
        '{$LoginOTP}' => $OtpCode
    ];

    // Replacing placeholders with actual values
    $MessageTemplateBody = str_replace(array_keys($values), array_values($values), $fetchedMessageBody1);

    // Format the Email using Email template
    $MailMessageBody = getMailTemplate($TemplateName, $MessageTemplateBody);

    // Send mail
    return send_Email_to_Queue($CheckUserEmailId, $strsubject, $MailMessageBody);

}

// Send Export Data mail
function sendExportMail($ExportEmailId, $exportFileFoldername){

    include  'sql_conn.php';

    $sqltemplates = "SELECT * FROM message_templates WHERE TemplateName = 'export mail' and DeleteFlag = 0 ";
    $resulttemplates = $conn->query($sqltemplates);

    if ($resulttemplates->num_rows > 0) {
        while($row = $resulttemplates->fetch_assoc()){
            $strsubject = $row['Subject'];
            $strmessage1 = $row['Body1'];
            $strmessage3 = $row['Body2'];
        }
    }

    // message link button
    $strmessage21 = '<br><p>Click on the below download button to downlaod data in csv file format and that can be opened using Microsoft excel.
                    </p><div class="d-grid gap-2 d-md-flex justify-content-md-center"> 
                    <a class="btn btn-primary" href="';
    $strmessage22 = 'https://networkpranav.in/APPS/password_manager/' . $exportFileFoldername;
    $strmessage23 = '"> Download </a> </div>';

    $strexportmsgbody = $strmessage1 . $strmessage21 . $strmessage22 . $strmessage23 . $strmessage3;

    send_Email_to_Queue($ExportEmailId, $strsubject, $strexportmsgbody);

    return 1;
}

// Send Delete Account/Password mail
function sendAccountPasswordDeleteMail($loggedinusermailid) {

    include 'sql_conn.php';

    $TemplateName = 'delete account';

    $sqlForgotPassword = "SELECT * FROM `password_manager`.`mail_templates` WHERE TemplateName = '$TemplateName' and DeleteFlag = 0 ";
    $resultForgotPassword = $conn->query($sqlForgotPassword);

    if ($resultForgotPassword->num_rows > 0) {
        while($row = $resultForgotPassword->fetch_assoc()){
            $strsubject = $row['Subject'];
            $fetchedMessageBody1 = $row['Body1'];
        }
    }

    $MessageTemplateBody = $fetchedMessageBody1;

    // Format the Email using Email template
    $MailMessageBody = getMailTemplate($TemplateName, $MessageTemplateBody);

    // Send mail
    return send_Email_to_Queue($loggedinusermailid, $strsubject, $MailMessageBody);

}

// Trigger mail if toaddress , mail subject , mail body is passed
function sendEmail($ToUserEmail, $emailSubject, $emailMessage) {
    include 'sql_conn.php';

    // Prepare the SQL statement with placeholders
    $stmt = $conn->prepare("INSERT INTO `db_pranav`.`phpmsgmailqueue` (frommailaddress, tomailaddress, mailsubject, mailbody) VALUES (?, ?, ?, ?)");

    // Check if the prepare statement was successful
    if ($stmt === false) {
        return 'Error: ' . $conn->error;
    }

    // Bind the parameters to the placeholders
    $fromEmail = 'networkpranav.in@gmail.com';
    $stmt->bind_param("ssss", $fromEmail, $ToUserEmail, $emailSubject, $emailMessage);

    // Execute the prepared statement
    if ($stmt->execute()) {
        return 'Success';
    } else {
        return 'Error: ' . $stmt->error;
    }

    // Close the statement
    $stmt->close();
}

// Fetch Mail Template
function getMailTemplate($PassedTemplateName, $PassedTemplateBody) {
    include 'sql_conn.php';
    $EmailTemplate = '<table align="center" border="0" cellpadding="0" cellspacing="0" width="600">
                        <tr>
                            <td align="center" bgcolor="#f0f0f0"><img src="{$banner_img_src_url}" alt="Logo" width="600" height="165"></td>
                        </tr>
                        <tr>
                            <td bgcolor="#ffffff" style="padding: 40px 30px 40px 30px;">
                                <table border="0" cellpadding="0" cellspacing="0" width="100%">
                                    <tr>
                                        <td style="color: #333; font-family: Arial, sans-serif; text-align: center; font-size: 24px;">
                                            <b> {$body_header}
                                            </b>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td
                                            style="padding: 20px 0 30px 0; color: #666; font-family: Arial, sans-serif; font-size: 16px; line-height: 1.6;">
                                            {$Template_Body}
                                        </td>
                                    </tr>
                                    <tr>
                                        <td
                                            style="padding: 20px 0 30px 0; color: #666; font-family: Arial, sans-serif; font-size: 16px; line-height: 1.6;">
                                            <a href="{$login_page_url}"> Click</a> here to login into your
                                            account.<br><br>
                                            If you have any questions or need assistance, please refer to our <a
                                                href="{$documentation_page_url}">documentation</a> or
                                            check our FAQs section.
                                        </td>
                                    </tr>
                                </table>
                            </td>
                        </tr>
                        <tr>
                            <td>
                                <p style="font-size:12px">This email is auto-generated so please do not reply to this email as we will be
                                    unable to respond from this email address. Please connect with us on <span> <a
                                            href="mailto:{$Support_email}" style="color:#bc0069;font-size:12px;text-decoration:none"
                                            target="_blank">{$Support_email}</a></span> for any queries. </p>
                            </td>
                        </tr>
                        <tr>
                            <td><br></br></td>
                        </tr>
                        <tr>
                            <td bgcolor="#f0f0f0" style="padding: 20px 30px 20px 30px;">
                                <table border="0" cellpadding="0" cellspacing="0" width="100%">
                                    <tr>
                                        <td style="color: #888; font-family: Arial, sans-serif; font-size: 12px; text-align: center;">
                                            {$current_year} @ SecurePass {$current_version}
                                        </td>
                                    </tr>
                                </table>
                            </td>
                        </tr>
                    </table>';

    // Default values if the mail templates do not have any variables
    $values = [
        '{$banner_img_src_url}' => $DomainURL . '/img/mailbanner.png',
        '{$body_header}' => '',
        '{$Template_Body}' => '',
        '{$login_page_url}' => $DomainURL . '/',
        '{$documentation_page_url}' => $DomainURL . '/docs',
        '{$Support_email}' => $SecurePassSupportEmail,
        '{$current_year}' => date('Y'),
        '{$current_version}' => 'v1.0.0'
    ];

    // Check App Version
    $sqlCheckVersion = "SELECT AppVersion 
                        FROM version WHERE DeleteFlag = 0 
                        ORDER BY 
                            CAST(SUBSTRING_INDEX(SUBSTRING_INDEX(AppVersion, '.', 1), 'v', -1) AS UNSIGNED) DESC,
                            CAST(SUBSTRING_INDEX(SUBSTRING_INDEX(AppVersion, '.', -2), '.', 1) AS UNSIGNED) DESC,
                            CAST(SUBSTRING_INDEX(AppVersion, '.', -1) AS UNSIGNED) DESC
                        LIMIT 1;
                        ";
    $resultCheckVersion = $conn->query($sqlCheckVersion);

    if ($resultCheckVersion->num_rows > 0) {
        while($row = $resultCheckVersion->fetch_assoc()){
            $fetchedAppVersion = $row['AppVersion'];
        }
    }

    // Get Template details
    $sqlGetTemplates = "SELECT * FROM mail_templates WHERE TemplateName = '$PassedTemplateName' and DeleteFlag = 0 ";
    $resultGetTemplates = $conn->query($sqlGetTemplates);

    if ($resultGetTemplates->num_rows > 0) {
        while($row = $resultGetTemplates->fetch_assoc()){
            $fetchedSubject = $row['Subject'];
            $fetchedHeader = $row['Header'];
            $fetchedBannerUrl = $row['BannerUrl'];
            $fetchedSupportMailAddress = $row['SupportMailAddress'];
            $fetchedLoginPageUrl = $row['LoginPageUrl'];
            $fetchedDocumentationUrl = $row['DocumentationUrl'];
        }
        // Update Values
        $values = [
            '{$banner_img_src_url}' => $fetchedBannerUrl,
            '{$body_header}' => $fetchedHeader,
            '{$Template_Body}' => $PassedTemplateBody,
            '{$login_page_url}' => $fetchedLoginPageUrl,
            '{$documentation_page_url}' => $fetchedDocumentationUrl,
            '{$Support_email}' => $fetchedSupportMailAddress,
            '{$current_year}' => date('Y'),
            '{$current_version}' => $fetchedAppVersion
        ];
    }

    // Replacing placeholders with actual values
    $FinalEmailTemplate = str_replace(array_keys($values), array_values($values), $EmailTemplate);

    return $FinalEmailTemplate;
}

 // function to send mail using mail queue 
function send_Email_to_Queue($ToMailAddress, $ToEmailSubject, $ToEmailBody) {

    include 'sql_conn.php';

    $sqlFetchMailSlug = "SELECT EmailId FROM `db_pranav`.`mailslug` WHERE DeleteFlag = 0 ORDER BY Sno DESC LIMIT 1";
    $resultFetchMailSlug = $conn1->query($sqlFetchMailSlug);

    if ($resultFetchMailSlug->num_rows > 0) {
        while($row = $resultFetchMailSlug->fetch_assoc()){
            $EmailIdFromMailSlug = $row['EmailId'];
        }
    }
    else{
        $EmailIdFromMailSlug = 'networkpranav.in@gmail.com';
    }

    $sqlinsertintodb = "INSERT INTO `db_pranav`.`phpmsgmailqueue` (frommailaddress, tomailaddress, mailsubject, mailbody) VALUES (?, ?, ?, ?)";
    $stmt = $conn1->prepare($sqlinsertintodb);
    $stmt->bind_param("ssss", $EmailIdFromMailSlug, $ToMailAddress, $ToEmailSubject, $ToEmailBody);
    
    if ($stmt->execute()) {
        return 'Success';
    } else {
        return 'Error';
    }
    
    $stmt->close();    

}

/* Emails Section Ends Here */
?>