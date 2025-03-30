<?php   
error_reporting(E_ALL ^ E_WARNING);
error_reporting(E_ERROR | E_PARSE);
?>

<?php
// Database connection 
include "sql_conn.php";
include 'myfunctions.php';

if (isset($_SESSION['passed_user_email'])) {
    $loggedinusermailid = DecryptSessionsandCookies($_SESSION['passed_user_email']);
    $UniqueId = $_POST['ID'];
    if (isset($_POST['deleteAccountPassword']) && $_POST['deleteAccountPassword'] == true) {

        // Perform the deletion
        $sql = "UPDATE vault SET deleteflag = 1 WHERE UniqueId = '$UniqueId' AND UserEmailId = '$loggedinusermailid' ";

        if ($conn->query($sql) === TRUE) {

            // Send notification(s) via mail if email notifications are enabled.
            $checknotificationssql = "SELECT * FROM notifications WHERE UserEmailId = '$loggedinusermailid' ";
            $checknotificationsresult = $conn->query($checknotificationssql);
            if ($checknotificationsresult->num_rows > 0){
                while ($checknotificationsrow = $checknotificationsresult->fetch_assoc()){
                    $NewAccountAddedFlag = $checknotificationsrow['NewAccountAdded'];
                }
            }

            if ($NewAccountAddedFlag == 1){
                $sendMailResponse = sendAccountPasswordDeleteMail($loggedinusermailid);
            } else{}

            // Deletion successful
            echo json_encode(['success' => true, 'message' => 'deleteAccountPassword=success']);
        } else {
            // Error during deletion
            echo json_encode(['success' => false, 'message' => 'failed to delete account/password.']);
        }
    }
    else {
        echo json_encode(['success' => false, 'message' => 'failed to delete account/password.']);
    }

}
else {
    echo json_encode(['success' => false, 'message' => 'You need to login first to access data.']);
}
?>