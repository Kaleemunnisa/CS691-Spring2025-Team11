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

    if (isset($_POST['saveEditedAccount'])) {

        // Retrieve modified data from the form
        $prigroupname = $_POST['group'];
        $altgroupname = $_POST['newGroup'];
        if ($prigroupname == 'new'){
            $groupname = $altgroupname;
        }
        else{
            $groupname = $prigroupname;
        }
        $newappname = $_POST['AccountName'];
        $newusername = $_POST['Username'];
        $postnewPassword = $_POST['Password'];
        $newurl = $_POST['Url'];
        $newnotes = $_POST['Notes'];
        $UniqueId = $_POST['ID'];

        $sql = "SELECT CurrentPasswordVersion, EncryptionKeyId FROM vault WHERE UniqueId = '$UniqueId'";
        $result = $conn->query($sql);
    
        if ($result->num_rows > 0) {
            while ($row = $result->fetch_assoc()) {
                $oldCurrentPasswordVersion = $row['CurrentPasswordVersion'];
                $oldCurrentEncryptionKeyId = $row['EncryptionKeyId'];
            }
        }

        $sqlfetchenckey = "SELECT * FROM encryption WHERE UserEmailId = '$loggedinusermailid' and EncryptionKeyVersion = '$oldCurrentEncryptionKeyId'; ";
        $resultfetchenckey = $conn->query($sqlfetchenckey);

        if ($resultfetchenckey->num_rows > 0) {
            while ($rowfetchenckey = $resultfetchenckey->fetch_assoc()) {
                $FetchedEncryptionKey = $rowfetchenckey['EncryptionKey'];
            }
        }
        // EnCrypt Password
        $newPassword = encryptString($postnewPassword, $FetchedEncryptionKey);

        $modifiedCurrentPasswordVersion = $oldCurrentPasswordVersion + 1;

        // Perform the update operation
        $updateSql = "UPDATE vault SET 
                    GroupName = '$groupname',
                    AppName = '$newappname',
                    UserName = '$newusername',
                    Password = '$newPassword',
                    Url = '$newurl',
                    Notes = '$newnotes',
                    CurrentPasswordVersion = '$modifiedCurrentPasswordVersion'
                    WHERE UniqueId = '$UniqueId' ";

        $result1 = $conn->query($updateSql);

        $insertsql = "INSERT INTO vault_history (UniqueId, Password, PasswordVersion, GroupName, AppName, UserName, Url, Notes, EncryptionKeyId) VALUES
                        ('$UniqueId','$newPassword','$modifiedCurrentPasswordVersion', '$groupname', '$newappname', '$newusername', '$newurl', '$newnotes', '$oldCurrentEncryptionKeyId')";

        $result2 = $conn->query($insertsql);

        if ($result1 == TRUE && $result2 == TRUE) {

            $checknotificationssql = "SELECT * FROM notifications WHERE UserEmailId = '$loggedinusermailid' ";
            $checknotificationsresult = $conn->query($checknotificationssql);
            if ($checknotificationsresult->num_rows > 0){
                while ($checknotificationsrow = $checknotificationsresult->fetch_assoc()){
                    $accountInfoUpdateFlag = $checknotificationsrow['AccountInfoUpdate'];
                }
            }

            if ($accountInfoUpdateFlag == 1){

                // send mail if notifications is enabled
                $sqlaccountInfoUpdate = "SELECT * FROM message_templates WHERE TemplateName = 'edit account' and DeleteFlag = 0 ";
                $resultaccountInfoUpdate = $conn->query($sqlaccountInfoUpdate);
            
                if ($resultaccountInfoUpdate->num_rows > 0) {
                    while($rowaccountInfoUpdate = $resultaccountInfoUpdate->fetch_assoc()){
                        $strsubject = $rowaccountInfoUpdate['Subject'];
                        $strmessagebody1 = $rowaccountInfoUpdate['Body1'];
                        $strmessagebody2 = $rowaccountInfoUpdate['Body2'];
                    }
                }
            
                // send mail
                $ToEmailBody = $strmessagebody1 .''. $strmessagebody2;
                send_Email_to_Queue($loggedinusermailid, $strsubject, $ToEmailBody);
            }

            echo json_encode(['success' => true, 'message' => 'saveEditAccount=true']);
        } else {
            echo json_encode(['success' => false, 'message' => 'failed to save account details']);
        }

    } elseif (isset($_POST['saveNewAccount'])) {
        // Retrieve data from the form
        $prigroupname = $_POST['group'];
        $altgroupname = $_POST['newGroup'];
        if ($prigroupname == 'new'){
            $groupname = $altgroupname;
        }
        else{
            $groupname = $prigroupname;
        }
        $appname = $_POST['AccountName'];
        $username = $_POST['Username'];
        $postPassword = $_POST['Password'];
        $url = $_POST['Url'];
        $notes = $_POST['Notes'];

        $sqlfetchencid = "SELECT * FROM encryption WHERE UserEmailId = '$loggedinusermailid' ORDER BY EncryptionKeyVersion DESC LIMIT 1;"; 
        $resultsqlfetchencid = $conn->query($sqlfetchencid);

        if ($resultsqlfetchencid->num_rows > 0) {
            while($rowsqlfetchencid = $resultsqlfetchencid->fetch_assoc()){
                $fetchedEncryptionKeyVersion = $rowsqlfetchencid['EncryptionKeyVersion'];
                $fetchedEncryptionKey = $rowsqlfetchencid['EncryptionKey'];
            }
        }

        // EnCrypt Password
        $newPassword = encryptString($postPassword, $fetchedEncryptionKey);

        $sql = "INSERT INTO vault ( GroupName, AppName, UserName, Password, Url, Notes, UserEmailId, EncryptionKeyId) VALUES ( '$groupname', '$appname', '$username', '$newPassword', '$url', '$notes', '$loggedinusermailid', '$fetchedEncryptionKeyVersion')";
        $result_sql = $conn->query($sql);
        $sqlfetch = "SELECT * FROM vault where UserName = '$username' AND GroupName = '$groupname' AND AppName = '$appname' AND Password = '$newPassword' AND Url = '$url' ";
        $resultsqlfetch = $conn->query($sqlfetch);

        if ($resultsqlfetch->num_rows > 0) {
            while($row = $resultsqlfetch->fetch_assoc()){
                $fetcheduniqueid = $row['UniqueId'];
                $CurrentPasswordVersion = $row['CurrentPasswordVersion'];
            }
        }

        $sql1 = "INSERT INTO vault_history (UniqueId, GroupName, AppName, UserName, Password, Url, Notes, PasswordVersion, EncryptionKeyId) VALUES ('$fetcheduniqueid', '$groupname', '$appname', '$username',  '$newPassword', '$url', '$notes', '$CurrentPasswordVersion', '$fetchedEncryptionKeyVersion')";
        $result_sql1 = $conn->query($sql1);

        if ($result_sql === TRUE && $result_sql1 === TRUE) {
            // Send notification(s) via mail if email notifications are enabled.

            $checknotificationssql = "SELECT * FROM notifications WHERE UserEmailId = '$loggedinusermailid' ";
            $checknotificationsresult = $conn->query($checknotificationssql);
            if ($checknotificationsresult->num_rows > 0){
                while ($checknotificationsrow = $checknotificationsresult->fetch_assoc()){
                    $NewAccountAddedFlag = $checknotificationsrow['NewAccountAdded'];
                }
            }

            if ($NewAccountAddedFlag == 1){

                // send mail if notifications is enabled
                $sqlNewAccountAdded = "SELECT * FROM message_templates WHERE TemplateName = 'add account' and DeleteFlag = 0 ";
                $resultNewAccountAdded = $conn->query($sqlNewAccountAdded);
            
                if ($resultNewAccountAdded->num_rows > 0) {
                    while($rowNewAccountAdded = $resultNewAccountAdded->fetch_assoc()){
                        $strsubject = $rowNewAccountAdded['Subject'];
                        $strmessagebody1 = $rowNewAccountAdded['Body1'];
                        $strmessagebody2 = $rowNewAccountAdded['Body2'];
                    }
                }
            
                // send mail
                $ToEmailBody = $strmessagebody1 .''. $strmessagebody2;
                send_Email_to_Queue($loggedinusermailid, $strsubject, $ToEmailBody);
            }
            echo json_encode(['success' => true, 'message' => 'addNewAccount=true', 'id' => $fetcheduniqueid]);
        } else{
            echo json_encode(['success' => false, 'message' => 'failed to add new account.']);
        }
    }
    else {}
}
else {
    echo json_encode(['success' => false, 'message' => 'You need to login first to access data.']);
}
?>