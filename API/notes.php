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
    $loggedinusermailid = DecryptSessionsandCookies($_SESSION['passed_user_email']);

    // Logic for Fetch Notes
    if (isset($_POST['fetchnotesdata']) == 'true') {

        // Fetch notes from notes table
        $sql = "SELECT * FROM notes WHERE UserEmailId = '$loggedinusermailid' AND DeleteFlag = 0 ORDER BY Title ASC";
        $result = $conn->query($sql);

        if ($result->num_rows > 0) {
            $data = [];
            while ($row = $result->fetch_assoc()) {

                $fetcheduniqueid = $row['UniqueId'];

                // Fetch Encryption keyid
                $EncryptionKeyId = $row['EncryptionKeyId'];

                // Fetch Encryption key
                $fetchencrpasssql = "SELECT EncryptionKey FROM encryption WHERE EncryptionKeyVersion = '$EncryptionKeyId' AND UserEmailId = '$loggedinusermailid' ";
                $fetchencrpassresult = $conn->query($fetchencrpasssql);
                if ($fetchencrpassresult->num_rows > 0) {
                    while ($fetchencrpassrow = $fetchencrpassresult->fetch_assoc()) {
                        $fetchedEncryptionKey = $fetchencrpassrow['EncryptionKey'];
                    }
                }

                // Fetch Share account Flag
                $checkaccountsharesql = "SELECT * FROM shared_notes WHERE fromsharedemailid = '$loggedinusermailid' AND deleteflag = 0 AND sharednotesuniqueid = '$fetcheduniqueid'";
                $checkaccountshareresult = $conn->query($checkaccountsharesql);
                if ($checkaccountshareresult->num_rows > 0) {
                    $sharedNotesFlag = 1;
                }else {
                    $sharedNotesFlag = 0;
                }
                
                // De-crypt password
                $decryptedNotes = decryptString($row['Notes'], $fetchedEncryptionKey);

                $data[] = [
                    "ID" => $fetcheduniqueid,
                    "GroupName" => $row['GroupName'],
                    "Title" => $row['Title'],
                    "ColourGroup" => $row['ColourGroup'],
                    "Notes" => $row['Notes'],
                    "IsNotesShared" => $sharedNotesFlag
                ];
            }
            echo json_encode(["success" => true, "message" => "Data fetched successfully.", "data" => $data]);
        }
        else {
            echo json_encode(['success' => true, 'message' => 'No data found.']);
        }

    }
    // Save Notes
    elseif (isset($_POST['saveEditedNotes']) == 'true') {

        // Retrieve data from the form
        $prigroupname = $_POST['group'];
        $altgroupname = $_POST['newGroup'];
        if ($prigroupname == 'new'){
            $groupname = $altgroupname;
        }
        else{
            $groupname = $prigroupname;
        }
        $notesTitle = $_POST['Title'];
        $notesContent = $_POST['Notes'];
        $notesID = $_POST['ID'];
        $ColourGroup = $_POST['ColourGroup'];

        $sql = "SELECT CurrentNotesVersion, EncryptionKeyId FROM notes WHERE UniqueId = '$notesID'";
        $result = $conn->query($sql);
    
        if ($result->num_rows > 0) {
            while ($row = $result->fetch_assoc()) {
                $oldCurrentNotesVersion = $row['CurrentNotesVersion'];
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

        $modifiedCurrentNotesVersion = $oldCurrentNotesVersion + 1;

        // Perform the update operation
        $updateSql = "UPDATE notes SET 
                    GroupName = '$groupname',
                    Title = '$notesTitle',
                    Notes = '$notesContent',
                    ColourGroup = '$ColourGroup',
                    CurrentNotesVersion = '$modifiedCurrentNotesVersion'
                    WHERE UniqueId = '$notesID' ";

        $result1 = $conn->query($updateSql);

        $insertsql = "INSERT INTO notes_history (Title, NotesVersion, GroupName, Notes, ColourGroup, EncryptionKeyId, NotesID) VALUES
                        ('$notesTitle','$modifiedCurrentNotesVersion', '$groupname', '$notesContent', '$ColourGroup', '$oldCurrentEncryptionKeyId', '$notesID')";

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

            echo json_encode(['success' => true, 'message' => 'saveEditedNotes=true']);
        } else {
            echo json_encode(['success' => false, 'message' => 'failed to save notes']);
        }
    }
    // Add New Notes
    elseif (isset($_POST['addNewNotes']) == 'true') {
        // Retrieve data from the form
        $prigroupname = $_POST['group'];
        $altgroupname = $_POST['newGroup'];
        if ($prigroupname == 'new'){
            $groupname = $altgroupname;
        }
        else{
            $groupname = $prigroupname;
        }
        $Title = $_POST['Title'];
        $Notes = $_POST['Notes'];
        $ColourGroup = $_POST['ColourGroup'];

        $sqlfetchencid = "SELECT * FROM encryption WHERE UserEmailId = '$loggedinusermailid' ORDER BY EncryptionKeyVersion DESC LIMIT 1;"; 
        $resultsqlfetchencid = $conn->query($sqlfetchencid);

        if ($resultsqlfetchencid->num_rows > 0) {
            while($rowsqlfetchencid = $resultsqlfetchencid->fetch_assoc()){
                $fetchedEncryptionKeyVersion = $rowsqlfetchencid['EncryptionKeyVersion'];
                $fetchedEncryptionKey = $rowsqlfetchencid['EncryptionKey'];
            }
        }

        $sql = "INSERT INTO notes ( GroupName, Title, Notes, ColourGroup, UserEmailId, EncryptionKeyId) VALUES ( '$groupname', '$Title', '$Notes', '$ColourGroup', '$loggedinusermailid', '$fetchedEncryptionKeyVersion')";
        $result_sql = $conn->query($sql);
        $sqlfetch = "SELECT * FROM notes where Title = '$Title' AND GroupName = '$groupname' AND Notes = '$Notes' AND ColourGroup = '$ColourGroup' AND UserEmailId = '$loggedinusermailid' ";
        $resultsqlfetch = $conn->query($sqlfetch);

        if ($resultsqlfetch->num_rows > 0) {
            while($row = $resultsqlfetch->fetch_assoc()){
                $fetcheduniqueid = $row['UniqueId'];
                $CurrentNotesVersion = $row['CurrentNotesVersion'];
            }
        }

        $sql1 = "INSERT INTO notes_history (NotesID, GroupName, Title, Notes, ColourGroup, NotesVersion, EncryptionKeyId) VALUES ('$fetcheduniqueid', '$groupname', '$Title', '$Notes',  '$ColourGroup', '$CurrentNotesVersion', '$fetchedEncryptionKeyVersion')";
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
            echo json_encode(['success' => true, 'message' => 'addNewNotes=true', 'id' => $fetcheduniqueid]);
        } else{
            echo json_encode(['success' => false, 'message' => 'failed to add new notes.']);
        }
    }
    // Delete Notes
    elseif (isset($_POST['ID']) && isset($_POST['deleteNotes']) == 'true') {
        // Retrieve data from the form
        $UniqueId = $_POST['ID'];
        // Perform the deletion
        $sql = "UPDATE notes SET deleteflag = 1 WHERE UniqueId = '$UniqueId' AND UserEmailId = '$loggedinusermailid' ";

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
            echo json_encode(['success' => true, 'message' => 'deleteNotes=success']);
        } else {
            // Error during deletion
            echo json_encode(['success' => false, 'message' => 'failed to delete notes.']);
        }
    }
    else {}


}
else {
    echo json_encode(['success' => false, 'message' => 'You need to login first to access data.']);
}
?>