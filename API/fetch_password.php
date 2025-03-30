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

    // Fetch Accounts passwords from Vault
    $sql = "SELECT * FROM vault WHERE UserEmailId = '$loggedinusermailid' AND DeleteFlag = 0 ORDER BY AppName ASC";
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
            $checkaccountsharesql = "SELECT * FROM shared_accounts WHERE fromsharedemailid = '$loggedinusermailid' AND deleteflag = 0 AND sharedaccountuniqueid = '$fetcheduniqueid'";
            $checkaccountshareresult = $conn->query($checkaccountsharesql);
            if ($checkaccountshareresult->num_rows > 0) {
                $sharedAccFlag = 1;
            }else {
                $sharedAccFlag = 0;
            }
            
            // De-crypt password
            $decryptedPassword = decryptString($row['Password'], $fetchedEncryptionKey);

            $data[] = [
                "ID" => $fetcheduniqueid,
                "GroupName" => $row['GroupName'],
                "AppName" => $row['AppName'],
                "UserName" => $row['UserName'],
                "Password" => $decryptedPassword,
                "WebsiteUrl" => $row['Url'],
                "Notes" => $row['Notes'],
                "IsAccountShared" => $sharedAccFlag
            ];
        }
        echo json_encode(["success" => true, "message" => "Data fetched successfully.", "data" => $data]);
    }
    else {
        echo json_encode(['success' => true, 'message' => 'No data found.']);
    }
}
else {
    echo json_encode(['success' => false, 'message' => 'You need to login first to access data.']);
}






?>