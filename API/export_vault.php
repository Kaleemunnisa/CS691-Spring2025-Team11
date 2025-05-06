<?php   
error_reporting(E_ALL ^ E_WARNING);
error_reporting(E_ERROR | E_PARSE);

// Database connection 
include "sql_conn.php";
include 'myfunctions.php';

header('Content-Type: application/json');

if (isset($_POST['Export']) && isset($_SESSION['passed_user_email'])) {

    $ExportEmailId = DecryptSessionsandCookies($_SESSION['passed_user_email']);
    if (empty($ExportEmailId)) {
        echo json_encode(['success' => false, 'message' => 'Session expired or user not authenticated.']);
        exit;
    }

    $sql = "SELECT * FROM vault WHERE UserEmailId = '$ExportEmailId' and DeleteFlag = 0";
    $Exportresult = $conn->query($sql);
    if (!$Exportresult) {
        echo json_encode(['success' => false, 'message' => 'Vault SQL error: ' . $conn->error]);
        exit;
    }

    $exportFileName = $ExportEmailId . date("mdY-his") . '.csv';
    $exportFileFoldername = '../exported_data/' . $exportFileName;

    if (!$myfile = fopen($exportFileFoldername, "w")) {
        echo json_encode(['success' => false, 'message' => 'Unable to open file: ' . $exportFileFoldername]);
        exit;
    }

    // Write CSV header using fputcsv
    $header = ["Group Name", "App Name", "Username", "Password", "Url", "Notes"];
    fputcsv($myfile, $header);

    while ($rowExport = $Exportresult->fetch_assoc()) {
        $FetchedGroupName = $rowExport['GroupName'];
        $FetchedAppName = $rowExport['AppName'];
        $FetchedUserName = $rowExport['UserName'];
        $FetchedEncryptedPassword = $rowExport['Password'];
        $FetchedUrl = $rowExport['Url'];
        $FetchedNotes = $rowExport['Notes'];
        $FetchedEncryptionKeyId = $rowExport['EncryptionKeyId'];

        // Fetch encryption key
        $sqlencryption = "SELECT EncryptionKey FROM encryption WHERE UserEmailId = '$ExportEmailId' and EncryptionKeyVersion = '$FetchedEncryptionKeyId'";
        $encryptionresult = $conn->query($sqlencryption);
        $FetchedEncryptionKey = '';
        if ($encryptionresult) {
            while ($rowencryption = $encryptionresult->fetch_assoc()) {
                $FetchedEncryptionKey = $rowencryption['EncryptionKey'];
            }
        }

        $FetchedDecryptedPassword = decryptString($FetchedEncryptedPassword, $FetchedEncryptionKey);

        // Write the data row using fputcsv
        $csvRow = [
            $FetchedGroupName,
            $FetchedAppName,
            $FetchedUserName,
            $FetchedDecryptedPassword,
            $FetchedUrl,
            $FetchedNotes
        ];
        fputcsv($myfile, $csvRow);
    }
    fclose($myfile);


    if ($ZipExportVaultMail == 1) {
        // Create password-protected ZIP (Windows compatible)
        $zip = new ZipArchive();
        $zipFileName = $exportFileFoldername . '.zip';
        $csvFileNameOnly = basename($exportFileFoldername); // only the CSV file name
        $zipPassword = generateExportFilePassword();

        if ($zip->open($zipFileName, ZipArchive::CREATE) === TRUE) {
            $zip->addFile($exportFileFoldername, $csvFileNameOnly);
            $zip->setEncryptionName($csvFileNameOnly, ZipArchive::EM_AES_256, $zipPassword);
            $zip->close();

            // Delete original CSV file
            unlink($exportFileFoldername);
        }
            // Save into DB
            $sqlInserttoDb = "INSERT INTO user_exported_files (exported_file_name, exported_file_path, UserEmailId) 
                            VALUES ('" . basename($zipFileName) . "', '".$exportFileFoldername.".zip"."', '$ExportEmailId')";
    }
    else {
        $zipPassword = NULL;
        // Save into DB
        $sqlInserttoDb = "INSERT INTO user_exported_files (exported_file_name, exported_file_path, UserEmailId) VALUES ('$exportFileName', '$exportFileFoldername', '$ExportEmailId')";
    }

    if ($conn->query($sqlInserttoDb) === TRUE) {
        if ($ZipExportVaultMail == 1) {
            $sqlFetch = "SELECT UniqueId FROM user_exported_files WHERE exported_file_name = '" . basename($zipFileName) . "' AND UserEmailId = '$ExportEmailId'";
        }
        else {
            $sqlFetch = "SELECT UniqueId FROM user_exported_files WHERE exported_file_name = '$exportFileName' AND UserEmailId = '$ExportEmailId'";
        }
        $FetchResult = $conn->query($sqlFetch);
        $FetchedUniqueID = "";
        while ($Fetchrow = $FetchResult->fetch_assoc()) {
            $FetchedUniqueID = $Fetchrow['UniqueId'];
        }
        $Download_file_link = 'API/downloadExportedData.php?file_id=' . $FetchedUniqueID;

        $returnFlag = sendExportMail($ExportEmailId, $Download_file_link, $zipPassword);
    
        if ($returnFlag == "1") {
            echo json_encode(['success' => true, 'message' => 'Data Export success! The exported file link has been sent to your email.']);
        } else {
            echo json_encode(['success' => false, 'message' => 'Exported file created, but email sending failed.']);
        }
    } else {
        echo json_encode(['success' => false, 'message' => 'Database insert error: ' . $conn->error]);
    }
    exit;
} else {
    echo json_encode(['success' => false, 'message' => 'Invalid request.']);
    exit;
}
?>
