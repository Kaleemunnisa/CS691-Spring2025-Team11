<?php   
error_reporting(E_ALL ^ E_WARNING);
error_reporting(E_ERROR | E_PARSE);

// Database connection 
include "sql_conn.php";
include 'myfunctions.php';

header('Content-Type: application/json');

// Parse incoming JSON
$data = json_decode(file_get_contents('php://input'), true);

if (!isset($_SESSION['passed_user_email'])) {
    echo json_encode(['success' => false, 'message' => 'Session expired.']);
    exit;
}
if (!$data || !isset($data['csv']) || !isset($data['mapping'])) {
    echo json_encode(['success' => false, 'message' => 'Invalid data.']);
    exit;
}
$csv = $data['csv'];
$mapping = $data['mapping'];
if (count($csv) < 2) {
    echo json_encode(['success' => false, 'message' => 'No data found in CSV.']);
    exit;
}

// Helper to get mapped value or default
function getMapped($destField, $header, $mapping, $row, $default = '') {
    if (!isset($mapping[$destField]) || !$mapping[$destField]) {
        return $default;
    }
    $srcIdx = array_search($mapping[$destField], $header);
    return ($srcIdx !== false && isset($row[$srcIdx])) ? trim($row[$srcIdx], " \t\n\r\0\x0B\"") : $default;
}

$header = array_map('trim', $csv[0]);
$UserEmailId = DecryptSessionsandCookies($_SESSION['passed_user_email']);

// Fetch the latest encryption key for this user
$sqlfetchencid = "SELECT * FROM encryption WHERE UserEmailId = '$UserEmailId' ORDER BY EncryptionKeyVersion DESC LIMIT 1;";
$resultsqlfetchencid = $conn->query($sqlfetchencid);
if (!$resultsqlfetchencid || $resultsqlfetchencid->num_rows == 0) {
    echo json_encode(['success' => false, 'message' => 'Encryption key not found for user.']);
    exit;
}
$rowEnc = $resultsqlfetchencid->fetch_assoc();
$fetchedEncryptionKeyVersion = $rowEnc['EncryptionKeyVersion'];
$fetchedEncryptionKey = $rowEnc['EncryptionKey'];

$importedCount = 0;
$failedCount = 0;
$failedRows = [];

for ($i = 1; $i < count($csv); $i++) {
    $row = $csv[$i];
    $insert = [];

    // Required vault fields for import, with defaults
    $GroupName = getMapped('GroupName', $header, $mapping, $row, 'Imported');
    $AppName = getMapped('AppName', $header, $mapping, $row, '');
    $UserName = getMapped('UserName', $header, $mapping, $row, '');
    $plainPassword = getMapped('Password', $header, $mapping, $row, '');
    $Url = getMapped('Url', $header, $mapping, $row, '');
    $Notes = getMapped('Notes', $header, $mapping, $row, '');

    // Encrypt password
    $newPassword = encryptString($plainPassword, $fetchedEncryptionKey);

    // Insert into vault
    $sql = "INSERT INTO vault 
        (GroupName, AppName, UserName, Password, Url, Notes, UserEmailId, EncryptionKeyId) 
        VALUES 
        (
            '".$conn->real_escape_string($GroupName)."',
            '".$conn->real_escape_string($AppName)."',
            '".$conn->real_escape_string($UserName)."',
            '".$conn->real_escape_string($newPassword)."',
            '".$conn->real_escape_string($Url)."',
            '".$conn->real_escape_string($Notes)."',
            '".$conn->real_escape_string($UserEmailId)."',
            '".$conn->real_escape_string($fetchedEncryptionKeyVersion)."'
        )";
    $result_sql = $conn->query($sql);

    if ($result_sql) {
        // Fetch the new record for UniqueId and CurrentPasswordVersion
        $sqlfetch = "SELECT * FROM vault WHERE UserName = '".$conn->real_escape_string($UserName)."' AND GroupName = '".$conn->real_escape_string($GroupName)."' AND AppName = '".$conn->real_escape_string($AppName)."' AND Password = '".$conn->real_escape_string($newPassword)."' AND Url = '".$conn->real_escape_string($Url)."' ORDER BY sno DESC LIMIT 1";
        $resultsqlfetch = $conn->query($sqlfetch);
        $fetcheduniqueid = '';
        $CurrentPasswordVersion = 1;
        if ($resultsqlfetch && $resultsqlfetch->num_rows > 0) {
            $rowFetched = $resultsqlfetch->fetch_assoc();
            $fetcheduniqueid = $rowFetched['UniqueId'];
            $CurrentPasswordVersion = $rowFetched['CurrentPasswordVersion'];
        }

        // Insert into vault_history as well
        $sql1 = "INSERT INTO vault_history (UniqueId, GroupName, AppName, UserName, Password, Url, Notes, PasswordVersion, EncryptionKeyId) VALUES (
            '".$conn->real_escape_string($fetcheduniqueid)."',
            '".$conn->real_escape_string($GroupName)."',
            '".$conn->real_escape_string($AppName)."',
            '".$conn->real_escape_string($UserName)."',
            '".$conn->real_escape_string($newPassword)."',
            '".$conn->real_escape_string($Url)."',
            '".$conn->real_escape_string($Notes)."',
            '".$conn->real_escape_string($CurrentPasswordVersion)."',
            '".$conn->real_escape_string($fetchedEncryptionKeyVersion)."'
        )";
        $result_sql1 = $conn->query($sql1);

        if ($result_sql1) {
            $importedCount++;
        } else {
            $failedCount++;
            $failedRows[] = $i + 1;
        }
    } else {
        $failedCount++;
        $failedRows[] = $i + 1;
    }
}

if ($failedCount == 0) {
    echo json_encode(['success' => true, 'message' => "Successfully imported $importedCount records."]);
} else {
    echo json_encode([
        'success' => false,
        'message' => "Imported $importedCount records. Failed to import $failedCount records at CSV rows: " . implode(", ", $failedRows)
    ]);
}
?>
