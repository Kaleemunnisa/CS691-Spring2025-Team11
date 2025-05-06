<?php
error_reporting(E_ALL ^ E_WARNING);
error_reporting(E_ERROR | E_PARSE);

include "sql_conn.php";
include 'myfunctions.php';

header('Content-Type: application/json');

if (isset($_SESSION['passed_user_email'])) {
    $loggedinusermailid = DecryptSessionsandCookies($_SESSION['passed_user_email']);

    // -------- FETCH CARDS ----------
    if (isset($_POST['action']) && $_POST['action'] == 'fetch') {
        $sql = "SELECT * FROM cards WHERE UserEmailId = '$loggedinusermailid' AND DeleteFlag = 0 ORDER BY datecreated DESC";
        $result = $conn->query($sql);

        if ($result->num_rows > 0) {
            $data = [];
            while ($row = $result->fetch_assoc()) {
                $EncryptionKeyId = $row['EncryptionKeyId'];
                $fetchedEncryptionKey = "";
                if ($EncryptionKeyId) {
                    $fetchencrpasssql = "SELECT EncryptionKey FROM encryption WHERE EncryptionKeyVersion = '$EncryptionKeyId' AND UserEmailId = '$loggedinusermailid'";
                    $fetchencrpassresult = $conn->query($fetchencrpasssql);
                    if ($fetchencrpassresult && $fetchencrpassresult->num_rows > 0) {
                        $fetchencrpassrow = $fetchencrpassresult->fetch_assoc();
                        $fetchedEncryptionKey = $fetchencrpassrow['EncryptionKey'];
                    }
                }

                // Decrypt Fields
                $fieldsDecrypted = [];
                if ($row['Fields'] && $fetchedEncryptionKey) {
                    $decrypted = decryptStringText($row['Fields'], $fetchedEncryptionKey);
                    $fieldsDecrypted = json_decode($decrypted, true);
                }

                $data[] = [
                    "UniqueId" => $row['UniqueId'],
                    "GroupName" => $row['GroupName'],
                    "CardName" => $row['CardName'],
                    "Fields" => $fieldsDecrypted,
                    "Notes" => $row['Notes'],
                    "CurrentCardVersion" => $row['CurrentCardVersion'],
                    "ActiveFlag" => $row['ActiveFlag'],
                    "DeleteFlag" => $row['DeleteFlag'],
                    "datecreated" => $row['datecreated'],
                    "EncryptionKeyId" => $row['EncryptionKeyId']
                ];
            }
            echo json_encode(["success" => true, "data" => $data]);
        } else {
            echo json_encode(['success' => true, 'data' => []]);
        }
        exit;
    }

    // --------- ADD NEW CARD ----------
    elseif (isset($_POST['action']) && $_POST['action'] == 'add') {
        $group = $_POST['GroupName'];
        $cardName = $_POST['CardName'];
        $fields = $_POST['Fields'];
        $notes = $_POST['Notes'];

        // Get latest Encryption Key
        $sqlfetchencid = "SELECT * FROM encryption WHERE UserEmailId = '$loggedinusermailid' ORDER BY EncryptionKeyVersion DESC LIMIT 1";
        $resultsqlfetchencid = $conn->query($sqlfetchencid);
        if ($resultsqlfetchencid->num_rows > 0) {
            $rowsqlfetchencid = $resultsqlfetchencid->fetch_assoc();
            $fetchedEncryptionKeyVersion = $rowsqlfetchencid['EncryptionKeyVersion'];
            $fetchedEncryptionKey = $rowsqlfetchencid['EncryptionKey'];
        } else {
            echo json_encode(['success' => false, 'error' => 'Encryption key not found']);
            exit;
        }

        $uniqueId = uniqid('', true);

        // Encrypt the fields JSON string
        $encryptedFields = encryptStringText($fields, $fetchedEncryptionKey);

        // Insert into cards table
        $sql = "INSERT INTO cards (UniqueId, GroupName, CardName, Fields, Notes, UserEmailId, EncryptionKeyId) VALUES (?, ?, ?, ?, ?, ?, ?)";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("ssssssi", $uniqueId, $group, $cardName, $encryptedFields, $notes, $loggedinusermailid, $fetchedEncryptionKeyVersion);
        $result = $stmt->execute();

        // Versioning
        $currentVersion = 1;

        // Insert into history
        $sqlHistory = "INSERT INTO cards_history (UniqueId, GroupName, CardName, Fields, Notes, CardVersion, EncryptionKeyId) VALUES (?, ?, ?, ?, ?, ?, ?)";
        $stmtHistory = $conn->prepare($sqlHistory);
        $stmtHistory->bind_param("ssssssi", $uniqueId, $group, $cardName, $encryptedFields, $notes, $currentVersion, $fetchedEncryptionKeyVersion);
        $resultHistory = $stmtHistory->execute();

        if ($result && $resultHistory) {
            echo json_encode(['success' => true]);
        } else {
            echo json_encode(['success' => false, 'error' => $stmt->error]);
        }
        exit;
    }

    // --------- EDIT CARD ----------
    elseif (isset($_POST['action']) && $_POST['action'] == 'edit') {
        $uniqueId = $_POST['UniqueId'];
        $fields = $_POST['Fields'];
        $notes = $_POST['Notes'];

        // Fetch old version and encryption id
        $sql = "SELECT CurrentCardVersion, EncryptionKeyId, GroupName, CardName FROM cards WHERE UniqueId = '$uniqueId'";
        $result = $conn->query($sql);
        if ($result->num_rows > 0) {
            $row = $result->fetch_assoc();
            $oldCurrentCardVersion = $row['CurrentCardVersion'];
            $oldCurrentEncryptionKeyId = $row['EncryptionKeyId'];
            $group = $row['GroupName'];
            $cardName = $row['CardName'];
        } else {
            echo json_encode(['success' => false, 'error' => 'Card not found']);
            exit;
        }

        // Get encryption key for this card
        $sqlfetchencid = "SELECT EncryptionKey FROM encryption WHERE EncryptionKeyVersion = '$oldCurrentEncryptionKeyId' AND UserEmailId = '$loggedinusermailid'";
        $resultsqlfetchencid = $conn->query($sqlfetchencid);
        if ($resultsqlfetchencid->num_rows > 0) {
            $rowenc = $resultsqlfetchencid->fetch_assoc();
            $fetchedEncryptionKey = $rowenc['EncryptionKey'];
        } else {
            echo json_encode(['success' => false, 'error' => 'Encryption key not found']);
            exit;
        }

        $modifiedCurrentCardVersion = $oldCurrentCardVersion + 1;

        // Encrypt the fields JSON string
        $encryptedFields = encryptStringText($fields, $fetchedEncryptionKey);

        // Update cards table
        $updateSql = "UPDATE cards SET Fields = ?, Notes = ?, CurrentCardVersion = ? WHERE UniqueId = ?";
        $stmt = $conn->prepare($updateSql);
        $stmt->bind_param("ssis", $encryptedFields, $notes, $modifiedCurrentCardVersion, $uniqueId);
        $result1 = $stmt->execute();

        // Insert into history table
        $sqlHistory = "INSERT INTO cards_history (UniqueId, GroupName, CardName, Fields, Notes, CardVersion, EncryptionKeyId) VALUES (?, ?, ?, ?, ?, ?, ?)";
        $stmtHistory = $conn->prepare($sqlHistory);
        $stmtHistory->bind_param("ssssssi", $uniqueId, $group, $cardName, $encryptedFields, $notes, $modifiedCurrentCardVersion, $oldCurrentEncryptionKeyId);
        $result2 = $stmtHistory->execute();

        if ($result1 && $result2) {
            echo json_encode(['success' => true]);
        } else {
            echo json_encode(['success' => false, 'error' => $stmt->error]);
        }
        exit;
    }

    // --------- DELETE CARD ----------
    elseif (isset($_POST['action']) && $_POST['action'] == 'delete') {
        $uniqueId = $_POST['UniqueId'];
        $sql = "UPDATE cards SET DeleteFlag = 1 WHERE UniqueId = '$uniqueId' AND UserEmailId = '$loggedinusermailid' ";
        if ($conn->query($sql) === TRUE) {
            echo json_encode(['success' => true]);
        } else {
            echo json_encode(['success' => false, 'message' => 'failed to delete card.']);
        }
        exit;
    }

    // --------- INVALID REQUEST ----------
    else {
        echo json_encode(['success' => false, 'message' => 'Invalid request.']);
        exit;
    }
} else {
    echo json_encode(['success' => false, 'message' => 'You need to login first to access data.']);
    exit;
}
?>
