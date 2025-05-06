<?php
error_reporting(E_ALL ^ E_WARNING);
error_reporting(E_ERROR | E_PARSE);

include "sql_conn.php";
include 'myfunctions.php';

header('Content-Type: application/json');

// --- Auth Check ---
if (!isset($_SESSION['passed_user_email'])) {
    echo json_encode(['success' => false, 'message' => 'not_logged_in']);
    exit;
}
$userEmail = DecryptSessionsandCookies($_SESSION['passed_user_email']);

// --- Encryption Helpers ---
function get_latest_encryption_key($conn, $userEmail) {
    $sql = "SELECT EncryptionKey, EncryptionKeyVersion FROM encryption WHERE UserEmailId = ? ORDER BY EncryptionKeyVersion DESC LIMIT 1";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("s", $userEmail);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($row = $result->fetch_assoc()) {
        return [$row['EncryptionKey'], $row['EncryptionKeyVersion']];
    }
    return [null, null];
}

// --- ACTION SWITCH ---
$action = $_POST['action'] ?? ($_POST['fetchnotesdata'] === 'true' ? 'fetch' : '');

if ($action === 'fetch') {
    $addresses = [];
    $stmt = $conn->prepare("SELECT * FROM address_book WHERE UserEmailId=? AND DeleteFlag=0 ORDER BY datecreated DESC");
    $stmt->bind_param("s", $userEmail);
    $stmt->execute();
    $result = $stmt->get_result();

    while ($row = $result->fetch_assoc()) {
        // --- Decrypt Fields JSON ---
        $fieldsDecrypted = $row['Fields'];
        if (!empty($row['EncryptionKeyId']) && !empty($row['Fields'])) {
            // Fetch encryption key
            $sqlKey = "SELECT EncryptionKey FROM encryption WHERE UserEmailId = ? AND EncryptionKeyVersion = ?";
            $stmtKey = $conn->prepare($sqlKey);
            $stmtKey->bind_param("si", $userEmail, $row['EncryptionKeyId']);
            $stmtKey->execute();
            $resKey = $stmtKey->get_result();
            if ($keyRow = $resKey->fetch_assoc()) {
                $fieldsDecrypted = decryptStringText($row['Fields'], $keyRow['EncryptionKey']);
            }
        }
        $addresses[] = [
            'UniqueId' => $row['UniqueId'],
            'GroupName' => $row['GroupName'],
            'FirstName' => $row['FirstName'],
            'LastName' => $row['LastName'],
            'Fields' => json_decode($fieldsDecrypted, true) ?: [], // Send as array
            'Notes' => $row['Notes'],
            'ColourGroup' => $row['ColourGroup'],
            'CurrentAddressVersion' => $row['CurrentAddressVersion'],
            'datecreated' => $row['datecreated'],
        ];
    }
    echo json_encode(['success' => true, 'data' => $addresses]);
    exit;
}

// --- ADD ADDRESS ---
if ($action === 'add') {
    $uniqueId = uniqid('', true);
    $groupName = trim($_POST['GroupName']);
    $firstName = trim($_POST['FirstName']);
    $lastName = trim($_POST['LastName']);
    $fields = trim($_POST['Fields']);
    $notes = trim($_POST['Notes']);
    $colourGroup = trim($_POST['ColourGroup']);

    // Encrypt Fields JSON
    list($encryptionKey, $encryptionKeyId) = get_latest_encryption_key($conn, $userEmail);
    if (!$encryptionKey || !$encryptionKeyId) {
        echo json_encode(['success' => false, 'message' => 'Encryption key missing']);
        exit;
    }
    $fieldsEncrypted = encryptStringText($fields, $encryptionKey);

    // Insert main record
    $stmt = $conn->prepare("INSERT INTO address_book 
        (UniqueId, GroupName, FirstName, LastName, Fields, Notes, ColourGroup, UserEmailId, EncryptionKeyId) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
    $stmt->bind_param("ssssssssi", $uniqueId, $groupName, $firstName, $lastName, $fieldsEncrypted, $notes, $colourGroup, $userEmail, $encryptionKeyId);
    $result = $stmt->execute();

    // Insert into history
    if ($result) {
        $currentVersion = 1;
        $stmtHist = $conn->prepare("INSERT INTO address_book_history 
            (UniqueId, GroupName, FirstName, LastName, Fields, Notes, ColourGroup, AddressVersion, EncryptionKeyId, AddressBookID) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
        $stmtHist->bind_param("sssssssisi", $uniqueId, $groupName, $firstName, $lastName, $fieldsEncrypted, $notes, $colourGroup, $currentVersion, $encryptionKeyId, $uniqueId);
        $stmtHist->execute();
        echo json_encode(['success' => true, 'message' => 'Address added', 'id' => $uniqueId]);
    } else {
        echo json_encode(['success' => false, 'message' => $stmt->error]);
    }
    exit;
}

// --- EDIT ADDRESS ---
if ($action === 'edit') {
    $uniqueId = $_POST['UniqueId'];
    $groupName = trim($_POST['GroupName']);
    $firstName = trim($_POST['FirstName']);
    $lastName = trim($_POST['LastName']);
    $notes = trim($_POST['Notes']);
    $colourGroup = trim($_POST['ColourGroup']);
    $fields = trim($_POST['Fields']);

    // Get current version and EncryptionKeyId
    $stmt = $conn->prepare("SELECT CurrentAddressVersion, EncryptionKeyId FROM address_book WHERE UniqueId = ? AND UserEmailId = ?");
    $stmt->bind_param("ss", $uniqueId, $userEmail);
    $stmt->execute();
    $stmt->bind_result($oldVersion, $oldEncryptionKeyId);
    $stmt->fetch();
    $stmt->close();

    if (!$oldVersion) $oldVersion = 1;
    if (!$oldEncryptionKeyId) {
        // fallback to latest key
        list(, $oldEncryptionKeyId) = get_latest_encryption_key($conn, $userEmail);
    }

    // Fetch encryption key
    $sqlKey = "SELECT EncryptionKey FROM encryption WHERE UserEmailId = ? AND EncryptionKeyVersion = ?";
    $stmtKey = $conn->prepare($sqlKey);
    $stmtKey->bind_param("si", $userEmail, $oldEncryptionKeyId);
    $stmtKey->execute();
    $resKey = $stmtKey->get_result();
    $keyRow = $resKey->fetch_assoc();
    $encryptionKey = $keyRow ? $keyRow['EncryptionKey'] : '';

    // Encrypt fields
    $fieldsEncrypted = encryptStringText($fields, $encryptionKey);

    $newVersion = $oldVersion + 1;

    // Update address_book
    $stmt = $conn->prepare("UPDATE address_book SET 
        GroupName=?, FirstName=?, LastName=?, Notes=?, ColourGroup=?, Fields=?, CurrentAddressVersion=? 
        WHERE UniqueId=? AND UserEmailId=? AND DeleteFlag=0");
    $stmt->bind_param("ssssssiss", $groupName, $firstName, $lastName, $notes, $colourGroup, $fieldsEncrypted, $newVersion, $uniqueId, $userEmail);
    $result = $stmt->execute();

    // Insert into address_book_history
    $stmtHist = $conn->prepare("INSERT INTO address_book_history 
        (UniqueId, GroupName, FirstName, LastName, Fields, Notes, ColourGroup, AddressVersion, EncryptionKeyId, AddressBookID) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
    $stmtHist->bind_param("sssssssisi", $uniqueId, $groupName, $firstName, $lastName, $fieldsEncrypted, $notes, $colourGroup, $newVersion, $oldEncryptionKeyId, $uniqueId);
    $stmtHist->execute();

    if ($result) {
        echo json_encode(['success' => true, 'message' => 'Address updated']);
    } else {
        echo json_encode(['success' => false, 'message' => $stmt->error]);
    }
    exit;
}

// --- DELETE ADDRESS ---
if ($action === 'delete') {
    $uniqueId = $_POST['UniqueId'];
    $stmt = $conn->prepare("UPDATE address_book SET DeleteFlag=1 WHERE UniqueId=? AND UserEmailId=?");
    $stmt->bind_param("ss", $uniqueId, $userEmail);
    $result = $stmt->execute();

    if ($result) {
        echo json_encode(['success' => true, 'message' => 'Address deleted']);
    } else {
        echo json_encode(['success' => false, 'message' => $stmt->error]);
    }
    exit;
}

// --- Invalid API Call ---
echo json_encode(['success' => false, 'message' => 'Invalid API call']);
exit;
?>
