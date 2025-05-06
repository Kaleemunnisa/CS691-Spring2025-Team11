<?php
error_reporting(E_ALL ^ E_WARNING);
error_reporting(E_ERROR | E_PARSE);

include "sql_conn.php";
include 'myfunctions.php';

session_start();
header('Content-Type: application/json');

if (!isset($_SESSION['passed_user_email'])) {
    echo json_encode(["success" => false, "message" => "Unauthorized"]);
    exit;
}

$email = DecryptSessionsandCookies($_SESSION['passed_user_email']);
$type = $_POST['vault_type'] ?? '';
$id = $_POST['id'] ?? '';

if (!$type || !$id) {
    echo json_encode(["success" => false, "message" => "Missing type or ID"]);
    exit;
}

$data = null;

switch ($type) {
    case 'password':
        $stmt = $conn->prepare("SELECT GroupName, AppName, UserName, Password, Url, Notes, EncryptionKeyId FROM vault WHERE UniqueId = ? AND UserEmailId = ? AND DeleteFlag = 1");
        $stmt->bind_param("ss", $id, $email);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows === 0) {
            echo json_encode(["success" => false, "message" => "Item not found"]);
            exit;
        }

        $row = $result->fetch_assoc();
        $encryptionKeyId = $row['EncryptionKeyId'];

        // Fetch EncryptionKey
        $encryptionKey = null;
        if ($encryptionKeyId) {
            $keyStmt = $conn->prepare("SELECT EncryptionKey FROM encryption WHERE EncryptionKeyVersion = ? AND UserEmailId = ?");
            $keyStmt->bind_param("is", $encryptionKeyId, $email);
            $keyStmt->execute();
            $keyResult = $keyStmt->get_result();
            if ($keyResult->num_rows > 0) {
                $encryptionKey = $keyResult->fetch_assoc()['EncryptionKey'];
            }
        }

        // Decrypt password if key available
        $decryptedPassword = $encryptionKey ? decryptString($row['Password'], $encryptionKey) : 'Decryption Failed';

        $data = [
            "GroupName" => $row['GroupName'],
            "AppName" => $row['AppName'],
            "UserName" => $row['UserName'],
            "Password" => $decryptedPassword,
            "Url" => $row['Url'],
            "Notes" => $row['Notes']
        ];
        break;

    case 'note':
        $stmt = $conn->prepare("SELECT GroupName, Title, Notes FROM notes WHERE UniqueId = ? AND UserEmailId = ? AND DeleteFlag = 1");
        $stmt->bind_param("ss", $id, $email);
        $stmt->execute();
        $result = $stmt->get_result();
        if ($result->num_rows === 0) {
            echo json_encode(["success" => false, "message" => "Item not found"]);
            exit;
        }
        $data = $result->fetch_assoc();
        break;

    case 'contact':
        $stmt = $conn->prepare("SELECT GroupName, FirstName, LastName, Notes FROM address_book WHERE UniqueId = ? AND UserEmailId = ? AND DeleteFlag = 1");
        $stmt->bind_param("ss", $id, $email);
        $stmt->execute();
        $result = $stmt->get_result();
        if ($result->num_rows === 0) {
            echo json_encode(["success" => false, "message" => "Item not found"]);
            exit;
        }
        $data = $result->fetch_assoc();
        break;

    case 'card':
        $stmt = $conn->prepare("SELECT Fields, Notes FROM cards WHERE UniqueId = ? AND UserEmailId = ? AND DeleteFlag = 1");
        $stmt->bind_param("ss", $id, $email);
        $stmt->execute();
        $result = $stmt->get_result();
        if ($result->num_rows === 0) {
            echo json_encode(["success" => false, "message" => "Item not found"]);
            exit;
        }
        $row = $result->fetch_assoc();
        $row['Fields'] = json_decode($row['Fields'], true) ?? [];
        $data = $row;
        break;

    default:
        echo json_encode(["success" => false, "message" => "Invalid vault type"]);
        exit;
}

echo json_encode(["success" => true, "data" => $data]);
