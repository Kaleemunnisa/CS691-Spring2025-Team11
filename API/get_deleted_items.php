<?php   
error_reporting(E_ALL ^ E_WARNING);
error_reporting(E_ERROR | E_PARSE);

// Database connection 
include "sql_conn.php";
include 'myfunctions.php';

header('Content-Type: application/json');

if (!isset($_SESSION['passed_user_email'])) {
    echo json_encode(["success" => false, "message" => "Unauthorized"]);
    exit;
}

$email = DecryptSessionsandCookies($_SESSION['passed_user_email']);
$action = $_POST['action'] ?? '';

function respond($success, $data = null, $message = '') {
    echo json_encode([
        "success" => $success,
        "data" => $data,
        "message" => $message
    ]);
    exit;
}

// Fetch all deleted items
if ($action === 'fetch') {
    $results = [];

    // Passwords
    $stmt = $conn->prepare("SELECT UniqueId, AppName FROM vault WHERE DeleteFlag = 1 AND UserEmailId = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $res = $stmt->get_result();
    while ($row = $res->fetch_assoc()) {
        $results[] = [
            "account_id" => $row['UniqueId'],
            "vault_type" => "password",
            "account_name" => $row['AppName']
        ];
    }

    // Contacts
    $stmt = $conn->prepare("SELECT UniqueId, FirstName, LastName FROM address_book WHERE DeleteFlag = 1 AND UserEmailId = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $res = $stmt->get_result();
    while ($row = $res->fetch_assoc()) {
        $results[] = [
            "account_id" => $row['UniqueId'],
            "vault_type" => "contact",
            "account_name" => trim($row['FirstName'] . ' ' . $row['LastName'])
        ];
    }

    // Notes
    $stmt = $conn->prepare("SELECT UniqueId, Title FROM notes WHERE DeleteFlag = 1 AND UserEmailId = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $res = $stmt->get_result();
    while ($row = $res->fetch_assoc()) {
        $results[] = [
            "account_id" => $row['UniqueId'],
            "vault_type" => "note",
            "account_name" => $row['Title'] ?? "(Untitled)"
        ];
    }

    // Cards
    $stmt = $conn->prepare("SELECT UniqueId, CardName FROM cards WHERE DeleteFlag = 1 AND UserEmailId = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $res = $stmt->get_result();
    while ($row = $res->fetch_assoc()) {
        $results[] = [
            "account_id" => $row['UniqueId'],
            "vault_type" => "card",
            "account_name" => $row['CardName']
        ];
    }

    respond(true, $results);
}

// Restore item
if ($action === 'restore') {
    $account_id = $_POST['account_id'] ?? '';
    $type = $_POST['vault_type'] ?? '';
    $map = [
        "password" => ["vault", "UniqueId"],
        "contact" => ["address_book", "UniqueId"],
        "note" => ["notes", "UniqueId"],
        "card" => ["cards", "UniqueId"]
    ];

    if (!isset($map[$type])) respond(false, null, "Invalid vault type");

    [$table, $idCol] = $map[$type];
    $stmt = $conn->prepare("UPDATE $table SET DeleteFlag = 0 WHERE $idCol = ? AND UserEmailId = ?");
    $stmt->bind_param("ss", $account_id, $email);
    $success = $stmt->execute();
    respond($success);
}

// Permanently delete item
if ($action === 'delete') {
    $account_id = $_POST['account_id'] ?? '';
    $type = $_POST['vault_type'] ?? '';
    $map = [
        "password" => ["vault", "UniqueId"],
        "contact" => ["address_book", "UniqueId"],
        "note" => ["notes", "UniqueId"],
        "card" => ["cards", "UniqueId"]
    ];

    if (!isset($map[$type])) respond(false, null, "Invalid vault type");

    [$table, $idCol] = $map[$type];
    $stmt = $conn->prepare("DELETE FROM $table WHERE $idCol = ? AND UserEmailId = ?");
    $stmt->bind_param("ss", $account_id, $email);
    $success = $stmt->execute();
    respond($success);
}

respond(false, null, "Invalid action");
