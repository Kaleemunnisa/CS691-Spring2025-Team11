<?php
include "sql_conn.php";
include 'myfunctions.php';
header('Content-Type: application/json');

// Check if user is logged in
if (isset($_SESSION['passed_user_email'])) {

    $userEmail = DecryptSessionsandCookies($_SESSION['passed_user_email']);
    $type = $_POST['type'] ?? '';
    $passwordId = $_POST['passwordId'] ?? '';
    $shareVaultType = $_POST['vaultType'];

    if (!$type || !$passwordId) {
        echo json_encode(['error' => 'Missing required data']);
        exit;
    }

    if ($type === 'internal') {
        // Share internally by email
        $shareUUID = uniqid("share_", true);
        $targetEmail = $_POST['email'] ?? '';
        if (!$targetEmail) {
            echo json_encode(['error' => 'No target email provided']);
            exit;
        }

        // Check if target user exists
        $checkStmt = $conn->prepare("SELECT 1 FROM users WHERE EmailId = ? LIMIT 1");
        $checkStmt->bind_param("s", $targetEmail);
        $checkStmt->execute();
        $checkStmt->store_result();

        if ($checkStmt->num_rows === 0) {
            echo json_encode(['error' => 'Target email not found']);
            exit;
        }

        // Insert internal share
        $stmt = $conn->prepare("INSERT INTO shared_account (owner_email, target_email, share_uuid, account_id, shared_type, vault_type)
                                VALUES (?, ?, ?, ?, 'internal', ?)");
        $stmt->bind_param("sssss", $userEmail, $targetEmail, $shareUUID, $passwordId, $shareVaultType);
        $stmt->execute();

        echo json_encode(['success' => true]);
        exit;

    } elseif ($type === 'external') {
        // Share externally
        $shareUUID = uniqid("share_", true);
        $noExpiry = $_POST['noExpiry'] === 'true' ? 1 : 0;
        $expiry = $_POST['expiry'] ?? NULL;

        if (!$noExpiry && !$expiry) {
            echo json_encode(['error' => 'Expiry required if noExpiry is not set']);
            exit;
        }

        if ($expiry == NULL) {
            // Insert external share
            $stmt = $conn->prepare("INSERT INTO shared_account (owner_email, account_id, share_uuid, shared_type, no_expiry, vault_type)
            VALUES (?, ?, ?, 'external', ?, ?)");
            $stmt->bind_param("sssis", $userEmail, $passwordId, $shareUUID, $noExpiry, $shareVaultType);
        }
        else {
            // Insert external share
            $stmt = $conn->prepare("INSERT INTO shared_account (owner_email, account_id, share_uuid, shared_type, no_expiry, expiry_at, vault_type)
                                    VALUES (?, ?, ?, 'external', ?, ?, ?)");
            $stmt->bind_param("sssiss", $userEmail, $passwordId, $shareUUID, $noExpiry, $expiry, $shareVaultType);
        }

        $stmt->execute();

        echo json_encode(['share_uuid' => $shareUUID]);
        exit;

    } else {
        echo json_encode(['error' => 'Invalid share type']);
        exit;
    }
}
else {
    echo json_encode(['success' => false, 'message' => 'You need to login first to access data.']);
    exit;
}
?>