<?php   
error_reporting(E_ALL ^ E_WARNING);
error_reporting(E_ERROR | E_PARSE);
?>

<?php
// Database connection 
include "sql_conn.php";
include 'myfunctions.php';

// Check if the user is logged in; if not, redirect to the login page
if (!isset($_SESSION['passed_user_email'])) {
    header("Location: ../login.html");
    exit();
}

$userEmail = DecryptSessionsandCookies($_SESSION['passed_user_email']);

// Get the requested file ID from the query string
if (!isset($_GET['file_id'])) {
    die('Invalid request');
}

$fileId = $_GET['file_id'];

// Fetch the file metadata from the database using MySQLi
$stmt = $conn->prepare('SELECT exported_file_name, exported_file_path FROM user_exported_files WHERE UniqueId = ? AND UserEmailId = ?');
if ($stmt) {
    // Bind the parameters
    $stmt->bind_param('ss', $fileId, $userEmail);

    // Execute the query
    $stmt->execute();

    // Bind the result variables
    $stmt->bind_result($exportedFileName, $exportedFilePath);

    // Fetch the result
    if ($stmt->fetch()) {
        // Security: Ensure file exists and is inside allowed directory
        if (!file_exists($exportedFilePath)) {
            die('File no longer exists on the server.');
        }
        // Serve the file for download
        header('Content-Description: File Transfer');
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . basename($exportedFileName) . '"');
        header('Content-Length: ' . filesize($exportedFilePath));
        header('Pragma: public');
        header('Cache-Control: must-revalidate, post-check=0, pre-check=0');
        header('Expires: 0');

        // Output the file content
        readfile($exportedFilePath);
        exit;
    } else {
        die('File not found or access denied');
    }
    $stmt->close();
} else {
    die('Error preparing statement: ' . $conn->error);
}
?>
