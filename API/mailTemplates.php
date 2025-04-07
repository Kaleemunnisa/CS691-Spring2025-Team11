<?php
error_reporting(E_ALL ^ E_WARNING);
error_reporting(E_ERROR | E_PARSE);

header('Content-Type: application/json');

// Database connection 
include "sql_conn.php";
include 'myfunctions.php';

if (!isset($_SESSION['passed_user_email'])) {
    echo json_encode(['success' => false, 'message' => 'You need to login first to access data.']);
    exit;
}

$loggedinusermailid = DecryptSessionsandCookies($_SESSION['passed_user_email']);

// Read input JSON
$input = json_decode(file_get_contents("php://input"), true);

// Load Message Templates
if (isset($input['loadMessageTemplates']) && $input['loadMessageTemplates'] === true) {
    $sql = "SELECT * FROM mail_templates";
    $result = $conn->query($sql);

    $data = [];
    if ($result->num_rows > 0) {
        while ($row = $result->fetch_assoc()) {
            $data[] = [
                "MessageTemplateID" => $row['id'],
                "MessageTemplateName" => $row['TemplateName'],
                "MessageTemplateSubject" => $row['Subject'],
                "MessageTemplateHeader" => $row['Header'],
                "MessageTemplateBody" => $row['Body1'],
                "MessageTemplateBannerUrl" => $row['BannerUrl'],
                "MessageTemplateSupportMailAddress" => $row['SupportMailAddress'],
                "MessageTemplateLoginPageUrl" => $row['LoginPageUrl'],
                "MessageTemplateDocumentationUrl" => $row['DocumentationUrl'],
                "MessageTemplateStatus" => (int)$row['DeleteFlag'] // Ensure it's an integer
            ];
        }
        echo json_encode(["success" => true, "message" => "Data fetched successfully.", "data" => $data]);
    } else {
        echo json_encode(["success" => true, "message" => "No data found.", "data" => []]);
    }
    exit;
}
// Placeholder for future API actions
if (isset($input['newMessageTemplate']) && $input['newMessageTemplate'] === true) {
    
    // Sanitize inputs
    $FetchedTemplateName = trim($input['MessageTemplateName']);
    $FetchedTemplateSubject = trim($input['MessageTemplateSubject']);
    $FetchedTemplateHeader = trim($input['MessageTemplateHeader']);
    $FetchedTemplateBody = trim($input['MessageTemplateBody']);
    $FetchedTemplateBannerUrl = trim($input['MessageTemplateBannerUrl']);
    $FetchedTemplateSupportMailAddress = trim($input['MessageTemplateSupportMailAddress']);
    $FetchedTemplateLoginPageUrl = trim($input['MessageTemplateLoginPageUrl']);
    $FetchedTemplateDocumentationUrl = trim($input['MessageTemplateDocumentationUrl']);

    // Check if template with the same name exists
    $sqlCheckTemplate = "SELECT COUNT(*) as count FROM mail_templates WHERE TemplateName = ?";
    $stmt = $conn->prepare($sqlCheckTemplate);
    $stmt->bind_param("s", $FetchedTemplateName);
    $stmt->execute();
    $resultCheckTemplate = $stmt->get_result();
    $stmt->close();

    if ($resultCheckTemplate && ($row = $resultCheckTemplate->fetch_assoc())) {
        $recordCount = $row['count'];

        if ($recordCount <= 0) {
            // Insert new template
            $currentTimestamp = date('Y-m-d H:i:s');

            $sqlInsert = "INSERT INTO mail_templates (TemplateName, Subject, Header, Body1, BannerUrl, SupportMailAddress, LoginPageUrl, DocumentationUrl, Last_modified_on, Last_modified_by) 
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
            $stmtInsert = $conn->prepare($sqlInsert);
            $stmtInsert->bind_param("ssssssssss", $FetchedTemplateName, $FetchedTemplateSubject, $FetchedTemplateHeader, $FetchedTemplateBody, 
                                    $FetchedTemplateBannerUrl, $FetchedTemplateSupportMailAddress, $FetchedTemplateLoginPageUrl, $FetchedTemplateDocumentationUrl, $currentTimestamp, $loggedinusermailid);

            if ($stmtInsert->execute()) {
                echo json_encode(["success" => true, "message" => "newMessageTemplateStatus=true"]);
            } else {
                echo json_encode(["success" => false, "message" => "newMessageTemplateStatus=false", "error" => $stmtInsert->error]);
            }

            $stmtInsert->close();
        } else {
            echo json_encode(["success" => false, "message" => "Error: Template with the same name already exists"]);
        }
    } else {
        echo json_encode(["success" => false, "message" => "Database error", "error" => $conn->error]);
    }
    exit;
}
elseif (isset($input['saveMessageTemplate']) && $input['saveMessageTemplate'] === true) {

    // Sanitize inputs
    $FetchedTemplateID = trim($input['MessageTemplateID']);
    $FetchedTemplateName = trim($input['MessageTemplateName']);
    $FetchedTemplateSubject = trim($input['MessageTemplateSubject']);
    $FetchedTemplateHeader = trim($input['MessageTemplateHeader']);
    $FetchedTemplateBody = trim($input['MessageTemplateBody']);
    $FetchedTemplateBannerUrl = trim($input['MessageTemplateBannerUrl']);
    $FetchedTemplateSupportMailAddress = trim($input['MessageTemplateSupportMailAddress']);
    $FetchedTemplateLoginPageUrl = trim($input['MessageTemplateLoginPageUrl']);
    $FetchedTemplateDocumentationUrl = trim($input['MessageTemplateDocumentationUrl']);

    $currentTimestamp = date('Y-m-d H:i:s');

    $updateSql = "UPDATE mail_templates SET 
                    TemplateName = ?, 
                    Subject = ?, 
                    Header = ?, 
                    Body1 = ?, 
                    BannerUrl = ?, 
                    SupportMailAddress = ?, 
                    LoginPageUrl = ?, 
                    DocumentationUrl = ?, 
                    Last_modified_on = ?, 
                    Last_modified_by = ? 
                WHERE id = ?";

    $stmtUpdate = $conn->prepare($updateSql);
    $stmtUpdate->bind_param("ssssssssssi", 
            $FetchedTemplateName, $FetchedTemplateSubject, $FetchedTemplateHeader, $FetchedTemplateBody, $FetchedTemplateBannerUrl, $FetchedTemplateSupportMailAddress, $FetchedTemplateLoginPageUrl, $FetchedTemplateDocumentationUrl, $currentTimestamp, $loggedinusermailid, $FetchedTemplateID);

    $resultUpdateSql = $stmtUpdate->execute();
    if ($stmtUpdate->execute()) {
        echo json_encode(["success" => true, "message" => "saveMessageTemplateStatus=true"]);
    } else {
        echo json_encode(["success" => false, "message" => "saveMessageTemplateStatus=false", "error" => $stmtUpdate->error]);
    }

    $stmtUpdate->close();

    exit;
}
elseif (isset($input['deleteMessageTemplate']) && $input['deleteMessageTemplate'] === true) {
    echo json_encode(["success" => false, "message" => "Deleting template not implemented yet."]);
}
else {
    echo json_encode(["success" => false, "message" => "Invalid request."]);
}
?>
