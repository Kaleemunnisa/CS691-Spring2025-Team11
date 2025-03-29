<?php

// Database connection (replace with your credentials)
    $servername = "";
    $username = "";
    $password = "";
    $dbname = "password_manager";

    $conn = new mysqli($servername, $username, $password, $dbname);
        if ($conn->connect_error) {
            die("Connection failed: " . $conn->connect_error);
        }

    $conn1 = new mysqli($servername, $username, $password);
        if ($conn1->connect_error) {
            die("Connection failed: " . $conn1->connect_error);
        }
?>