<?php
date_default_timezone_set('America/Chicago');

// Fetch data from config file

    $file = '../config.env'; // Path to config file
    $lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

    foreach ($lines as $line) {
        $parts = explode('=', $line, 2); 
        if (count($parts) == 2) {
            $key = trim($parts[0]); 
            $value = trim($parts[1], '"'); // Remove quotes if present

            global $$key; // Declare the dynamic variable as global
            $$key = $value; // Set its value
        }
    }

    $conn = new mysqli($DB_HOST, $DB_USER, $DB_PASS, $DB_NAME);
        if ($conn->connect_error) {
            die("Connection failed: " . $conn->connect_error);
        }

    $conn1 = new mysqli($DB_HOST, $DB_USER, $DB_PASS, $DB_NAME1);
        if ($conn1->connect_error) {
            die("Connection failed: " . $conn1->connect_error);
        }
?>