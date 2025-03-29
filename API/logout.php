<?php

  // User is logged in, perform logout
  session_unset(); // Unset all session variables
  session_destroy(); // Destroy the session
  unset($_COOKIE['user_login']); // Unset COOKIE user_login
  setcookie('user_login', '', -1, '/');  // Destroy the COOKIE

// Redirect the user to the login page
header("Location: ../index.html");
exit();
?>