
<?php
session_start();

// Clear remember me cookie if it exists
if (isset($_COOKIE['remember_token'])) {
    setcookie('remember_token', '', time() - 3600, '/', '', false, true);
}

// Destroy session
session_destroy();

// Redirect to sign-in page
header('Location: ../pages/sign-in.html');
exit;
?>

