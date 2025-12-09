
<?php
session_start();
require_once '../config/database.php';

header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'message' => 'Method not allowed']);
    exit;
}

$first_name = trim($_POST['firstname'] ?? '');
$last_name = trim($_POST['lastname'] ?? '');
$email = trim($_POST['email'] ?? '');
$phone = trim($_POST['phone'] ?? '');
$password = $_POST['password'] ?? '';
$confirm_password = $_POST['confirmPassword'] ?? '';
$membership_type = $_POST['membershipType'] ?? '';
$newsletter_signup = isset($_POST['newsletter-signup']) ? 1 : 0;

$errors = [];

// Validate input
if (empty($first_name)) {
    $errors['firstname'] = 'First name is required';
} elseif (strlen($first_name) < 2) {
    $errors['firstname'] = 'First name must be at least 2 characters';
}

if (empty($last_name)) {
    $errors['lastname'] = 'Last name is required';
} elseif (strlen($last_name) < 2) {
    $errors['lastname'] = 'Last name must be at least 2 characters';
}

if (empty($email)) {
    $errors['email'] = 'Email is required';
} elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $errors['email'] = 'Please enter a valid email address';
}

if (empty($phone)) {
    $errors['phone'] = 'Phone number is required';
} elseif (!preg_match('/^[\+]?[1-9]?[0-9]{7,15}$/', preg_replace('/\s/', '', $phone))) {
    $errors['phone'] = 'Please enter a valid phone number';
}

if (empty($password)) {
    $errors['password'] = 'Password is required';
} elseif (strlen($password) < 8) {
    $errors['password'] = 'Password must be at least 8 characters';
} elseif (!preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/', $password)) {
    $errors['password'] = 'Password must contain at least one uppercase letter, one lowercase letter, and one number';
}

if ($password !== $confirm_password) {
    $errors['confirmPassword'] = 'Passwords do not match';
}

if (empty($membership_type)) {
    $errors['membershipType'] = 'Please select a membership type';
} elseif (!in_array($membership_type, ['day-pass', 'monthly', 'annual', 'student'])) {
    $errors['membershipType'] = 'Invalid membership type selected';
}

if (!empty($errors)) {
    echo json_encode(['success' => false, 'errors' => $errors]);
    exit;
}

try {
    // Check if email already exists
    $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ?");
    $stmt->execute([$email]);
    if ($stmt->fetch()) {
        echo json_encode(['success' => false, 'message' => 'An account with this email already exists']);
        exit;
    }

    // Hash password
    $password_hash = password_hash($password, PASSWORD_DEFAULT);

    // Insert new user
    $insertStmt = $pdo->prepare("
        INSERT INTO users (first_name, last_name, email, phone, password_hash, membership_type, newsletter_signup, created_at, updated_at, is_active) 
        VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), NOW(), 1)
    ");
    
    $insertStmt->execute([
        $first_name,
        $last_name,
        $email,
        $phone,
        $password_hash,
        $membership_type,
        $newsletter_signup
    ]);

    $user_id = $pdo->lastInsertId();

    // Set session variables
    $_SESSION['user_id'] = $user_id;
    $_SESSION['user_email'] = $email;
    $_SESSION['user_name'] = $first_name . ' ' . $last_name;

    // Send welcome email (optional - you can implement this later)
    // sendWelcomeEmail($email, $first_name);

    echo json_encode([
        'success' => true,
        'message' => 'Account created successfully! Welcome to ToKa Fitness, ' . $first_name . '!',
        'redirect' => '../dashboard.html' // Change this to your dashboard page
    ]);

} catch (PDOException $e) {
    error_log("Database error: " . $e->getMessage());
    echo json_encode(['success' => false, 'message' => 'An error occurred while creating your account. Please try again.']);
}
?>

