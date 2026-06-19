<?php 

include 'configure.php';
session_start();

if (isset($_POST['submit'])) {
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';

    if (empty($email) || empty($password)) {
        header("Location: ../LoginIndex.html?error=empty_fields");
        exit();
    }

    // Prepare the SQL statement to prevent SQL injection
    $stmt = $conn->prepare("SELECT * FROM users WHERE email = ?");
    if (!$stmt) {
        header("Location: ../LoginIndex.html?error=database_error");
        exit();
    }

    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        $row = mysqli_fetch_assoc($result);
        if (password_verify($password, $row['password'])) {
            $_SESSION['username'] = $row['username'];
            session_regenerate_id(true);
            $stmt->close();
            header("Location: ../html/index.html");
            exit();
        }
    }
    
    $stmt->close();
    header("Location: ../LoginIndex.html?error=invalid_credentials");
    exit();
}
?>
