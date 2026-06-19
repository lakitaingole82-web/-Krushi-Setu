<?php
include 'configure.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['rsubmit'])) {
  $rname = trim($_POST['rname'] ?? '');
  $rmail = trim($_POST['rmail'] ?? '');
  $rpass = $_POST['rpass'] ?? '';
  $rcpass = $_POST['rcpass'] ?? '';

  if ($rname === '' || $rmail === '' || $rpass === '' || $rcpass === '') {
    echo "<script>alert('Please fill in all fields.'); window.history.back();</script>";
    exit();
  }

  if ($rpass !== $rcpass) {
    echo "<script>alert('Passwords do not match.'); window.history.back();</script>";
    exit();
  }

  $hashedPassword = password_hash($rpass, PASSWORD_DEFAULT);

  $stmt = $conn->prepare('INSERT INTO users (username, email, password) VALUES (?, ?, ?)');
  if ($stmt) {
    $stmt->bind_param('sss', $rname, $rmail, $hashedPassword);
    if ($stmt->execute()) {
      echo "<script>
              alert('You are now registered.');
              window.location.href='../LoginIndex.html';
            </script>";
      $stmt->close();
      exit();
    }
    $stmt->close();
  }

  echo "<script>alert('Registration failed. Please try again.'); window.history.back();</script>";
  exit();
}
?>
