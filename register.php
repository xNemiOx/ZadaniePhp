<?php
require_once 'database.php';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $name = $_POST['name'] ?? '';
    $phone = $_POST['phone'] ?? '';
    $email = $_POST['email'] ?? '';
    $password = $_POST['password'] ?? '';
    $correctPassword = $_POST['correctPassword'] ?? '';

    if (strlen($password) < 6) {
        $error = 'Новый пароль должен содержать не менее 6 символов';
    } elseif ($password !== $correctPassword) {
        $error = 'Пароли не совпадают';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = 'Неверный формат адреса электронной почты';
    } elseif (!preg_match('/^\+?[1-9]\d{10,14}$/', $phone)) {
        $error = 'Неверный формат номера телефона';
    } else {

        // Проверка на то, существует ли пользователь с таким именем, email или телефоном
        $stmt = $mysqli->prepare("SELECT * FROM user WHERE name = ? OR email = ? OR phone = ?");
        $stmt->bind_param('sss', $name, $email, $phone);
        $stmt->execute();
        $result = $stmt->get_result();
        $user = $result->fetch_assoc();

        if ($user) {
            if ($user['name'] === $name) {
                $error = 'Пользователь с таким именем уже существует';
            } elseif ($user['email'] === $email) {
                $error = 'Пользователь с таким адресом электронной почты уже существует';
            } elseif ($user['phone'] === $phone) {
                $error = 'Пользователь с таким номером телефона уже существует';
            }
        } else {
            $hashedPassword = password_hash($password, PASSWORD_BCRYPT);

            $query = "INSERT INTO user (name, phone, email, password) 
                    VALUES ('$name', '$phone', '$email', '$hashedPassword')";
            $result = mysqli_query($mysqli, $query);

            if ($result) {
                header('Location: login.php');
                exit;
            } else {
                $error = 'Не удалось сохранить пользователя. Попробуйте снова.';
            }
        }
    }
}
?>

<!DOCTYPE html>
<html lang="ru">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Регистрация</title>
    <link rel="stylesheet" href="styles.css">
    <style>
        .password-toggle {
            cursor: pointer;
            font-size: 14px;
            color: #007BFF;
            border: none;
            background: none;
            padding: 0;
            margin: 0;
        }
    </style>
</head>

<body>
    <div class="container">
        <div class="reg">
            <h1>Регистрация</h1>
        </div>
        <?php if (isset($error)): ?>
            <p class="error"><?= htmlspecialchars($error) ?></p>
        <?php endif; ?>
        <form method="POST">
            <div class="string">
                <input type="text" name="name" placeholder="Имя" required>
                <input type="text" name="phone" placeholder="Номер телефона" required>
                <input type="email" name="email" placeholder="Электронная почта" required>
            </div>
            <div class="string">
                <input type="password" id="password" name="password" placeholder="Пароль" required>
                <input type="password" id="correctPassword" name="correctPassword" placeholder="Подтверждение пароля" required>
                <button type="button" id="showHideBtn" onclick="togglePasswordVisibility()">Показать пароли</button>
            </div>
            <div class="reg">
                <button type="submit">Зарегистрироваться</button>
                <p>Уже есть аккаунт? <a href="login.php">Войти</a></p>
            </div>
        </form>
    </div>

    <script>
        function togglePasswordVisibility() {
            var password = document.getElementById("password");
            var correctPassword = document.getElementById("correctPassword");
            var showHideBtn = document.getElementById("showHideBtn");

            if (password.type === "password" && correctPassword.type === "password") {
                password.type = "text";
                correctPassword.type = "text";
                showHideBtn.textContent = "Скрыть пароли";
            } else {
                password.type = "password";
                correctPassword.type = "password";
                showHideBtn.textContent = "Показать пароли";
            }
        }
    </script>
</body>

</html>

<style>
    .container {
        max-width: 600px;
        margin: 0 auto;
        padding: 20px;
        box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
        border-radius: 8px;
        background: #fff;
    }

    .string {
        margin-bottom: 15px;
    }

    .reg {
        margin-top: 40px;
        justify-content: center;
        display: flex;
        flex-direction: column;
        align-items: center;
    }
</style>
