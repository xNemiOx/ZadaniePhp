<?php
session_start();
require_once 'database.php';


if (!isset($_SESSION['user'])) {
    header('Location: login.php');
    exit;
}

$user = $_SESSION['user'];
$error = '';
$success = '';
$editMode = isset($_GET['edit']) && $_GET['edit'] == 'true';

function validateCurrentPassword($inputPassword, $userPasswordHash)
{
    return password_verify($inputPassword, $userPasswordHash);
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $name = $_POST['name'] ?? '';
    $phone = $_POST['phone'] ?? '';
    $email = $_POST['email'] ?? '';
    $oldPassword = $_POST['oldPassword'] ?? '';
    $newPassword = $_POST['newPassword'] ?? '';
    $confirmPassword = $_POST['confirmPassword'] ?? '';

    $login = filter_var($login, FILTER_SANITIZE_EMAIL);

    // Валидация данных
    if (strlen($newPassword) > 0 && strlen($newPassword) < 6) {
        $error = 'Новый пароль должен содержать не менее 6 символов';
    } elseif ($newPassword !== $confirmPassword) {
        $error = 'Новый пароль и подтверждение пароля не совпадают';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = 'Неверный формат адреса электронной почты';
    } elseif (!preg_match('/^\+?[1-9]\d{10,14}$/', $phone)) {
        $error = 'Неверный формат номера телефона';
    } else {

        // Загрузка актуальных данных пользователя
        $stmt = $mysqli->prepare("SELECT * FROM user WHERE id = ?");
        $stmt->bind_param('i', $user['id']);
        $stmt->execute();
        $result = $stmt->get_result();
        $userFromDb = $result->fetch_assoc();

        // Смена пароля
        if ($oldPassword && $newPassword && $confirmPassword) {
            if (empty($oldPassword)) {
                $error = 'Введите старый пароль';
            } elseif (empty($newPassword)) {
                $error = 'Введите новый пароль';
            } elseif ($newPassword !== $confirmPassword) {
                $error = 'Новый пароль и подтверждение пароля не совпадают';
            } else {
                // Валидация пароля
                if (validateCurrentPassword($oldPassword, $userFromDb['password'])) {
                    $hashedPassword = password_hash($newPassword, PASSWORD_BCRYPT);

                    $stmt = $mysqli->prepare("UPDATE user SET name = ?, phone = ?, email = ?, password = ? WHERE id = ?");
                    $stmt->bind_param('ssssi', $name, $phone, $email, $hashedPassword, $user['id']);
                    $stmt->execute();

                    // Обновление сессии с измененными данными
                    $_SESSION['user']['name'] = $name;
                    $_SESSION['user']['phone'] = $phone;
                    $_SESSION['user']['email'] = $email;
                    $_SESSION['user']['password'] = $hashedPassword;

                    $success = 'Данные успешно обновлены, пожалуйста обновите страницу!';
                } else {
                    $error = 'Старый пароль неверен';
                }
            }
        } else {
            // Обновление данных без пароля
            $stmt = $mysqli->prepare("UPDATE user SET name = ?, phone = ?, email = ? WHERE id = ?");
            $stmt->bind_param('sssi', $name, $phone, $email, $user['id']);
            $stmt->execute();

            // Обновление сессии с измененными данными
            $_SESSION['user']['name'] = $name;
            $_SESSION['user']['phone'] = $phone;
            $_SESSION['user']['email'] = $email;

            $success = 'Данные успешно обновлены, пожалуйста обновите страницу!';
        }
    }
}
?>

<!DOCTYPE html>
<html lang="ru">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Профиль</title>
    <link rel="stylesheet" href="styles.css">
    <script>
        function togglePasswordVisibility() {
            var oldPassword = document.getElementById("oldPassword");
            var newPassword = document.getElementById("newPassword");
            var confirmPassword = document.getElementById("confirmPassword");
            var showHideBtn = document.getElementById("showHideBtn");

            if (oldPassword.type === "password" && newPassword.type === "password" && confirmPassword.type === "password") {
                oldPassword.type = "text";
                newPassword.type = "text";
                confirmPassword.type = "text";
                showHideBtn.textContent = "Скрыть пароли";
            } else {
                oldPassword.type = "password";
                newPassword.type = "password";
                confirmPassword.type = "password";
                showHideBtn.textContent = "Показать пароли";
            }
        }
    </script>
</head>

<body>
    <div class="container">
        <div class="h1">
            <h1>Профиль</h1>
        </div>
        <?php if ($error): ?>
            <p class="error"><?= htmlspecialchars($error) ?></p>
        <?php endif; ?>
        <?php if ($success): ?>
            <p class="success"><?= htmlspecialchars($success) ?></p>
        <?php endif; ?>
        <?php if ($editMode): ?>
            <form method="POST">
                <div class="string">
                    <input type="text" name="name" placeholder="Имя" value="<?= htmlspecialchars($user['name']) ?>" required>
                    <input type="text" name="phone" placeholder="Номер телефона" value="<?= htmlspecialchars($user['phone']) ?>" required>
                    <input type="email" name="email" placeholder="Электронная почта" value="<?= htmlspecialchars($user['email']) ?>" required>
                </div>
                <div class="string">
                    <input type="password" name="oldPassword" placeholder="Старый пароль" id="oldPassword">
                    <input type="password" name="newPassword" placeholder="Новый пароль" id="newPassword">
                    <input type="password" name="confirmPassword" placeholder="Подтверждение пароля" id="confirmPassword">
                </div>
                <div class="string">
                    <button type="button" id="showHideBtn" onclick="togglePasswordVisibility()">Показать пароли</button>
                    <button type="submit">Обновить</button>
                </div>
                <div class="redact">
                    <a href="index.php">Назад</a>
                </div>
                <div class="exit">
                    <p><a href="logout.php">Выйти</a></p>
                </div>
            </form>
        <?php else: ?>
            <p><strong>Имя:</strong> <?= htmlspecialchars($user['name']) ?></p>
            <p><strong>Номер телефона:</strong> <?= htmlspecialchars($user['phone']) ?></p>
            <p><strong>Электронная почта:</strong> <?= htmlspecialchars($user['email']) ?></p>
            <div class="redact">
                <a href="index.php?edit=true">Редактировать</a>
            </div>
            <div class="exit">
                <p><a href="logout.php">Выйти</a></p>
            </div>
        <?php endif; ?>
    </div>
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

    .buttons {
        margin-top: 30px;
        justify-content: space-between;
        display: flex;
        align-items: center;
    }

    .redact {
        margin-top: 30px;
    }

    .exit {
        position: absolute;
        margin-top: -34px;
        margin-left: 550px;

    }

    .h1 {
        text-align: center;
    }
</style>