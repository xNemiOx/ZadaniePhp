<?php

require_once __DIR__ . '/vendor/autoload.php';

use Dotenv\Dotenv;

$dotenv = Dotenv::createImmutable(__DIR__);
$dotenv->load();

$secretKey = $_ENV['SECRET_KEY'];
$captchaSiteKey = $_ENV['CAPTCHA_SITE_KEY'];

require_once 'database.php';

session_start();
error_reporting(E_ALL);
ini_set('display_errors', 1);

$error = '';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $login = $_POST['login'] ?? '';
    $password = $_POST['password'] ?? '';

    $login = filter_var($login, FILTER_SANITIZE_EMAIL);

    // Проверка того, что данные формы передаются
    if (empty($login)) {
        $error = 'Поле с логином пустое';
    } elseif (empty($password)) {
        $error = 'Пароль пустой';
    } else {

        // Проверка наличия токена капчи
        // Проверка наличия токена капчи
        if (!isset($_POST["smart-token"])) {
            $error = 'Токен капчи не получен. Пожалуйста, проверьте, правильно ли загружена капча.';
        } else {
            $ch = curl_init();
            $args = http_build_query([
                "secret" => $secretKey,
                "token" => $_POST["smart-token"],
                "ip" => $_SERVER['REMOTE_ADDR'],
            ]);
            curl_setopt($ch, CURLOPT_URL, "https://smartcaptcha.yandexcloud.net/validate?$args");
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 5);
            curl_setopt($ch, CURLOPT_CAINFO, "C:\cacert-2024-07-02.pem");

            $server_output = curl_exec($ch);
            $httpcode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

            if (curl_errno($ch)) {
                $error = 'Ошибка при подключении к серверу капчи: ' . curl_error($ch);
            }

            curl_close($ch);

            if ($httpcode !== 200) {
                $error = 'Ошибка валидации капчи. Код ответа: ' . $httpcode . '. Ответ сервера: ' . $server_output;
            } else {
                $resp = json_decode($server_output);
                if ($resp->status !== "ok") {
                    $error = 'Капча не пройдена. Пожалуйста, попробуйте еще раз.';
                } else {
                    // Определение типа ввода: email или телефон
                    $isEmail = filter_var($login, FILTER_VALIDATE_EMAIL);

                    // Запрос в зависимости от типа ввода
                    if ($isEmail) {
                        $stmt = $mysqli->prepare("SELECT * FROM user WHERE email = ?");
                    } else {
                        $stmt = $mysqli->prepare("SELECT * FROM user WHERE phone = ?");
                    }

                    if ($stmt === false) {
                        die('Ошибка подготовки запроса: ' . $mysqli->error);
                    }

                    $stmt->bind_param('s', $login);
                    $stmt->execute();
                    $result = $stmt->get_result();
                    $user = $result->fetch_assoc();

                    if ($user) {
                        // Проверка пароля
                        if (password_verify($password, $user['password'])) {
                            // Проверка необходимости повторного хеширования
                            $options = [
                                'cost' => 12,
                            ];
                            if (password_needs_rehash($user['password'], PASSWORD_DEFAULT, $options)) {

                                $newHashedPassword = password_hash($password, PASSWORD_DEFAULT, $options);

                                // Обновление пароля в базе данных
                                $stmt = $mysqli->prepare("UPDATE user SET password = ? WHERE email = ? OR phone = ?");
                                $stmt->bind_param('sss', $newHashedPassword, $login, $login);
                                $stmt->execute();
                                $stmt->close();
                            }

                            // Успешная авторизация
                            $_SESSION['user'] = $user;
                            header('Location: index.php');
                            exit;
                        } else {
                            $error = 'Неверный пароль';
                        }
                    } else {
                        $error = 'Неверный email или телефон';
                    }

                    $stmt->close();
                }
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
    <title>Вход</title>
    <link rel="stylesheet" href="styles.css">
    <script src="https://captcha-api.yandex.ru/captcha.js" defer></script>
</head>

<body>
    <div class="container">
        <div class="auto">
            <h1>Вход</h1>
        </div>
        <div class="auto">
            <?php if ($error): ?>
                <p class="error"><?= htmlspecialchars($error) ?></p>
            <?php endif; ?>
            <form method="POST">
                <input type="text" name="login" placeholder="Почта или телефон" required>
                <input type="password" id="password" name="password" placeholder="Пароль" required>
                <button type="button" id="showHideBtn" onclick="togglePasswordVisibility()">Показать пароль</button>
                <div class="cap">
                    <div class="smart-captcha" data-sitekey="ysc1_AGejMw3jRC6GMmFeVOiuh6m6TOzrjjnBv6vCOq9p9a3b9cb5"></div>
                </div>
                <div class="auto">
                    <button type="submit">Войти</button>
                    <p>Нет аккаунта? <a href="register.php">Зарегистрироваться</a></p>
                </div>
            </form>
        </div>
    </div>
</body>

</html>

<script>
    function togglePasswordVisibility() {
        var password = document.getElementById("password");
        var showHideBtn = document.getElementById("showHideBtn");

        if (password.type === "password") {
            password.type = "text";
            showHideBtn.textContent = "Скрыть пароль";
        } else {
            password.type = "password";
            showHideBtn.textContent = "Показать пароль";
        }
    }
</script>

<style>
    .container {
        max-width: 600px;
        margin: 0 auto;
        padding: 20px;
        box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
        border-radius: 8px;
        background: #fff;
    }

    .error {
        color: red;
        margin-bottom: 15px;
    }

    .success {
        color: green;
        margin-bottom: 15px;
    }

    .smart-recaptcha {
        margin: 20px 0;
        transform: scale(1);
        transform-origin: 0 0;
        width: 100% !important;
        z-index: 1000;
    }

    .string {
        margin-bottom: 15px;
    }

    .cap {
        margin-bottom: 15px;
        margin-top: 15px;
    }

    .auto {
        margin-top: 40px;
        justify-content: center;
        display: flex;
        flex-direction: column;
        align-items: center;
    }
</style>