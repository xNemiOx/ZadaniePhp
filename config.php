<?php

require_once __DIR__ . '/vendor/autoload.php';

use Dotenv\Dotenv;

$dotenv = Dotenv::createImmutable(__DIR__);
$dotenv->load();

// Проверяем наличие переменных
$secretKey = $_ENV['SECRET_KEY'] ?? 'default_value';
$captchaSiteKey = $_ENV['CAPTCHA_SITE_KEY'] ?? 'default_value';

// Выводим переменные для проверки (должны быть без ошибок и иметь правильные значения)
error_log("SECRET_KEY: " . $secretKey);
error_log("CAPTCHA_SITE_KEY: " . $captchaSiteKey);

// Остальной код...
