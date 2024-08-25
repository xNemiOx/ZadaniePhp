<?php
$servername = 'mysql-5.7.';
$username = 'root';
$password = '';
$dbname = 'zadanphp';

$mysqli = new mysqli($servername, $username, $password, $dbname);

if ($mysqli->connect_error) {
    die('Ошибка подключения: ' . $mysqli->connect_error);
}

$mysqli->set_charset('utf8');
?>