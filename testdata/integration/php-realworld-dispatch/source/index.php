<?php
require 'vendor/autoload.php';
require 'StreamReader.php';
$reader = new StreamReader();
echo $reader->read('php://stdin');
