<?php
require 'vendor/autoload.php';
use GuzzleHttp\Psr7\Utils;

class App {
    public function run() {
        $stream = fopen('php://stdin', 'r');
        $line = Utils::readLine($stream);
        echo $line;
    }
}
