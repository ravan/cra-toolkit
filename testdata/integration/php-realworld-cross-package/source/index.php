<?php
require 'vendor/autoload.php';
require 'parser.php';

class App {
    public function run() {
        $result = RequestParser::parse('php://stdin');
        echo $result;
    }
}
