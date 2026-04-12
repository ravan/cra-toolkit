<?php

class App {
    public function run() {
        $content = file_get_contents('php://stdin');
        echo $content;
    }
}
