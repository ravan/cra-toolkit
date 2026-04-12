<?php
use GuzzleHttp\Psr7\Utils;

class RequestParser {
    public static function parse($input) {
        $stream = fopen($input, 'r');
        return Utils::readLine($stream);
    }
}
