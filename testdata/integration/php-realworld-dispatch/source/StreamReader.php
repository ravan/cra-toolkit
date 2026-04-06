<?php
use GuzzleHttp\Psr7\Utils;
class StreamReader {
    public function read($source) {
        $stream = fopen($source, 'r');
        return Utils::readLine($stream);
    }
}
