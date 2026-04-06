<?php
use GuzzleHttp\Psr7\Utils;
function testReadLine() {
    $line = Utils::readLine(fopen('php://memory', 'r'));
    assert($line === '');
}
