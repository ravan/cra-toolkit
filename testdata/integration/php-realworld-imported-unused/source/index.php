<?php
require 'vendor/autoload.php';
use GuzzleHttp\Psr7\Response;
$response = new Response(200, [], 'OK');
echo $response->getBody();
