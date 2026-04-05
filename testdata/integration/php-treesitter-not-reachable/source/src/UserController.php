<?php
namespace App;

use GuzzleHttp\Client;

class UserController
{
    #[Route('/api/data', methods: ['GET'])]
    public function getData(): string
    {
        // Uses curl instead of Guzzle client
        $ch = curl_init('https://api.example.com/data');
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        return (string) curl_exec($ch);
    }
}
