<?php
namespace App;

use GuzzleHttp\Client;

class UserController
{
    #[Route('/api/proxy', methods: ['GET'])]
    public function proxy(string $url): string
    {
        $client = new Client(['cookies' => true]);
        $response = $client->get($url);
        return (string) $response->getBody();
    }
}
