<?php

declare(strict_types=1);

namespace App\Services;

use GuzzleHttp\Client;
use Web3\Providers\HttpProvider;

class CustomHttpProvider extends HttpProvider
{
    /**
     * Create a custom HTTP provider with timeout
     */
    public function __construct(string $url, int $timeout = 10)
    {
        parent::__construct($url);

        // Override the Guzzle client with custom timeout
        $this->httpClient = new Client([
            'timeout' => $timeout,
            'connect_timeout' => $timeout,
        ]);
    }
}
