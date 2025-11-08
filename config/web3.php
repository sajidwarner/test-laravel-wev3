<?php

return [
    /*
    |--------------------------------------------------------------------------
    | BSC RPC URLs
    |--------------------------------------------------------------------------
    */
    'bsc_rpc_url' => env('BSC_RPC_URL', 'https://bsc-dataseed.binance.org/'),

    'bsc_testnet_rpc_url' => env('BSC_TESTNET_RPC_URL', 'https://data-seed-prebsc-1-s1.binance.org:8545/'),

    /*
    |--------------------------------------------------------------------------
    | Request Timeout (in seconds)
    |--------------------------------------------------------------------------
    */
    'timeout' => env('WEB3_TIMEOUT', 10),

    /*
    |--------------------------------------------------------------------------
    | Alternative RPC URLs (for fallback)
    |--------------------------------------------------------------------------
    */
    'bsc_rpc_urls' => [
        'https://bsc-dataseed.binance.org/',
        'https://bsc-dataseed1.defibit.io/',
        'https://bsc-dataseed1.ninicoin.io/',
        'https://bsc.publicnode.com',
    ],

    /*
    |--------------------------------------------------------------------------
    | Popular BEP-20 Token Contracts (Mainnet)
    |--------------------------------------------------------------------------
    */
    'tokens' => [
        'USDT' => '0x55d398326f99059fF775485246999027B3197955',
        'USDC' => '0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d',
        'BUSD' => '0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56',
        'CAKE' => '0x0E09FaBB73Bd3Ade0a17ECC321fD13a19e81cE82',
        'DAI' => '0x1AF3F329e8BE154074D8769D1FFa4eE058B1DBc3',
    ],
];
