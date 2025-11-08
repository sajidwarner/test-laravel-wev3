<?php

namespace App\Http\Controllers;

use App\Services\BEP20WalletService;
use Illuminate\Http\Request;

class TestWeb3Controller extends Controller
{
    public function index()
    {

        $service = new BEP20WalletService();

        // Check system info
        dd($service->getSystemInfo());


        $wallet = $service->generateWallet();
        echo "Method used: " . $wallet['method'] . "\n";
        echo "Address: " . $wallet['address'] . "\n";

        return view('test-web3');
    }
}
