<?php

namespace App\Console\Commands;

use App\Services\BEP20WalletService;
use Illuminate\Console\Command;

class MonitorBep20Deposits extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'app:monitor-bep20-deposits';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Monitor BEP20 deposits and trigger auto transfer';

    /**
     * Execute the console command.
     */
    public function handle()
    {
        $walletService = new BEP20WalletService();
    }
}
