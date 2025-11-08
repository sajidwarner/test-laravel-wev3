<?php


use App\Http\Controllers\WalletController;
use Illuminate\Support\Facades\Route;

Route::prefix('wallet')->group(function () {
    Route::get('/generate', [WalletController::class, 'generate']);
    Route::get('/import', [WalletController::class, 'import']);
    Route::get('/validate', [WalletController::class, 'validate']);
    Route::get('/balance', [WalletController::class, 'balance']);
    Route::get('/token-balance', [WalletController::class, 'tokenBalance']); // NEW
    Route::get('/token-info', [WalletController::class, 'tokenInfo']); // NEW
    Route::get('/sign-message', [WalletController::class, 'signMessage']);

    Route::get('/system-info', [WalletController::class, 'systemInfo']);
});
Route::get('/', function () {
    return view('welcome');
});
