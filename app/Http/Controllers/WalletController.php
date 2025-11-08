<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Services\BEP20WalletService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\ValidationException;

class WalletController extends Controller
{
    public function __construct(
        private readonly BEP20WalletService $walletService
    ) {}

    /**
     * Generate a new BEP-20 wallet
     */
    public function generate(): JsonResponse
    {
        try {
            $wallet = $this->walletService->generateWallet();

            // SECURITY WARNING: Never return private key to client in production!
            // Store it encrypted in database instead
            // This is only for demonstration purposes

            return response()->json([
                'success' => true,
                'data' => [
                    'address' => $wallet['address'],
                    'private_key' => $wallet['private_key'], // Remove in production!
                    'method' => $wallet['method'],
                ],
            ]);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Failed to generate wallet',
                'error' => $e->getMessage(),
            ], 500);
        }
    }

    /**
     * Import wallet from private key
     */
    public function import(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'private_key' => 'required|string|regex:/^(0x)?[a-fA-F0-9]{64}$/',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'message' => 'Validation failed',
                'errors' => $validator->errors(),
            ], 422);
        }

        try {
            $wallet = $this->walletService->importWallet($request->private_key);

            return response()->json([
                'success' => true,
                'data' => [
                    'address' => $wallet['address'],
                    'public_key' => $wallet['public_key'],
                ],
            ]);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Failed to import wallet',
                'error' => $e->getMessage(),
            ], 500);
        }
    }

    /**
     * Validate a wallet address
     */
    public function validate(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'address' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'message' => 'Validation failed',
                'errors' => $validator->errors(),
            ], 422);
        }

        $isValid = $this->walletService->isValidAddress($request->address);

        return response()->json([
            'success' => true,
            'valid' => $isValid,
            'address' => $request->address,
        ]);
    }

    /**
     * Get BNB balance of a wallet
     */
    public function balance(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'address' => 'required|string|regex:/^0x[a-fA-F0-9]{40}$/',
            'network' => 'sometimes|in:mainnet,testnet',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'message' => 'Validation failed',
                'errors' => $validator->errors(),
            ], 422);
        }

        try {
            $network = $request->input('network', 'mainnet');
            $rpcUrl = $network === 'testnet'
                ? config('web3.bsc_testnet_rpc_url')
                : config('web3.bsc_rpc_url');

            $balance = $this->walletService->getBalance($request->address, $rpcUrl);

            return response()->json([
                'success' => true,
                'data' => [
                    'address' => $request->address,
                    'network' => $network,
                    'balance_wei' => $balance['balance_wei'],
                    'balance_bnb' => $balance['balance_bnb'],
                ],
            ]);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Failed to fetch balance',
                'error' => $e->getMessage(),
            ], 500);
        }
    }

    /**
     * Get BEP-20 token balance
     */
    public function tokenBalance(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'address' => 'required|string|regex:/^0x[a-fA-F0-9]{40}$/',
            'token_contract' => 'required|string|regex:/^0x[a-fA-F0-9]{40}$/',
            'network' => 'sometimes|in:mainnet,testnet',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'message' => 'Validation failed',
                'errors' => $validator->errors(),
            ], 422);
        }

        try {
            $network = $request->input('network', 'mainnet');
            $rpcUrl = $network === 'testnet'
                ? config('web3.bsc_testnet_rpc_url')
                : config('web3.bsc_rpc_url');

            $balance = $this->walletService->getTokenBalance(
                $request->address,
                $request->token_contract,
                $rpcUrl
            );

            return response()->json([
                'success' => true,
                'data' => [
                    'address' => $request->address,
                    'token_contract' => $request->token_contract,
                    'network' => $network,
                    'balance_raw' => $balance['balance_raw'],
                    'balance_formatted' => $balance['balance_formatted'],
                    'decimals' => $balance['decimals'],
                ],
            ]);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Failed to fetch token balance',
                'error' => $e->getMessage(),
            ], 500);
        }
    }

    /**
     * Get token information
     */
    public function tokenInfo(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'token_contract' => 'required|string|regex:/^0x[a-fA-F0-9]{40}$/',
            'network' => 'sometimes|in:mainnet,testnet',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'message' => 'Validation failed',
                'errors' => $validator->errors(),
            ], 422);
        }

        try {
            $network = $request->input('network', 'mainnet');
            $rpcUrl = $network === 'testnet'
                ? config('web3.bsc_testnet_rpc_url')
                : config('web3.bsc_rpc_url');

            $tokenInfo = $this->walletService->getTokenInfo(
                $request->token_contract,
                $rpcUrl
            );

            return response()->json([
                'success' => true,
                'data' => [
                    'network' => $network,
                    ...$tokenInfo,
                ],
            ]);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Failed to fetch token info',
                'error' => $e->getMessage(),
            ], 500);
        }
    }

    /**
     * Sign a message
     */
    public function signMessage(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'message' => 'required|string',
            'private_key' => 'required|string|regex:/^(0x)?[a-fA-F0-9]{64}$/',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'message' => 'Validation failed',
                'errors' => $validator->errors(),
            ], 422);
        }

        try {
            $signature = $this->walletService->signMessage(
                $request->message,
                $request->private_key
            );

            return response()->json([
                'success' => true,
                'data' => [
                    'message' => $request->message,
                    'signature' => $signature,
                ],
            ]);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Failed to sign message',
                'error' => $e->getMessage(),
            ], 500);
        }
    }

    /**
     * Get system information
     */
    public function systemInfo(): JsonResponse
    {
        return response()->json([
            'success' => true,
            'data' => $this->walletService->getSystemInfo(),
        ]);
    }
}
