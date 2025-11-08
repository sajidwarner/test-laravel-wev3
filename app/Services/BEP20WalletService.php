<?php

declare(strict_types=1);

namespace App\Services;

use Elliptic\EC;
use Exception;
use kornrunner\Keccak;
use Web3\Providers\HttpProvider;
use Web3\RequestManagers\HttpRequestManager;
use Web3\Web3;

class BEP20WalletService
{
    private EC $ec;
    private bool $useNativeSecp256k1;

    public function __construct()
    {
        $this->useNativeSecp256k1 = extension_loaded('secp256k1');

        if (!$this->useNativeSecp256k1) {
            $this->ec = new EC('secp256k1');
        }
    }

    /**
     * Generate a new BEP-20 wallet address and private key
     */
    public function generateWallet(): array
    {
        if ($this->useNativeSecp256k1) {
            return $this->generateWalletNative();
        }

        return $this->generateWalletPurePhp();
    }

    /**
     * Generate wallet using native secp256k1 extension
     */
    private function generateWalletNative(): array
    {
        $context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

        $privateKey = bin2hex(random_bytes(32));
        $privateKeyBin = hex2bin($privateKey);

        $publicKey = '';
        secp256k1_ec_pubkey_create($context, $publicKey, $privateKeyBin);

        $serialized = '';
        secp256k1_ec_pubkey_serialize($context, $serialized, $publicKey, SECP256K1_EC_UNCOMPRESSED);
        $publicKeyHex = bin2hex($serialized);

        $address = $this->publicKeyToAddress($publicKeyHex);

        return [
            'address' => $address,
            'private_key' => $privateKey,
            'public_key' => $publicKeyHex,
            'method' => 'native_secp256k1',
        ];
    }

    /**
     * Generate wallet using pure PHP
     */
    private function generateWalletPurePhp(): array
    {
        $keyPair = $this->ec->genKeyPair();

        $privateKey = $keyPair->getPrivate('hex');
        $publicKey = $keyPair->getPublic('hex');

        $address = $this->publicKeyToAddress($publicKey);

        return [
            'address' => $address,
            'private_key' => $privateKey,
            'public_key' => $publicKey,
            'method' => 'pure_php',
        ];
    }

    /**
     * Import wallet from private key
     */
    public function importWallet(string $privateKey): array
    {
        $privateKey = str_replace('0x', '', $privateKey);

        if ($this->useNativeSecp256k1) {
            return $this->importWalletNative($privateKey);
        }

        return $this->importWalletPurePhp($privateKey);
    }

    /**
     * Import wallet using native extension
     */
    private function importWalletNative(string $privateKey): array
    {
        $context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
        $privateKeyBin = hex2bin($privateKey);

        $publicKey = '';
        secp256k1_ec_pubkey_create($context, $publicKey, $privateKeyBin);

        $serialized = '';
        secp256k1_ec_pubkey_serialize($context, $serialized, $publicKey, SECP256K1_EC_UNCOMPRESSED);
        $publicKeyHex = bin2hex($serialized);

        return [
            'address' => $this->publicKeyToAddress($publicKeyHex),
            'private_key' => $privateKey,
            'public_key' => $publicKeyHex,
        ];
    }

    /**
     * Import wallet using pure PHP
     */
    private function importWalletPurePhp(string $privateKey): array
    {
        $keyPair = $this->ec->keyFromPrivate($privateKey, 'hex');
        $publicKey = $keyPair->getPublic('hex');

        return [
            'address' => $this->publicKeyToAddress($publicKey),
            'private_key' => $privateKey,
            'public_key' => $publicKey,
        ];
    }

    /**
     * Convert public key to address
     */
    private function publicKeyToAddress(string $publicKey): string
    {
        if (str_starts_with($publicKey, '04')) {
            $publicKey = substr($publicKey, 2);
        }

        $hash = Keccak::hash(hex2bin($publicKey), 256);
        $address = '0x' . substr($hash, -40);

        return $this->toChecksumAddress($address);
    }

    /**
     * Convert address to checksum format (EIP-55)
     */
    private function toChecksumAddress(string $address): string
    {
        $address = strtolower(str_replace('0x', '', $address));
        $hash = Keccak::hash($address, 256);
        $checksum = '0x';

        for ($i = 0; $i < strlen($address); $i++) {
            if (intval($hash[$i], 16) >= 8) {
                $checksum .= strtoupper($address[$i]);
            } else {
                $checksum .= $address[$i];
            }
        }

        return $checksum;
    }

    /**
     * Validate if an address is valid
     */
    public function isValidAddress(string $address): bool
    {
        return (bool) preg_match('/^0x[a-fA-F0-9]{40}$/', $address);
    }

    /**
     * Get BNB balance of an address
     * 
     * @throws Exception
     */
    public function getBalance(string $address, ?string $rpcUrl = null): array
    {
        $rpcUrl = $rpcUrl ?? config('web3.bsc_rpc_url', 'https://bsc-dataseed.binance.org/');
        // Correct way to initialize Web3
        $requestManager = new HttpRequestManager($rpcUrl, 10); // 10 seconds timeout
        $web3 = new Web3(new HttpProvider($requestManager));

        $balance = null;
        $error = null;

        $web3->eth->getBalance($address, function ($err, $result) use (&$balance, &$error) {
            if ($err !== null) {
                $error = $err->getMessage();
                return;
            }
            $balance = $result->toString();
        });

        if ($error) {
            throw new Exception($error);
        }

        $bnbBalance = bcdiv($balance, '1000000000000000000', 18);

        return [
            'balance_wei' => $balance,
            'balance_bnb' => $bnbBalance,
        ];
    }

    /**
     * Sign a message with private key
     */
    public function signMessage(string $message, string $privateKey): string
    {
        $privateKey = str_replace('0x', '', $privateKey);

        if ($this->useNativeSecp256k1) {
            return $this->signMessageNative($message, $privateKey);
        }

        return $this->signMessagePurePhp($message, $privateKey);
    }

    /**
     * Sign message using pure PHP
     */
    private function signMessagePurePhp(string $message, string $privateKey): string
    {
        $keyPair = $this->ec->keyFromPrivate($privateKey, 'hex');
        $messageHash = Keccak::hash($message, 256);
        $signature = $keyPair->sign($messageHash);

        return '0x' . str_pad($signature->r->toString(16), 64, '0', STR_PAD_LEFT) .
            str_pad($signature->s->toString(16), 64, '0', STR_PAD_LEFT) .
            dechex($signature->recoveryParam);
    }

    /**
     * Sign message using native extension
     */
    private function signMessageNative(string $message, string $privateKey): string
    {
        $context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
        $messageHash = hex2bin(Keccak::hash($message, 256));
        $privateKeyBin = hex2bin($privateKey);

        $signature = '';
        secp256k1_ecdsa_sign($context, $signature, $messageHash, $privateKeyBin);

        $serialized = '';
        secp256k1_ecdsa_signature_serialize_compact($context, $serialized, $signature);

        return '0x' . bin2hex($serialized);
    }

    /**
     * Get current method being used
     */
    public function getMethod(): string
    {
        return $this->useNativeSecp256k1 ? 'native_secp256k1' : 'pure_php';
    }

    private function createWeb3Instance(?string $rpcUrl = null, ?int $timeout = null): Web3
    {
        $rpcUrl = $rpcUrl ?? config('web3.bsc_rpc_url', 'https://bsc-dataseed.binance.org/');
        $timeout = $timeout ?? config('web3.timeout', 10);

        $requestManager = new HttpRequestManager($rpcUrl, $timeout);
        $httpProvider = new HttpProvider($requestManager);

        return new Web3($httpProvider);
    }

    /**
     * Get BEP-20 token balance
     * 
     * @throws Exception
     */
    public function getTokenBalance(string $address, string $tokenContract, ?string $rpcUrl = null): array
    {
        $web3 = $this->createWeb3Instance($rpcUrl);

        // ERC-20/BEP-20 balanceOf function signature
        $functionSignature = '0x70a08231'; // balanceOf(address)
        $paddedAddress = str_pad(str_replace('0x', '', $address), 64, '0', STR_PAD_LEFT);
        $data = $functionSignature . $paddedAddress;

        $balance = null;
        $error = null;

        $web3->eth->call([
            'to' => $tokenContract,
            'data' => $data,
        ], function ($err, $result) use (&$balance, &$error) {
            if ($err !== null) {
                $error = $err->getMessage();
                return;
            }
            $balance = $result;
        });

        if ($error) {
            throw new Exception($error);
        }

        // Handle null or empty balance
        if (empty($balance) || $balance === '0x') {
            return [
                'balance_raw' => '0',
                'balance_formatted' => '0',
                'decimals' => 18,
            ];
        }

        // Get token decimals
        $decimals = $this->getTokenDecimals($tokenContract, $rpcUrl);

        // Remove '0x' prefix and convert hex to decimal
        $balanceHex = str_replace('0x', '', $balance);

        // Handle empty hex
        if (empty($balanceHex)) {
            return [
                'balance_raw' => '0',
                'balance_formatted' => '0',
                'decimals' => $decimals,
            ];
        }

        // Convert hex to decimal string (for large numbers)
        $balanceWei = $this->hexToDec($balanceHex);

        // Convert to human readable format
        $divisor = bcpow('10', (string)$decimals, 0);
        $balanceFormatted = bcdiv($balanceWei, $divisor, $decimals);

        return [
            'balance_raw' => $balanceWei,
            'balance_formatted' => $balanceFormatted,
            'decimals' => $decimals,
        ];
    }

    /**
     * Convert hex to decimal for very large numbers
     */
    private function hexToDec(string $hex): string
    {
        $hex = ltrim($hex, '0') ?: '0';

        if (strlen($hex) <= 15) {
            // For smaller numbers, use hexdec
            return (string)hexdec($hex);
        }

        // For large numbers, use bcmath
        $dec = '0';
        $len = strlen($hex);

        for ($i = 0; $i < $len; $i++) {
            $dec = bcadd(bcmul($dec, '16', 0), (string)hexdec($hex[$i]), 0);
        }

        return $dec;
    }

    /**
     * Get token decimals
     * 
     * @throws Exception
     */
    public function getTokenDecimals(string $tokenContract, ?string $rpcUrl = null): int
    {
        $web3 = $this->createWeb3Instance($rpcUrl);

        // ERC-20/BEP-20 decimals function signature
        $functionSignature = '0x313ce567'; // decimals()

        $decimals = null;
        $error = null;

        $web3->eth->call([
            'to' => $tokenContract,
            'data' => $functionSignature,
        ], function ($err, $result) use (&$decimals, &$error) {
            if ($err !== null) {
                $error = $err->getMessage();
                return;
            }
            $decimals = $result;
        });

        if ($error) {
            throw new Exception($error);
        }

        return hexdec($decimals);
    }

    /**
     * Get token name
     * 
     * @throws Exception
     */
    public function getTokenName(string $tokenContract, ?string $rpcUrl = null): string
    {
        $web3 = $this->createWeb3Instance($rpcUrl);

        // ERC-20/BEP-20 name function signature
        $functionSignature = '0x06fdde03'; // name()

        $name = null;
        $error = null;

        $web3->eth->call([
            'to' => $tokenContract,
            'data' => $functionSignature,
        ], function ($err, $result) use (&$name, &$error) {
            if ($err !== null) {
                $error = $err->getMessage();
                return;
            }
            $name = $result;
        });

        if ($error) {
            throw new Exception($error);
        }

        return $this->decodeString($name);
    }

    /**
     * Get token symbol
     * 
     * @throws Exception
     */
    public function getTokenSymbol(string $tokenContract, ?string $rpcUrl = null): string
    {
        $web3 = $this->createWeb3Instance($rpcUrl);

        // ERC-20/BEP-20 symbol function signature
        $functionSignature = '0x95d89b41'; // symbol()

        $symbol = null;
        $error = null;

        $web3->eth->call([
            'to' => $tokenContract,
            'data' => $functionSignature,
        ], function ($err, $result) use (&$symbol, &$error) {
            if ($err !== null) {
                $error = $err->getMessage();
                return;
            }
            $symbol = $result;
        });

        if ($error) {
            throw new Exception($error);
        }

        return $this->decodeString($symbol);
    }

    /**
     * Get token info (name, symbol, decimals)
     * 
     * @throws Exception
     */
    public function getTokenInfo(string $tokenContract, ?string $rpcUrl = null): array
    {
        return [
            'contract' => $tokenContract,
            'name' => $this->getTokenName($tokenContract, $rpcUrl),
            'symbol' => $this->getTokenSymbol($tokenContract, $rpcUrl),
            'decimals' => $this->getTokenDecimals($tokenContract, $rpcUrl),
        ];
    }

    /**
     * Decode hex string from contract response
     */
    private function decodeString(string $hex): string
    {
        $hex = str_replace('0x', '', $hex);

        // Skip first 64 characters (offset)
        $hex = substr($hex, 64);

        // Next 64 characters contain the length
        $length = hexdec(substr($hex, 0, 64));

        // Rest is the actual string
        $hex = substr($hex, 64, $length * 2);

        return hex2bin($hex);
    }





    /**
     * Get system information about crypto support
     */
    public function getSystemInfo(): array
    {
        return [
            'secp256k1_extension' => extension_loaded('secp256k1'),
            'gmp_extension' => extension_loaded('gmp'),
            'bcmath_extension' => extension_loaded('bcmath'),
            'current_method' => $this->getMethod(),
            'php_version' => PHP_VERSION,
        ];
    }
}
