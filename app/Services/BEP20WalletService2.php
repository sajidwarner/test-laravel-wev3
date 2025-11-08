<?php

declare(strict_types=1);

namespace App\Services;

use Elliptic\EC;
use Exception;
use kornrunner\Keccak;
use Web3\Providers\HttpProvider;
use Web3\RequestManagers\HttpRequestManager;
use Web3\Web3;

class BEP20WalletService2
{
    private EC $ec;
    private bool $useNativeSecp256k1;
    private TransactionSigner $signer;

    public function __construct()
    {
        $this->useNativeSecp256k1 = extension_loaded('secp256k1');

        if (!$this->useNativeSecp256k1) {
            $this->ec = new EC('secp256k1');
        }

        $this->signer = new TransactionSigner();
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
        $web3 = new Web3(new HttpProvider($rpcUrl));

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
     * Transfer BEP-20 tokens
     * 
     * @param string $fromAddress Sender address
     * @param string $fromPrivateKey Sender private key
     * @param string $toAddress Recipient address
     * @param string $tokenContract Token contract address
     * @param string $amount Amount to transfer (in human readable format)
     * @param string|null $rpcUrl RPC URL
     * @return array Transaction hash and details
     * @throws Exception
     */
    public function transferToken(
        string $fromAddress,
        string $fromPrivateKey,
        string $toAddress,
        string $tokenContract,
        string $amount,
        ?string $rpcUrl = null
    ): array {
        $web3 = $this->createWeb3Instance($rpcUrl);

        // Get token decimals
        $decimals = $this->getTokenDecimals($tokenContract, $rpcUrl);

        // Convert amount to wei (smallest unit)
        $amountWei = bcmul($amount, bcpow('10', (string)$decimals, 0), 0);

        // ERC-20/BEP-20 transfer function signature
        $functionSignature = '0xa9059cbb'; // transfer(address,uint256)

        // Encode recipient address (pad to 32 bytes)
        $paddedAddress = str_pad(str_replace('0x', '', $toAddress), 64, '0', STR_PAD_LEFT);

        // Encode amount (pad to 32 bytes)
        $paddedAmount = str_pad(dechex((int)$amountWei), 64, '0', STR_PAD_LEFT);

        // Combine into data payload
        $data = $functionSignature . $paddedAddress . $paddedAmount;

        // Get nonce
        $nonce = $this->getNonce($fromAddress, $rpcUrl);

        // Get gas price
        $gasPrice = $this->getGasPrice($rpcUrl);

        // Estimate gas
        $gasLimit = '100000'; // Standard for token transfers

        // Build transaction
        $transaction = [
            'from' => $fromAddress,
            'to' => $tokenContract,
            'gas' => '0x' . dechex((int)$gasLimit),
            'gasPrice' => $gasPrice,
            'value' => '0x0',
            'data' => $data,
            'nonce' => '0x' . dechex($nonce),
            'chainId' => 56, // BSC Mainnet
        ];

        // Sign transaction
        $signedTx = $this->signTransaction($transaction, $fromPrivateKey);

        // Send transaction
        $txHash = $this->sendRawTransaction($signedTx, $rpcUrl);

        return [
            'transaction_hash' => $txHash,
            'from' => $fromAddress,
            'to' => $toAddress,
            'token_contract' => $tokenContract,
            'amount' => $amount,
            'amount_wei' => $amountWei,
            'gas_limit' => $gasLimit,
            'gas_price' => $gasPrice,
            'nonce' => $nonce,
        ];
    }

    /**
     * Transfer BNB (native token)
     */
    public function transferBNB(
        string $fromAddress,
        string $fromPrivateKey,
        string $toAddress,
        string $amount,
        ?string $rpcUrl = null
    ): array {
        $web3 = $this->createWeb3Instance($rpcUrl);

        // Convert BNB to Wei
        $amountWei = bcmul($amount, '1000000000000000000', 0);

        // Get nonce
        $nonce = $this->getNonce($fromAddress, $rpcUrl);

        // Get gas price
        $gasPrice = $this->getGasPrice($rpcUrl);

        // Build transaction
        $transaction = [
            'from' => $fromAddress,
            'to' => $toAddress,
            'gas' => '0x5208', // 21000 in hex (standard for BNB transfer)
            'gasPrice' => $gasPrice,
            'value' => '0x' . dechex((int)$amountWei),
            'data' => '0x',
            'nonce' => '0x' . dechex($nonce),
            'chainId' => 56,
        ];

        // Sign transaction
        $signedTx = $this->signTransaction($transaction, $fromPrivateKey);

        // Send transaction
        $txHash = $this->sendRawTransaction($signedTx, $rpcUrl);

        return [
            'transaction_hash' => $txHash,
            'from' => $fromAddress,
            'to' => $toAddress,
            'amount_bnb' => $amount,
            'amount_wei' => $amountWei,
        ];
    }

    /**
     * Get nonce (transaction count) for an address
     */
    private function getNonce(string $address, ?string $rpcUrl = null): int
    {
        $web3 = $this->createWeb3Instance($rpcUrl);

        $nonce = null;
        $error = null;

        $web3->eth->getTransactionCount($address, 'pending', function ($err, $result) use (&$nonce, &$error) {
            if ($err !== null) {
                $error = $err->getMessage();
                return;
            }
            $nonce = $result;
        });

        if ($error) {
            throw new Exception($error);
        }

        return hexdec($nonce->toString());
    }

    /**
     * Get current gas price
     */
    private function getGasPrice(?string $rpcUrl = null): string
    {
        $web3 = $this->createWeb3Instance($rpcUrl);

        $gasPrice = null;
        $error = null;

        $web3->eth->gasPrice(function ($err, $result) use (&$gasPrice, &$error) {
            if ($err !== null) {
                $error = $err->getMessage();
                return;
            }
            $gasPrice = $result;
        });

        if ($error) {
            throw new Exception($error);
        }

        return '0x' . $gasPrice->toHex();
    }

    /**
     * Sign transaction with private key
     */
    private function signTransaction(array $transaction, string $privateKey): string
    {
        return $this->signer->signTransaction($transaction, $privateKey);
    }

    /**
     * Send raw signed transaction
     */
    private function sendRawTransaction(string $signedTx, ?string $rpcUrl = null): string
    {
        $web3 = $this->createWeb3Instance($rpcUrl);

        $txHash = null;
        $error = null;

        $web3->eth->sendRawTransaction($signedTx, function ($err, $result) use (&$txHash, &$error) {
            if ($err !== null) {
                $error = $err->getMessage();
                return;
            }
            $txHash = $result;
        });

        if ($error) {
            throw new Exception($error);
        }

        return $txHash;
    }

    /**
     * Split and transfer tokens: 99% to address1, 1% to address2
     * Gas fees paid from feePayerWallet
     */
    public function splitTransfer(
        string $fromAddress,
        string $fromPrivateKey,
        string $recipient99Address,
        string $recipient1Address,
        string $tokenContract,
        string $feePayerPrivateKey,
        ?string $rpcUrl = null
    ): array {
        // Get total balance
        $balance = $this->getTokenBalance($fromAddress, $tokenContract, $rpcUrl);
        $totalBalance = $balance['balance_formatted'];

        if ($totalBalance === '0' || bccomp($totalBalance, '0', 18) <= 0) {
            throw new Exception('Insufficient token balance');
        }

        // Calculate amounts (99% and 1%)
        $amount99 = bcmul($totalBalance, '0.99', 18);
        $amount1 = bcmul($totalBalance, '0.01', 18);

        $results = [];

        // Transfer 99% to first recipient
        try {
            $tx1 = $this->transferToken(
                $fromAddress,
                $fromPrivateKey,
                $recipient99Address,
                $tokenContract,
                $amount99,
                $rpcUrl
            );
            $results['transfer_99_percent'] = $tx1;
        } catch (Exception $e) {
            throw new Exception('Failed to transfer 99%: ' . $e->getMessage());
        }

        // Wait a bit to avoid nonce issues
        sleep(2);

        // Transfer 1% to second recipient
        try {
            $tx2 = $this->transferToken(
                $fromAddress,
                $fromPrivateKey,
                $recipient1Address,
                $tokenContract,
                $amount1,
                $rpcUrl
            );
            $results['transfer_1_percent'] = $tx2;
        } catch (Exception $e) {
            throw new Exception('Failed to transfer 1%: ' . $e->getMessage());
        }

        return [
            'success' => true,
            'total_balance' => $totalBalance,
            'amount_99_percent' => $amount99,
            'amount_1_percent' => $amount1,
            'recipient_99' => $recipient99Address,
            'recipient_1' => $recipient1Address,
            'transactions' => $results,
        ];
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
