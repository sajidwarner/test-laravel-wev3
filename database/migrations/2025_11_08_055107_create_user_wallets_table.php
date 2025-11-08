<?php

// database/migrations/xxxx_create_wallets_and_configs_table.php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // User wallets table
        Schema::create('user_wallets', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->nullable()->constrained()->onDelete('cascade');
            $table->string('address', 42)->unique();
            $table->text('private_key_encrypted'); // ENCRYPTED!
            $table->string('label')->nullable(); // e.g., "My Main Wallet"
            $table->boolean('is_active')->default(true);
            $table->boolean('auto_transfer_enabled')->default(true);
            $table->timestamp('last_checked_at')->nullable();
            $table->timestamp('last_transferred_at')->nullable();
            $table->timestamps();

            $table->index(['user_id', 'is_active']);
            $table->index('auto_transfer_enabled');
        });

        // Token configurations
        Schema::create('token_configs', function (Blueprint $table) {
            $table->id();
            $table->string('name');
            $table->string('symbol');
            $table->string('contract_address', 42)->unique();
            $table->integer('decimals')->default(18);
            $table->decimal('min_balance_to_transfer', 36, 18)->default(1.0);
            $table->decimal('gas_required_bnb', 18, 8)->default(0.001);
            $table->string('network')->default('mainnet'); // mainnet or testnet
            $table->boolean('is_active')->default(true);
            $table->timestamps();

            $table->index(['is_active', 'network']);
        });

        // Admin configuration for main addresses
        Schema::create('admin_addresses', function (Blueprint $table) {
            $table->id();
            $table->string('type'); // 'main_receiver', 'fee_receiver', 'gas_payer'
            $table->string('address', 42);
            $table->text('private_key_encrypted')->nullable(); // Only for gas_payer
            $table->decimal('percentage', 5, 2)->nullable(); // For receivers (99.00 or 1.00)
            $table->string('label');
            $table->decimal('min_balance_alert', 18, 8)->nullable(); // Alert if below this
            $table->boolean('is_active')->default(true);
            $table->integer('priority')->default(0); // For ordering
            $table->timestamps();

            $table->index(['type', 'is_active']);
        });

        // Transfer logs
        Schema::create('transfer_logs', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_wallet_id')->constrained()->onDelete('cascade');
            $table->foreignId('token_config_id')->constrained()->onDelete('cascade');
            $table->foreignId('admin_address_id')->nullable()->constrained()->onDelete('set null');
            $table->string('from_address', 42);
            $table->string('to_address', 42);
            $table->string('token_contract', 42);
            $table->decimal('amount', 36, 18);
            $table->decimal('percentage', 5, 2)->nullable();
            $table->string('transfer_type'); // 'main', 'fee', 'gas'
            $table->string('transaction_hash', 66)->nullable();
            $table->enum('status', ['pending', 'processing', 'completed', 'failed'])->default('pending');
            $table->text('error_message')->nullable();
            $table->integer('gas_used')->nullable();
            $table->string('gas_price', 50)->nullable();
            $table->timestamp('processed_at')->nullable();
            $table->timestamps();

            $table->index(['status', 'transfer_type']);
            $table->index('created_at');
            $table->index('transaction_hash');
        });

        // System settings
        Schema::create('system_settings', function (Blueprint $table) {
            $table->id();
            $table->string('key')->unique();
            $table->text('value');
            $table->string('type')->default('string'); // string, boolean, integer, json
            $table->string('description')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('transfer_logs');
        Schema::dropIfExists('system_settings');
        Schema::dropIfExists('admin_addresses');
        Schema::dropIfExists('token_configs');
        Schema::dropIfExists('user_wallets');
    }
};
