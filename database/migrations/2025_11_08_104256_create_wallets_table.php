<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('wallets', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->constrained()->onDelete('cascade');
            $table->string('address')->unique(); // EVM wallet address
            $table->text('encrypted_private_key')->nullable(); // Encrypted private key
            $table->text('encrypted_seed_phrase')->nullable(); // Encrypted seed phrase
            $table->enum('type', ['generated', 'imported'])->default('generated');
            $table->string('network')->default('bsc'); // bsc, ethereum, polygon, etc.
            $table->string('rpc_url')->nullable();
            $table->decimal('balance', 20, 8)->default(0); // Native currency balance
            $table->decimal('total_deposited', 20, 8)->default(0); // Total deposited amount
            $table->boolean('is_active')->default(true);
            $table->timestamp('last_checked_at')->nullable();
            $table->timestamps();

            $table->index('address');
            $table->index('user_id');
            $table->index('created_at');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('wallets');
    }
};
