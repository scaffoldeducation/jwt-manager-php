<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

class CreateOauthJwtBlacklistTable extends Migration
{

    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        $tableName = env('OAUTH_TABLE_BLACKLIST', "oauth_jwt_blacklist");
        Schema::create($tableName, function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('user_id')->index();
            $table->string('jti', 250)->unique();
            $table->dateTime('expires_at');
            $table->dateTime('created_at');
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        $tableName = env('OAUTH_TABLE_BLACKLIST', "oauth_jwt_blacklist");
        Schema::dropIfExists($tableName);
    }

}