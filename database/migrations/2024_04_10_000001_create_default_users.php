<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;

return new class extends Migration
{
    public function up()
    {
        // Create admin user
        DB::table('users')->insert([
            'name' => 'Admin User',
            'email' => 'admin@admin.com',
            'password' => Hash::make('12345678'),
            'email_verified_at' => now(),
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        // Create driver user
        DB::table('users')->insert([
            'name' => 'Driver User',
            'email' => 'driver@driver.com',
            'password' => Hash::make('12345678'),
            'email_verified_at' => now(),
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        // Create customer user
        DB::table('users')->insert([
            'name' => 'Customer User',
            'email' => 'customer@customer.com',
            'password' => Hash::make('12345678'),
            'email_verified_at' => now(),
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        // Assign roles
        $admin = DB::table('users')->where('email', 'admin@admin.com')->first();
        $driver = DB::table('users')->where('email', 'driver@driver.com')->first();
        $customer = DB::table('users')->where('email', 'customer@customer.com')->first();

        $adminRole = DB::table('roles')->where('name', 'admin')->first();
        $driverRole = DB::table('roles')->where('name', 'driver')->first();
        $customerRole = DB::table('roles')->where('name', 'customer')->first();

        DB::table('model_has_roles')->insert([
            ['role_id' => $adminRole->id, 'model_type' => 'App\Models\User', 'model_id' => $admin->id],
            ['role_id' => $driverRole->id, 'model_type' => 'App\Models\User', 'model_id' => $driver->id],
            ['role_id' => $customerRole->id, 'model_type' => 'App\Models\User', 'model_id' => $customer->id],
        ]);
    }

    public function down()
    {
        DB::table('model_has_roles')->whereIn('model_id', function($query) {
            $query->select('id')
                  ->from('users')
                  ->whereIn('email', ['admin@admin.com', 'driver@driver.com', 'customer@customer.com']);
        })->delete();

        DB::table('users')->whereIn('email', [
            'admin@admin.com',
            'driver@driver.com',
            'customer@customer.com'
        ])->delete();
    }
}; 