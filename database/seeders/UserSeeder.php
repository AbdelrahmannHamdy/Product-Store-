<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use App\Models\User;
use Illuminate\Support\Facades\Hash;

class UserSeeder extends Seeder
{
    public function run()
    {
        // Create admin user
        $admin = User::create([
            'name' => 'Admin User',
            'email' => 'admin@admin.com',
            'password' => Hash::make('12345678'),
            'email_verified_at' => now(),
        ]);
        $admin->assignRole('admin');

        // Create driver user
        $driver = User::create([
            'name' => 'Driver User',
            'email' => 'driver@driver.com',
            'password' => Hash::make('12345678'),
            'email_verified_at' => now(),
        ]);
        $driver->assignRole('driver');

        // Create customer user
        $customer = User::create([
            'name' => 'Customer User',
            'email' => 'customer@customer.com',
            'password' => Hash::make('12345678'),
            'email_verified_at' => now(),
        ]);
        $customer->assignRole('customer');
    }
}
