<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use Spatie\Permission\Models\Role;
use Spatie\Permission\Models\Permission;

class RoleSeeder extends Seeder
{
    public function run(): void
    {
        // Create permissions
        $createUsers = Permission::firstOrCreate(['name' => 'create_users']);
        $manageUsers = Permission::firstOrCreate(['name' => 'manage_users']);
        
        // Create roles
        $manager = Role::firstOrCreate(['name' => 'manager']);
        $admin = Role::firstOrCreate(['name' => 'admin']);
        $driver = Role::firstOrCreate(['name' => 'driver']);
        $customer = Role::firstOrCreate(['name' => 'customer']);
        
        // Assign permissions to manager
        $manager->syncPermissions([
            $createUsers,
            $manageUsers
        ]);
        
        // Assign permissions to admin (except create_users)
        $admin->syncPermissions([
            $manageUsers
        ]);
    }
} 