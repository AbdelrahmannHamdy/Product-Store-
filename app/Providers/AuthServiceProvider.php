<?php

namespace App\Providers;

use Illuminate\Foundation\Support\Providers\AuthServiceProvider as ServiceProvider;
use Illuminate\Support\Facades\Gate;

class AuthServiceProvider extends ServiceProvider
{
    protected $policies = [
        //
    ];

    public function boot()
    {
        $this->registerPolicies();

        // Define gates for product management
        Gate::define('manage-products', function ($user) {
            return $user->hasAnyRole(['employee', 'admin']);
        });

        // Define gates for customer credit management
        Gate::define('manage-customer-credits', function ($user) {
            return $user->hasAnyRole(['employee', 'admin']);
        });

        // Define gates for employee management
        Gate::define('manage-employees', function ($user) {
            return $user->hasPermissionTo('manage-employees');
        });
    }
} 