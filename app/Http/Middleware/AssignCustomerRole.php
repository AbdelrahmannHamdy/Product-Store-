<?php

namespace App\Http\Middleware;

use App\Models\Role;
use Closure;
use Illuminate\Http\Request;

class AssignCustomerRole
{
    public function handle(Request $request, Closure $next)
    {
        $user = $request->user();
        
        if ($user && !$user->roles()->exists()) {
            $customerRole = Role::where('name', 'customer')->first();
            if ($customerRole) {
                $user->roles()->attach($customerRole->id);
            }
        }

        return $next($request);
    }
} 