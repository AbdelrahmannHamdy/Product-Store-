<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Spatie\Permission\Traits\HasRoles;

class Driver extends Authenticatable
{
    use HasFactory, HasRoles;

    protected $fillable = [
        'name',
        'email',
        'phone',
        'status',
        'password'
    ];

    protected $hidden = [
        'password',
        'remember_token',
    ];

    public function currentOrder()
    {
        return $this->hasOne(Purchase::class)
            ->where('order_status', '!=', 'Delivered')
            ->latest();
    }

    public function orders()
    {
        return $this->hasMany(Purchase::class);
    }

    public function isAvailable()
    {
        return !$this->currentOrder;
    }
} 