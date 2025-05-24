<?php

namespace App\Http\Controllers;

use App\Models\Driver;
use Illuminate\Http\Request;

class DriverController extends Controller
{
    public function getAvailableDrivers()
    {
        $drivers = Driver::with(['currentOrder' => function($query) {
            $query->where('order_status', '!=', 'Delivered');
        }])->get();

        return response()->json($drivers->map(function($driver) {
            return [
                'id' => $driver->id,
                'name' => $driver->name,
                'is_available' => !$driver->currentOrder,
                'current_order_id' => $driver->currentOrder ? $driver->currentOrder->id : null
            ];
        }));
    }
} 