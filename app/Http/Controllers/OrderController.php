<?php

namespace App\Http\Controllers;

use App\Models\Purchase;
use App\Models\Driver;
use Illuminate\Http\Request;

class OrderController extends Controller
{
    public function assignDriver(Request $request, $id)
    {
        $driver = Driver::findOrFail($request->driver_id);

        // Check if driver is available
        if ($driver->currentOrder && $driver->currentOrder->order_status !== 'Delivered') {
            return redirect()->back()->with('error', 'Driver is currently assigned to another order');
        }

        // Assign driver to order
        $order = Purchase::findOrFail($id);
        $order->driver_id = $driver->id;
        $order->save();

        return redirect()->back()->with('success', 'Driver assigned successfully');
    }

    public function removeDriver($orderId)
    {
        $order = Purchase::findOrFail($orderId);
        
        // Remove driver from order
        $order->driver_id = null;
        $order->save();

        return redirect()->back()->with('success', 'Driver removed successfully');
    }
} 