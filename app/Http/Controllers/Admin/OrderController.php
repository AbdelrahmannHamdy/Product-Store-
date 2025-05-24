<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Models\Purchase;
use App\Models\Driver;
use App\Models\User;
use Illuminate\Http\Request;

class OrderController extends Controller
{
    public function index(Request $request)
    {
        $query = Purchase::with(['user', 'product', 'driver']);

        if ($request->status) {
            $query->where('order_status', $request->status);
        }

        if ($request->date) {
            $query->whereDate('created_at', $request->date);
        }

        $purchases = $query->latest()->paginate(10);

        // Get all drivers with their current orders
        $drivers = User::role('driver')->get();

        // Map drivers to include availability status
        $availableDrivers = $drivers->map(function($driver) {
            return [
                'id' => $driver->id,
                'name' => $driver->name,
                'is_available' => $driver->isAvailable(),
                'current_order_id' => optional($driver->currentOrder)->id
            ];
        });

        return view('admin.orders.index', compact('purchases', 'availableDrivers'));
    }

    public function driverOrders()
    {
        $orders = Purchase::where('driver_id', auth()->id())
            ->with(['user', 'product'])
            ->latest()
            ->get();
        return view('driver.orders.index', compact('orders'));
    }

    public function driverOrderShow(Purchase $order)
    {
        abort_unless($order->driver_id == auth()->id(), 403);
        return view('driver.orders.show', compact('order'));
    }

    public function updateStatus(Request $request, Purchase $order)
    {
        abort_unless($order->driver_id == auth()->id(), 403);
        
        $request->validate([
            'order_status' => 'required|in:Pending,On the way,Delivered'
        ]);

        $order->order_status = $request->order_status;
        if ($request->order_status === 'Delivered') {
            $order->delivered_at = now();
        }
        $order->save();

        return redirect()->back()->with('success', 'Order status updated successfully!');
    }

    public function createDriver()
    {
        return view('admin.drivers.create');
    }

    public function storeDriver(Request $request)
    {
        $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|email|unique:users,email',
            'phone' => 'required|string|max:20',
            'password' => 'required|string|min:6|confirmed',
        ]);

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'phone' => $request->phone,
            'password' => Hash::make($request->password),
        ]);

        $user->assignRole('driver');

        return redirect()->route('admin.orders.index')->with('success', 'Driver added successfully!');
    }

    public function assignDriver(Request $request, $orderId)
    {
        $request->validate([
            'driver_id' => 'required|exists:users,id'
        ]);

        $order = Purchase::findOrFail($orderId);
        $order->driver_id = $request->driver_id;
        $order->save();

        return redirect()->back()->with('success', 'Driver assigned successfully!');
    }
}
