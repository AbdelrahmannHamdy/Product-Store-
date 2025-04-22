<?php

namespace App\Http\Controllers;

use App\Models\Product;
use App\Models\Purchase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class PurchaseController extends Controller
{
    public function index()
    {
        $purchases = Auth::user()->purchases()->with('product')->get();
        return view('purchases.index', compact('purchases'));
    }

    public function store(Request $request, Product $product)
    {
        $request->validate([
            'quantity' => 'required|integer|min:1'
        ]);

        $quantity = $request->input('quantity');
        $user = Auth::user();

        if (!$user->hasRole('customer')) {
            return redirect()->back()->with('error', 'Only customers can make purchases.');
        }

        $result = $user->purchaseProduct($product, $quantity);

        if ($result) {
            return redirect()->route('purchases.index')
                ->with('success', 'Purchase completed successfully.');
        }

        return redirect()->back()->with('error', 'Unable to complete purchase. Please check your credit balance and product availability.');
    }
} 