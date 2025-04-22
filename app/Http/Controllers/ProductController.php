<?php

namespace App\Http\Controllers;

use App\Models\Product;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Storage;

class ProductController extends Controller
{
    public function index(Request $request)
    {
        $query = Product::query();

        // Apply keyword search
        if ($request->filled('keywords')) {
            $keywords = $request->keywords;
            $query->where(function($q) use ($keywords) {
                $q->where('name', 'like', "%{$keywords}%")
                  ->orWhere('description', 'like', "%{$keywords}%")
                  ->orWhere('code', 'like', "%{$keywords}%");
            });
        }

        // Apply price filters
        if ($request->filled('min_price')) {
            $query->where('price', '>=', $request->min_price);
        }
        if ($request->filled('max_price')) {
            $query->where('price', '<=', $request->max_price);
        }

        // Apply sorting
        $sortBy = $request->input('sort_by', 'created_at');
        $sortDirection = $request->input('sort_direction', 'desc');
        
        // Validate sort field to prevent SQL injection
        $allowedSortFields = ['name', 'price', 'created_at'];
        if (in_array($sortBy, $allowedSortFields)) {
            $query->orderBy($sortBy, $sortDirection);
        }

        $products = $query->paginate(12)->withQueryString();
        
        return view('products.index', compact('products'));
    }

    public function show(Product $product)
    {
        return view('products.show', compact('product'));
    }

    public function create()
    {
        Gate::authorize('manage-products');
        return view('products.create');
    }

    public function store(Request $request)
    {
        Gate::authorize('manage-products');

        $validated = $request->validate([
            'name' => 'required|string|max:255',
            'code' => 'required|string|max:255|unique:products',
            'model' => 'required|string|max:255',
            'description' => 'required|string',
            'price' => 'required|numeric|min:0',
            'stock_quantity' => 'required|integer|min:0',
            'image' => 'nullable|image|mimes:jpeg,png,jpg,gif|max:2048'
        ]);

        try {
            // Handle image upload
            if ($request->hasFile('image')) {
                $image = $request->file('image');
                $imageName = time() . '_' . $image->getClientOriginalName();
                $path = $image->storeAs('products', $imageName, 'public');
                if (!$path) {
                    throw new \Exception('Failed to upload image');
                }
                $validated['image'] = $path;
            }

            $product = Product::create($validated);

            return redirect()->route('products.index')
                ->with('success', 'Product created successfully.');
        } catch (\Exception $e) {
            return back()->withInput()
                ->withErrors(['error' => 'Failed to create product. ' . $e->getMessage()]);
        }
    }

    public function edit(Product $product)
    {
        Gate::authorize('manage-products');
        return view('products.edit', compact('product'));
    }

    public function update(Request $request, Product $product)
    {
        Gate::authorize('manage-products');

        $validated = $request->validate([
            'name' => 'required|string|max:255',
            'code' => 'required|string|max:255|unique:products,code,' . $product->id,
            'model' => 'required|string|max:255',
            'description' => 'required|string',
            'price' => 'required|numeric|min:0',
            'stock_quantity' => 'required|integer|min:0',
            'image' => 'nullable|image|mimes:jpeg,png,jpg,gif|max:2048'
        ]);

        try {
            // Handle image upload
            if ($request->hasFile('image')) {
                // Delete old image if exists
                if ($product->image && Storage::disk('public')->exists($product->image)) {
                    Storage::disk('public')->delete($product->image);
                }

                $image = $request->file('image');
                $imageName = time() . '_' . $image->getClientOriginalName();
                $path = $image->storeAs('products', $imageName, 'public');
                if (!$path) {
                    throw new \Exception('Failed to upload image');
                }
                $validated['image'] = $path;
            }

            $product->update($validated);

            return redirect()->route('products.index')
                ->with('success', 'Product updated successfully.');
        } catch (\Exception $e) {
            return back()->withInput()
                ->withErrors(['error' => 'Failed to update product. ' . $e->getMessage()]);
        }
    }

    public function destroy(Product $product)
    {
        Gate::authorize('manage-products');

        try {
            // Delete image if exists
            if ($product->image && Storage::disk('public')->exists($product->image)) {
                Storage::disk('public')->delete($product->image);
            }

            $product->delete();

            return redirect()->route('products.index')
                ->with('success', 'Product deleted successfully.');
        } catch (\Exception $e) {
            return back()->withErrors(['error' => 'Failed to delete product. ' . $e->getMessage()]);
        }
    }
} 