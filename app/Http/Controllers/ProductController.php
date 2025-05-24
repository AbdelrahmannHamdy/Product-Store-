<?php

namespace App\Http\Controllers;

use App\Models\Product;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Storage;

class ProductController extends Controller
{
    public function __construct()
    {
        // Remove any auth middleware if it exists
    }

    public function index(Request $request)
    {
        $query = Product::withCount('likes');

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

        // Filter out held products for customers
        if (auth()->check() && auth()->user()->hasRole('customer')) {
            $query->where('hold', false);
        }

        // Apply sorting
        $sortBy = $request->input('sort_by', 'likes_count');
        $sortDirection = $request->input('sort_direction', 'desc');
        
        // Validate sort field to prevent SQL injection
        $allowedSortFields = ['name', 'price', 'created_at', 'likes_count'];
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
            if ($request->hasFile('image')) {
                $image = $request->file('image');
                $filename = time() . '_' . $image->getClientOriginalName();
                $path = $image->storeAs('products', $filename, 'public');
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
            if ($request->hasFile('image')) {
                // Delete old image if exists
                if ($product->image && Storage::disk('public')->exists($product->image)) {
                    Storage::disk('public')->delete($product->image);
                }

                $image = $request->file('image');
                $filename = time() . '_' . $image->getClientOriginalName();
                $path = $image->storeAs('products', $filename, 'public');
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

    public function toggleHold(Product $product)
    {
        $product->hold = !$product->hold;
        $product->save();

        $status = $product->hold ? 'held' : 'unheld';
        return redirect()->back()->with('success', "Product has been {$status}.");
    }

    public function favourite(\App\Models\Product $product)
    {
        // تحقق أن المستخدم عميل
        if (!auth()->user()->hasRole('customer')) {
            abort(403);
        }

        $product->favourite = !$product->favourite;
        $product->save();

        return back()->with('success', 'Favourite status updated!');
    }

    public function favourites()
    {
        // لو تريد فقط مفضلة المستخدم الحالي (لو عندك جدول علاقات)، الكود يختلف
        // هنا سنعرض كل المنتجات التي favourite = 1
        $products = \App\Models\Product::where('favourite', true)->get();
        return view('products.favourites', compact('products'));
    }

    public function addReview(Request $request, Product $product)
    {
        // Removed permission check so any authenticated user can add a review
        $request->validate([
            'review' => 'required|string|min:10|max:1000'
        ]);

        $product->review = $request->review;
        $product->save();

        return back()->with('success', 'Review added successfully!');
    }
} 