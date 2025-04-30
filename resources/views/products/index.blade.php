@extends('layouts.app')

@section('content')
<div class="container">
    <div class="row mb-4">
        <div class="col">
            <h2>Products</h2>
        </div>
        @can('manage-products')
        <div class="col-auto">
            <a href="{{ route('products.create') }}" class="btn btn-primary">Add New Product</a>
        </div>
        @endcan
    </div>

    <!-- Search and Filter Form -->
    <div class="card mb-4">
        <div class="card-body">
            <form method="GET" action="{{ route('products.index') }}" class="row g-3 align-items-end">
                <div class="col-md">
                    <label for="keywords" class="form-label">Search Keywords</label>
                    <input type="text" class="form-control" id="keywords" name="keywords" value="{{ request('keywords') }}" placeholder="Search products...">
                </div>
                <div class="col-md">
                    <label for="min_price" class="form-label">Min Price</label>
                    <input type="number" class="form-control" id="min_price" name="min_price" value="{{ request('min_price') }}" placeholder="Min price" min="0" step="0.01">
                </div>
                <div class="col-md">
                    <label for="max_price" class="form-label">Max Price</label>
                    <input type="number" class="form-control" id="max_price" name="max_price" value="{{ request('max_price') }}" placeholder="Max price" min="0" step="0.01">
                </div>
                <div class="col-md">
                    <label for="sort_by" class="form-label">Sort By</label>
                    <select class="form-select" id="sort_by" name="sort_by">
                        <option value="">Select field...</option>
                        <option value="name" {{ request('sort_by') == 'name' ? 'selected' : '' }}>Name</option>
                        <option value="price" {{ request('sort_by') == 'price' ? 'selected' : '' }}>Price</option>
                        <option value="created_at" {{ request('sort_by') == 'created_at' ? 'selected' : '' }}>Date Added</option>
                    </select>
                </div>
                <div class="col-md">
                    <label for="sort_direction" class="form-label">Order</label>
                    <select class="form-select" id="sort_direction" name="sort_direction">
                        <option value="asc" {{ request('sort_direction') == 'asc' ? 'selected' : '' }}>Ascending</option>
                        <option value="desc" {{ request('sort_direction') == 'desc' ? 'selected' : '' }}>Descending</option>
                    </select>
                </div>
                <div class="col-md-auto">
                    <button type="submit" class="btn btn-primary">Submit</button>
                    <a href="{{ route('products.index') }}" class="btn btn-danger">Reset</a>
                </div>
            </form>
        </div>
    </div>

    <div class="row">
        @foreach($products as $product)
        <div class="col-12 mb-4">
            <div class="card">
                <div class="card-body">
                    <h2 class="mb-2">{{ $product->name }}</h2>
                    <p class="text-muted mb-4">Your Credit: ${{ number_format(auth()->user()->credit->amount ?? 0, 2) }}</p>

                    <div class="row mb-2 bg-light">
                        <div class="col-md-2 py-2">
                            <strong>Name</strong>
                        </div>
                        <div class="col-md-10 py-2">
                            {{ $product->name }}
                        </div>
                    </div>

                    <div class="row mb-2">
                        <div class="col-md-2 py-2">
                            <strong>Model</strong>
                        </div>
                        <div class="col-md-10 py-2">
                            {{ $product->model }}
                        </div>
                    </div>

                    <div class="row mb-2 bg-light">
                        <div class="col-md-2 py-2">
                            <strong>Code</strong>
                        </div>
                        <div class="col-md-10 py-2">
                            {{ $product->code }}
                        </div>
                    </div>

                    <div class="row mb-2">
                        <div class="col-md-2 py-2">
                            <strong>Price</strong>
                        </div>
                        <div class="col-md-10 py-2">
                            ${{ number_format($product->price, 2) }}
                        </div>
                    </div>

                    <div class="row mb-2 bg-light">
                        <div class="col-md-2 py-2">
                            <strong>Stock</strong>
                        </div>
                        <div class="col-md-10 py-2">
                            {{ $product->stock_quantity }}
                        </div>
                    </div>

                    <div class="row mb-4">
                        <div class="col-md-2 py-2">
                            <strong>Description</strong>
                        </div>
                        <div class="col-md-10 py-2">
                            {{ $product->description }}
                        </div>
                    </div>

                    <div class="row">
                        <div class="col-12 text-center">
                            @if($product->stock_quantity <= 0)
                                <button class="btn btn-secondary me-2" style="min-width: 120px;" disabled>Out of Stock</button>
                            @else
                                @if(auth()->user()->hasRole('customer'))
                                    <a href="{{ route('products.show', $product) }}" class="btn btn-info me-2" style="min-width: 120px;">View</a>
                                    <form action="{{ route('purchases.store', $product) }}" method="POST" class="d-inline">
                                        @csrf
                                        <input type="hidden" name="quantity" value="1">
                                        <button type="submit" class="btn btn-success" style="min-width: 120px;">Buy Now</button>
                                    </form>
                                @endif
                            @endif

                            @can('manage-products')
                                <a href="{{ route('products.edit', $product) }}" class="btn btn-warning me-2" style="min-width: 120px;">Edit</a>
                                <form action="{{ route('products.destroy', $product) }}" method="POST" class="d-inline">
                                    @csrf
                                    @method('DELETE')
                                    <button type="submit" class="btn btn-danger" style="min-width: 120px;" onclick="return confirm('Are you sure you want to delete this product?')">Delete</button>
                                </form>
                            @endcan

                            @if(auth()->check() && auth()->user()->can('hold_products'))
                                <form action="{{ route('products.hold', $product) }}" method="POST" class="d-inline">
                                    @csrf
                                    <button type="submit" class="btn btn-sm {{ $product->hold ? 'btn-success' : 'btn-warning' }}">
                                        {{ $product->hold ? 'Unhold' : 'Hold' }}
                                    </button>
                                </form>
                            @endif
                        </div>
                    </div>
                </div>
            </div>
        </div>
        @endforeach
    </div>

    @if($products->isEmpty())
    <div class="alert alert-info">
        No products available.
    </div>
    @endif

    <div class="d-flex justify-content-center mt-4">
        {{ $products->links() }}
    </div>
</div>
@endsection
