@extends('layouts.app')

@section('content')
<div class="container">
    <div class="row">
        <div class="col-md-6">
            @if($product->image)
                <img src="{{ asset('storage/' . $product->image) }}" class="img-fluid rounded" alt="{{ $product->name }}">
            @endif
        </div>
        <div class="col-md-6">
            <h1>{{ $product->name }}</h1>
            <p class="lead">{{ $product->description }}</p>
            
            <div class="mb-3">
                <h3 class="text-primary">${{ number_format($product->price, 2) }}</h3>
                <span class="badge bg-{{ $product->stock_quantity > 0 ? 'success' : 'danger' }} mb-3">
                    {{ $product->stock_quantity > 0 ? 'In Stock' : 'Out of Stock' }}
                    ({{ $product->stock_quantity }} available)
                </span>
            </div>

            <div class="mb-4">
                <p><strong>Product Code:</strong> {{ $product->code }}</p>
                <p><strong>Model:</strong> {{ $product->model }}</p>
            </div>

            @auth
                @if($product->stock_quantity > 0)
                    <form action="{{ route('purchases.store', $product) }}" method="POST" class="mb-3">
                        @csrf
                        <div class="row g-3 align-items-center">
                            <div class="col-auto">
                                <label for="quantity" class="form-label">Quantity:</label>
                            </div>
                            <div class="col-auto">
                                <input type="number" name="quantity" id="quantity" class="form-control" 
                                       value="1" min="1" max="{{ $product->stock_quantity }}" required>
                            </div>
                            <div class="col-auto">
                                <button type="submit" class="btn btn-primary">Purchase</button>
                            </div>
                        </div>
                    </form>
                @else
                    <div class="alert alert-warning">
                        This product is currently out of stock.
                    </div>
                @endif

                @if(session('error'))
                    <div class="alert alert-danger">
                        {{ session('error') }}
                    </div>
                @endif

                @if(session('success'))
                    <div class="alert alert-success">
                        {{ session('success') }}
                    </div>
                @endif
            @else
                <div class="alert alert-info">
                    Please <a href="{{ route('login') }}">login</a> to purchase this product.
                </div>
            @endauth

            <div class="mt-4">
                <a href="{{ route('products.index') }}" class="btn btn-secondary">Back to Products</a>
                @can('manage-products')
                    <a href="{{ route('products.edit', $product) }}" class="btn btn-warning">Edit Product</a>
                    <form action="{{ route('products.destroy', $product) }}" method="POST" class="d-inline">
                        @csrf
                        @method('DELETE')
                        <button type="submit" class="btn btn-danger" onclick="return confirm('Are you sure you want to delete this product?')">Delete Product</button>
                    </form>
                @endcan
            </div>
        </div>
    </div>
</div>
@endsection 