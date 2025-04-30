@extends('layouts.app')

@section('title', $product->name)

@section('content')
<div class="container">
    <div class="row">
        <div class="col-md-6">
            @if($product->image)
                <img src="{{ asset('storage/' . $product->image) }}" class="img-fluid rounded" alt="{{ $product->name }}">
            @else
                <div class="bg-light p-5 text-center">
                    <p>No image available</p>
                </div>
            @endif
        </div>
        <div class="col-md-6">
            <h1>{{ $product->name }}</h1>
            <p class="text-muted">Code: {{ $product->code }}</p>
            <p class="text-muted">Model: {{ $product->model }}</p>
            <p>{{ $product->description }}</p>
            
            <div class="mb-3">
                <h3 class="text-primary">${{ number_format($product->price, 2) }}</h3>
                <span class="badge bg-{{ $product->stock_quantity > 0 ? 'success' : 'danger' }} mb-3">
                    {{ $product->stock_quantity > 0 ? 'In Stock' : 'Out of Stock' }}
                    ({{ $product->stock_quantity }} available)
                </span>
            </div>

            @if(auth()->check() && auth()->user()->hasRole('customer') && $product->hasBeenPurchasedBy(auth()->user()))
                <div class="mt-3">
                    <form action="{{ route('products.like', $product) }}" method="POST">
                        @csrf
                        <button type="submit" class="btn btn-outline-primary">
                            @if($product->isLikedBy(auth()->user()))
                                <i class="fas fa-heart text-danger"></i> Unlike
                            @else
                                <i class="far fa-heart"></i> Like
                            @endif
                            <span class="badge bg-secondary">{{ $product->likes_count ?? 0 }}</span>
                        </button>
                    </form>
                </div>
            @endif

            @if(auth()->check() && auth()->user()->hasRole('customer'))
                <form action="{{ route('purchases.store', $product) }}" method="POST" class="mt-3">
                    @csrf
                    <div class="input-group mb-3" style="max-width: 200px;">
                        <input type="number" name="quantity" class="form-control" value="1" min="1" max="{{ $product->stock_quantity }}">
                        <button type="submit" class="btn btn-primary">Purchase</button>
                    </div>
                </form>
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