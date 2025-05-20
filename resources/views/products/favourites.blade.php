@extends('layouts.app')

@section('content')
<div class="container">
    <h2>Favourite Products</h2>
    <div class="row">
        @forelse($products as $product)
            <div class="col-md-4">
                <div class="card mb-3">
                    @if($product->image)
                        <img src="{{ asset('storage/' . $product->image) }}" class="card-img-top" alt="{{ $product->name }}">
                    @endif
                    <div class="card-body">
                        <h5 class="card-title">{{ $product->name }}</h5>
                        <p class="card-text">{{ $product->description }}</p>
                        <a href="{{ route('products.show', $product) }}" class="btn btn-primary">View</a>
                    </div>
                </div>
            </div>
        @empty
            <p>No favourite products found.</p>
        @endforelse
    </div>
</div>
@endsection 