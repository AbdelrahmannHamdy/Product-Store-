@extends('layouts.master')
@section('title', 'Products')
@section('content')
<div class="container">
    <div class="row justify-content-center">
        <div class="col-md-10">
            <div class="card">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <h2 class="mb-0">Products</h2>
                    @can('add_products')
                    <a href="{{route('products.create')}}" class="btn btn-success">Add Product</a>
                    @endcan
                </div>
                
                <div class="card-body">
                    <form class="mb-4">
                        <div class="row g-3">
                            <div class="col-md-3">
                                <input name="keywords" type="text" class="form-control" placeholder="Search Keywords" value="{{ request()->keywords }}" />
                            </div>
                            <div class="col-md-2">
                                <input name="min_price" type="number" class="form-control" placeholder="Min Price" value="{{ request()->min_price }}"/>
                            </div>
                            <div class="col-md-2">
                                <input name="max_price" type="number" class="form-control" placeholder="Max Price" value="{{ request()->max_price }}"/>
                            </div>
                            <div class="col-md-2">
                                <select name="order_by" class="form-select">
                                    <option value="" {{ request()->order_by==""?"selected":"" }} disabled>Order By</option>
                                    <option value="name" {{ request()->order_by=="name"?"selected":"" }}>Name</option>
                                    <option value="price" {{ request()->order_by=="price"?"selected":"" }}>Price</option>
                                </select>
                            </div>
                            <div class="col-md-2">
                                <select name="order_direction" class="form-select">
                                    <option value="" {{ request()->order_direction==""?"selected":"" }} disabled>Direction</option>
                                    <option value="ASC" {{ request()->order_direction=="ASC"?"selected":"" }}>ASC</option>
                                    <option value="DESC" {{ request()->order_direction=="DESC"?"selected":"" }}>DESC</option>
                                </select>
                            </div>
                            <div class="col-md-1">
                                <button type="submit" class="btn btn-primary w-100">Search</button>
                            </div>
                        </div>
                    </form>

                    @foreach($products as $product)
                    <div class="card mb-3">
                        <div class="card-body">
                            <div class="row">
                                <div class="col-md-4">
                                    @if($product->image)
                                        <img src="{{ asset('storage/' . $product->image) }}" class="img-fluid rounded" alt="{{$product->name}}">
                                    @endif
                                </div>
                                <div class="col-md-8">
                                    <div class="d-flex justify-content-between align-items-center mb-3">
                                        <h3 class="mb-0">{{$product->name}}</h3>
                                        <div class="btn-group">
                                            @can('edit_products')
                                            <a href="{{route('products.edit', $product->id)}}" class="btn btn-outline-primary">Edit</a>
                                            @endcan
                                            @can('delete_products')
                                            <form action="{{route('products.destroy', $product->id)}}" method="POST" class="d-inline">
                                                @csrf
                                                @method('DELETE')
                                                <button type="submit" class="btn btn-outline-danger ms-2" onclick="return confirm('Are you sure you want to delete this product?')">Delete</button>
                                            </form>
                                            @endcan
                                            @can('hold_products')
                                                <form action="{{ route('products.hold', $product) }}" method="POST" class="d-inline">
                                                    @csrf
                                                    <button type="submit" class="btn {{ $product->hold ? 'btn-outline-success' : 'btn-outline-warning' }} ms-2">
                                                        {{ $product->hold ? 'Unhold' : 'Hold' }}
                                                    </button>
                                                </form>
                                            @endcan
                                        </div>
                                    </div>

                                    <table class="table table-sm">
                                        <tr><th width="20%">Model</th><td>{{$product->model}}</td></tr>
                                        <tr><th>Code</th><td>{{$product->code}}</td></tr>
                                        <tr><th>Price</th><td>${{number_format($product->price, 2)}}</td></tr>
                                        <tr><th>Description</th><td>{{$product->description}}</td></tr>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
                    @endforeach

                    @if($products->isEmpty())
                    <div class="alert alert-info">
                        No products available.
                    </div>
                    @endif
                </div>
            </div>
        </div>
    </div>
</div>
@endsection