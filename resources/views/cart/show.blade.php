@extends('layouts.app')

@section('content')
<div class="container py-4">
    <h2 class="mb-4">Shopping Cart</h2>
    @if(count($cart) === 0)
        <div class="alert alert-info">Your cart is empty.</div>
    @else
    <div class="row">
        <div class="col-lg-8">
            <table class="table align-middle">
                <thead>
                    <tr>
                        <th>Product</th>
                        <th>Price</th>
                        <th>Quantity</th>
                        <th>Subtotal</th>
                        <th></th>
                    </tr>
                </thead>
                <tbody>
                    @foreach($cart as $item)
                    <tr>
                        <td class="d-flex align-items-center">
                            <img src="{{ $item['image'] ? asset('storage/' . $item['image']) : 'https://via.placeholder.com/60x60?text=Product' }}" class="rounded me-2" style="width:60px;height:60px;object-fit:cover;">
                            <span>{{ $item['name'] }}</span>
                        </td>
                        <td>E£{{ number_format($item['price'], 2) }}</td>
                        <td>
                            <form action="{{ route('cart.updateQty', $item['product_id']) }}" method="POST" class="d-flex align-items-center">
                                @csrf
                                <input type="number" name="quantity" value="{{ $item['quantity'] }}" min="1" class="form-control form-control-sm w-50 me-2">
                                <button type="submit" class="btn btn-outline-secondary btn-sm">Update</button>
                            </form>
                        </td>
                        <td>E£{{ number_format($item['price'] * $item['quantity'], 2) }}</td>
                        <td>
                            <form action="{{ route('cart.remove', $item['product_id']) }}" method="POST">
                                @csrf
                                <button type="submit" class="btn btn-outline-danger btn-sm">Remove</button>
                            </form>
                        </td>
                    </tr>
                    @endforeach
                </tbody>
            </table>
        </div>
        <div class="col-lg-4">
            <div class="card">
                <div class="card-body">
                    <h5 class="card-title">Order Summary</h5>
                    <div class="d-flex justify-content-between mb-2">
                        <span>Subtotal:</span>
                        <span>E£{{ number_format($subtotal, 2) }}</span>
                    </div>
                    <div class="d-flex justify-content-between mb-2">
                        <span>Shipping:</span>
                        <span>E£{{ number_format($shipping, 2) }}</span>
                    </div>
                    <hr>
                    <div class="d-flex justify-content-between mb-3">
                        <strong>Total:</strong>
                        <strong>E£{{ number_format($total, 2) }}</strong>
                    </div>
                    <form action="{{ route('checkout.show') }}" method="GET">
                        @csrf
                        <button type="submit" class="btn btn-primary w-100">Proceed to Checkout</button>
                    </form>
                </div>
            </div>
        </div>
    </div>
    @endif
</div>
@endsection 