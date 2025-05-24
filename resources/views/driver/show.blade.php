@extends('layouts.app')

@section('content')
<div class="container">
    <h1>Order #{{ $order->id }}</h1>
    <ul class="list-group mb-3">
        <li class="list-group-item"><strong>Customer:</strong> {{ $order->user->name ?? '-' }}</li>
        <li class="list-group-item"><strong>Product:</strong> {{ $order->product->name ?? '-' }}</li>
        <li class="list-group-item"><strong>Status:</strong> {{ $order->status }}</li>
        <li class="list-group-item"><strong>Created At:</strong> {{ $order->created_at }}</li>
    </ul>

    <form action="{{ route('driver.orders.updateStatus', $order) }}" method="POST" class="mb-3">
        @csrf
        <div class="mb-3">
            <label for="status" class="form-label">Update Status</label>
            <select name="status" id="status" class="form-select">
                <option value="on_the_way" {{ $order->status == 'on_the_way' ? 'selected' : '' }}>On the Way</option>
                <option value="delivered" {{ $order->status == 'delivered' ? 'selected' : '' }}>Delivered</option>
                <option value="cancelled" {{ $order->status == 'cancelled' ? 'selected' : '' }}>Cancelled</option>
            </select>
        </div>
        <button type="submit" class="btn btn-primary">Update Status</button>
    </form>

<a href="{{ route('driver.orders.index') }}" class="btn btn-secondary">Back to My Orders</a>
</div>
@endsection
