@extends('layouts.app')

@section('content')
<div class="container">
    <h1>My Orders</h1>
    @if($orders->isEmpty())
        <div class="alert alert-info">No orders assigned to you yet.</div>
    @else
        <table class="table table-bordered">
            <thead>
                <tr>
                    <th>#</th>
                    <th>Customer</th>
                    <th>Product</th>
                    <th>Status</th>
                    <th>Created At</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
                @foreach($orders as $order)
                <tr>
                    <td>{{ $order->id }}</td>
                    <td>{{ $order->user->name ?? '-' }}</td>
                    <td>{{ $order->product->name ?? '-' }}</td>
                    <td>{{ $order->status }}</td>
                    <td>{{ $order->created_at }}</td>
                    <td>
                        <a href="{{ route('driver.orders.show', $order) }}" class="btn btn-info btn-sm">View</a>
                    </td>
                </tr>
                @endforeach
            </tbody>
        </table>
    @endif
</div>
@endsection