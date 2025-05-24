@extends('layouts.app')

@section('content')
<div class="container py-4">
    <h2 class="mb-4">My Orders</h2>

    <div class="card">
        <div class="card-body">
            <div class="table-responsive">
                <table class="table table-hover">
                    <thead>
                        <tr>
                            <th>Order ID</th>
                            <th>Customer</th>
                            <th>Product</th>
                            <th>Quantity</th>
                            <th>Total</th>
                            <th>Status</th>
                            <th>Created</th>
                            <th>Est. Delivery</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        @forelse($orders as $order)
                        <tr>
                            <td>#{{ $order->id }}</td>
                            <td>
                                <div>{{ $order->user->name }}</div>
                                <small class="text-muted">{{ $order->user->email }}</small>
                            </td>
                            <td>
                                <div>{{ optional($order->product)->name ?? 'Product Deleted' }}</div>
                                @if(optional($order->product)->image)
                                    <img src="{{ asset('storage/' . optional($order->product)->image) }}" 
                                         alt="Product" 
                                         style="width:40px; height:40px; object-fit:cover; border-radius:4px;">
                                @endif
                            </td>
                            <td>{{ $order->quantity }}</td>
                            <td>${{ number_format($order->total_price, 2) }}</td>
                            <td>
                                <span class="badge bg-{{ $order->order_status === 'Delivered' ? 'success' : ($order->order_status === 'On the way' ? 'primary' : 'warning') }}">
                                    {{ $order->order_status }}
                                </span>
                            </td>
                            <td>{{ $order->created_at->format('Y-m-d H:i') }}</td>
                            <td>
                                @if($order->estimated_delivery_time)
                                    {{ \Carbon\Carbon::parse($order->estimated_delivery_time)->format('Y-m-d H:i') }}
                                @else
                                    <span class="text-muted">Not set</span>
                                @endif
                            </td>
                            <td>
                                <div class="btn-group">
                                    <a href="{{ route('driver.orders.show', $order) }}" 
                                       class="btn btn-sm btn-outline-primary">
                                        <i class="fas fa-eye"></i> View
                                    </a>
                                    @if($order->order_status !== 'Delivered')
                                        <button type="button" 
                                                class="btn btn-sm btn-outline-secondary" 
                                                data-bs-toggle="modal" 
                                                data-bs-target="#updateStatusModal{{ $order->id }}">
                                            <i class="fas fa-edit"></i> Update
                                        </button>
                                    @endif
                                </div>

                                <!-- Update Status Modal -->
                                <div class="modal fade" id="updateStatusModal{{ $order->id }}" tabindex="-1">
                                    <div class="modal-dialog">
                                        <div class="modal-content">
                                            <form action="{{ route('driver.orders.updateStatus', $order) }}" method="POST">
                                                @csrf
                                                <div class="modal-header">
                                                    <h5 class="modal-title">Update Order #{{ $order->id }} Status</h5>
                                                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                                                </div>
                                                <div class="modal-body">
                                                    <div class="mb-3">
                                                        <label class="form-label">Order Status</label>
                                                        <select name="order_status" class="form-select">
                                                            <option value="Pending" {{ $order->order_status == 'Pending' ? 'selected' : '' }}>Pending</option>
                                                            <option value="On the way" {{ $order->order_status == 'On the way' ? 'selected' : '' }}>On the way</option>
                                                            <option value="Delivered" {{ $order->order_status == 'Delivered' ? 'selected' : '' }}>Delivered</option>
                                                        </select>
                                                    </div>
                                                </div>
                                                <div class="modal-footer">
                                                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                                                    <button type="submit" class="btn btn-primary">Update Status</button>
                                                </div>
                                            </form>
                                        </div>
                                    </div>
                                </div>
                            </td>
                        </tr>
                        @empty
                        <tr>
                            <td colspan="9" class="text-center">No orders assigned to you yet.</td>
                        </tr>
                        @endforelse
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>
@endsection 