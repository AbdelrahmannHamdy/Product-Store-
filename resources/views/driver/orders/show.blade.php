@extends('layouts.app')

@section('content')
<div class="container py-4">
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h2>Order #{{ $order->id }} Details</h2>
        <a href="{{ route('driver.orders.index') }}" class="btn btn-outline-secondary">
            <i class="fas fa-arrow-left"></i> Back to Orders
        </a>
    </div>

    <div class="row">
        <div class="col-md-8">
            <!-- Order Details -->
            <div class="card mb-4">
                <div class="card-header">
                    <h5 class="card-title mb-0">Order Information</h5>
                </div>
                <div class="card-body">
                    <div class="row">
                        <div class="col-md-6">
                            <h6>Customer Details</h6>
                            <p>
                                <strong>Name:</strong> {{ $order->user->name }}<br>
                                <strong>Email:</strong> {{ $order->user->email }}<br>
                                <strong>Phone:</strong> {{ $order->user->phone ?? 'Not provided' }}
                            </p>
                        </div>
                        <div class="col-md-6">
                            <h6>Order Status</h6>
                            <p>
                                <span class="badge bg-{{ $order->order_status === 'Delivered' ? 'success' : ($order->order_status === 'On the way' ? 'primary' : 'warning') }}">
                                    {{ $order->order_status }}
                                </span>
                            </p>
                            @if($order->order_status !== 'Delivered')
                                <button type="button" 
                                        class="btn btn-primary btn-sm" 
                                        data-bs-toggle="modal" 
                                        data-bs-target="#updateStatusModal">
                                    Update Status
                                </button>
                            @endif
                        </div>
                    </div>

                    <hr>

                    <div class="row">
                        <div class="col-md-6">
                            <h6>Product Details</h6>
                            <div class="d-flex align-items-center">
                                @if(optional($order->product)->image)
                                    <img src="{{ asset('storage/' . optional($order->product)->image) }}" 
                                         alt="Product" 
                                         style="width:60px; height:60px; object-fit:cover; border-radius:4px; margin-right:15px;">
                                @endif
                                <div>
                                    <strong>{{ optional($order->product)->name ?? 'Product Deleted' }}</strong><br>
                                    <span class="text-muted">Quantity: {{ $order->quantity }}</span>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <h6>Order Summary</h6>
                            <p>
                                <strong>Total Price:</strong> ${{ number_format($order->total_price, 2) }}<br>
                                <strong>Created:</strong> {{ $order->created_at->format('Y-m-d H:i') }}<br>
                                <strong>Estimated Delivery:</strong> 
                                @if($order->estimated_delivery_time)
                                    {{ \Carbon\Carbon::parse($order->estimated_delivery_time)->format('Y-m-d H:i') }}
                                @else
                                    <span class="text-muted">Not set</span>
                                @endif
                            </p>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Delivery Address -->
            <div class="card">
                <div class="card-header">
                    <h5 class="card-title mb-0">Delivery Address</h5>
                </div>
                <div class="card-body">
                    <p>
                        {{ $order->delivery_address }}<br>
                        {{ $order->delivery_city }}, {{ $order->delivery_state }} {{ $order->delivery_zip }}
                    </p>
                </div>
            </div>
        </div>

        <div class="col-md-4">
            <!-- Order Timeline -->
            <div class="card">
                <div class="card-header">
                    <h5 class="card-title mb-0">Order Timeline</h5>
                </div>
                <div class="card-body">
                    <div class="timeline">
                        <div class="timeline-item">
                            <div class="timeline-marker bg-success"></div>
                            <div class="timeline-content">
                                <h6 class="mb-0">Order Created</h6>
                                <small class="text-muted">{{ $order->created_at->format('Y-m-d H:i') }}</small>
                            </div>
                        </div>
                        @if($order->driver_assigned_at)
                        <div class="timeline-item">
                            <div class="timeline-marker bg-primary"></div>
                            <div class="timeline-content">
                                <h6 class="mb-0">Driver Assigned</h6>
                                <small class="text-muted">{{ $order->driver_assigned_at->format('Y-m-d H:i') }}</small>
                            </div>
                        </div>
                        @endif
                        @if($order->delivery_time)
                        <div class="timeline-item">
                            <div class="timeline-marker bg-success"></div>
                            <div class="timeline-content">
                                <h6 class="mb-0">Order Delivered</h6>
                                <small class="text-muted">{{ $order->delivery_time->format('Y-m-d H:i') }}</small>
                            </div>
                        </div>
                        @endif
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Update Status Modal -->
<div class="modal fade" id="updateStatusModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <form action="{{ route('driver.orders.updateStatus', $order) }}" method="POST">
                @csrf
                <div class="modal-header">
                    <h5 class="modal-title">Update Order Status</h5>
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

<style>
.timeline {
    position: relative;
    padding: 20px 0;
}

.timeline-item {
    position: relative;
    padding-left: 40px;
    margin-bottom: 20px;
}

.timeline-marker {
    position: absolute;
    left: 0;
    top: 0;
    width: 15px;
    height: 15px;
    border-radius: 50%;
}

.timeline-item:not(:last-child):before {
    content: '';
    position: absolute;
    left: 7px;
    top: 15px;
    height: calc(100% + 5px);
    width: 1px;
    background: #dee2e6;
}
</style>
@endsection 