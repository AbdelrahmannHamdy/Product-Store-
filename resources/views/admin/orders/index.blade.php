@extends('layouts.app')

@section('content')
<div class="container py-4">
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h2>Order Management</h2>
        <div class="d-flex gap-2">
            <select class="form-select" id="statusFilter">
                <option value="">All Statuses</option>
                <option value="Pending">Pending</option>
                <option value="On the way">On the way</option>
                <option value="Delivered">Delivered</option>
            </select>
            <input type="date" class="form-control" id="dateFilter" placeholder="Filter by date">
        </div>
    </div>

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
                            <th>Driver</th>
                            <th>Created</th>
                            <th>Est. Delivery</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        @forelse($purchases as $purchase)
                        <tr>
                            <td>#{{ $purchase->id }}</td>
                            <td>
                                <div>{{ $purchase->user->name }}</div>
                                <small class="text-muted">{{ $purchase->user->email }}</small>
                            </td>
                            <td>
                                <div>{{ optional($purchase->product)->name ?? 'Product Deleted' }}</div>
                                @if(optional($purchase->product)->image)
                                    <img src="{{ asset('storage/' . optional($purchase->product)->image) }}" 
                                         alt="Product" 
                                         style="width:40px; height:40px; object-fit:cover; border-radius:4px;">
                                @endif
                            </td>
                            <td>{{ $purchase->quantity }}</td>
                            <td>${{ number_format($purchase->total_price, 2) }}</td>
                            <td>
                                <span class="badge bg-{{ $purchase->order_status === 'Delivered' ? 'success' : ($purchase->order_status === 'On the way' ? 'primary' : 'warning') }}">
                                    {{ $purchase->order_status }}
                                </span>
                            </td>
                            <td>
                                <div class="driver-assignment" data-order-id="{{ $purchase->id }}">
                                    @if($purchase->driver)
                                        <div class="current-driver">
                                            <span class="badge bg-info">{{ $purchase->driver->name }}</span>
                                            <form action="{{ route('orders.remove-driver', $purchase->id) }}" method="POST" class="d-inline">
                                                @csrf
                                                <button type="submit" class="btn btn-sm btn-outline-danger ms-2">
                                                    <i class="fas fa-times"></i>
                                                </button>
                                            </form>
                                        </div>
                                    @else
                                        <form action="{{ route('orders.assign-driver', $purchase->id) }}" method="POST">
                                            @csrf
                                            <div class="input-group input-group-sm">
                                                <select name="driver_id" class="form-select">
                                                    <option value="">Select Driver</option>
                                                    @foreach($availableDrivers as $driver)
                                                        <option value="{{ $driver['id'] }}" {{ !$driver['is_available'] ? 'disabled' : '' }}>
                                                            {{ $driver['name'] }} {{ !$driver['is_available'] ? '(Busy)' : '' }}
                                                        </option>
                                                    @endforeach
                                                </select>
                                                <button type="submit" class="btn btn-primary">Assign</button>
                                            </div>
                                        </form>
                                    @endif
                                </div>
                            </td>
                            <td>{{ $purchase->created_at->format('Y-m-d H:i') }}</td>
                            <td>
                                @if($purchase->estimated_delivery_time)
                                    {{ \Carbon\Carbon::parse($purchase->estimated_delivery_time)->format('Y-m-d H:i') }}
                                @else
                                    <span class="text-muted">Not set</span>
                                @endif
                            </td>
                            <td>
                                <div class="btn-group">
                                    <a href="{{ route('purchases.tracking', $purchase) }}" 
                                       class="btn btn-sm btn-outline-primary">
                                        <i class="fas fa-eye"></i> View
                                    </a>
                                    <button type="button" 
                                            class="btn btn-sm btn-outline-secondary" 
                                            data-bs-toggle="modal" 
                                            data-bs-target="#updateStatusModal{{ $purchase->id }}">
                                        <i class="fas fa-edit"></i> Update
                                    </button>
                                </div>

                                <!-- Update Status Modal -->
                                <div class="modal fade" id="updateStatusModal{{ $purchase->id }}" tabindex="-1">
                                    <div class="modal-dialog">
                                        <div class="modal-content">
                                            <form action="{{ route('purchases.updateStatus', $purchase) }}" method="POST">
                                                @csrf
                                                <div class="modal-header">
                                                    <h5 class="modal-title">Update Order #{{ $purchase->id }} Status</h5>
                                                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                                                </div>
                                                <div class="modal-body">
                                                    <div class="mb-3">
                                                        <label class="form-label">Order Status</label>
                                                        <select name="order_status" class="form-select">
                                                            <option value="Pending" {{ $purchase->order_status == 'Pending' ? 'selected' : '' }}>Pending</option>
                                                            <option value="On the way" {{ $purchase->order_status == 'On the way' ? 'selected' : '' }}>On the way</option>
                                                            <option value="Delivered" {{ $purchase->order_status == 'Delivered' ? 'selected' : '' }}>Delivered</option>
                                                        </select>
                                                    </div>
                                                    <div class="mb-3">
                                                        <label class="form-label">Estimated Delivery Time</label>
                                                        <input type="datetime-local" 
                                                               name="estimated_delivery_time" 
                                                               class="form-control"
                                                               value="{{ $purchase->estimated_delivery_time ? \Carbon\Carbon::parse($purchase->estimated_delivery_time)->format('Y-m-d\\TH:i') : '' }}">
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
                            <td colspan="10" class="text-center">No orders found.</td>
                        </tr>
                        @endforelse
                    </tbody>
                </table>
            </div>

            <div class="d-flex justify-content-center mt-4">
                {{ $purchases->links() }}
            </div>
        </div>
    </div>
</div>

@push('scripts')
<script>
document.addEventListener('DOMContentLoaded', function() {
    const statusFilter = document.getElementById('statusFilter');
    const dateFilter = document.getElementById('dateFilter');

    function applyFilters() {
        const status = statusFilter.value;
        const date = dateFilter.value;
        let url = new URL(window.location.href);
        
        if (status) url.searchParams.set('status', status);
        else url.searchParams.delete('status');
        
        if (date) url.searchParams.set('date', date);
        else url.searchParams.delete('date');
        
        window.location.href = url.toString();
    }

    statusFilter.addEventListener('change', applyFilters);
    dateFilter.addEventListener('change', applyFilters);

    // Load available drivers for each order
    loadAvailableDrivers();
});

function loadAvailableDrivers() {
    fetch('/api/drivers/available')
        .then(response => response.json())
        .then(data => {
            const driverSelects = document.querySelectorAll('.driver-select');
            driverSelects.forEach(select => {
                data.forEach(driver => {
                    const option = document.createElement('option');
                    option.value = driver.id;
                    option.textContent = driver.name;
                    option.className = driver.is_available ? 'text-success' : 'text-muted';
                    option.disabled = !driver.is_available;
                    select.appendChild(option);
                });
            });
        })
        .catch(error => console.error('Error loading drivers:', error));
}

function assignDriver(orderId, driverId) {
    if (!driverId) return;

    fetch(`/api/orders/${orderId}/assign-driver`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-TOKEN': document.querySelector('meta[name="csrf-token"]').content
        },
        body: JSON.stringify({ driver_id: driverId })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            const driverAssignment = document.querySelector(`.driver-assignment[data-order-id="${orderId}"]`);
            driverAssignment.innerHTML = `
                <div class="current-driver">
                    <span class="badge bg-info">${data.driver.name}</span>
                    <button class="btn btn-sm btn-outline-danger ms-2" onclick="removeDriver(${orderId})">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
            `;
            // Reload available drivers for other orders
            loadAvailableDrivers();
        }
    })
    .catch(error => console.error('Error assigning driver:', error));
}

function removeDriver(orderId) {
    fetch(`/api/orders/${orderId}/remove-driver`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-TOKEN': document.querySelector('meta[name="csrf-token"]').content
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            const driverAssignment = document.querySelector(`.driver-assignment[data-order-id="${orderId}"]`);
            driverAssignment.innerHTML = `
                <select class="form-select form-select-sm driver-select" onchange="assignDriver(${orderId}, this.value)">
                    <option value="">Select Driver</option>
                </select>
            `;
            // Reload available drivers
            loadAvailableDrivers();
        }
    })
    .catch(error => console.error('Error removing driver:', error));
}
</script>
@endpush
@endsection 