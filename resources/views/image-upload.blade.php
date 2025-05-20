@extends('layouts.app')

@section('content')
<div class="container mt-5">
    <div class="row justify-content-center">
        <div class="col-md-8">
            <div class="card">
                <div class="card-header">رفع صورة</div>

                <div class="card-body">
                    @if(session('success'))
                        <div class="alert alert-success">
                            {{ session('success') }}
                        </div>
                    @endif

                    <form action="{{ route('image.upload') }}" method="POST" enctype="multipart/form-data">
                        @csrf
                        <div class="mb-3">
                            <label for="image" class="form-label">اختر صورة</label>
                            <input class="form-control" type="file" id="image" name="image" required>
                        </div>
                        <button type="submit" class="btn btn-primary">رفع</button>
                    </form>

                    @if(session('image'))
                        <div class="mt-3">
                            <p>الصورة المرفوعة:</p>
                            <img src="{{ asset(session('image')) }}" alt="الصورة" style="max-width: 300px;">
                        </div>
                    @endif
                </div>
            </div>
        </div>
    </div>
</div>
@endsection 