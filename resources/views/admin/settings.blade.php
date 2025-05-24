@extends('layouts.app')

@section('content')
<div class="container py-4">
    <h2>Site Settings</h2>
    @if(session('success'))
        <div class="alert alert-success">{{ session('success') }}</div>
    @endif
    <form method="POST" action="{{ route('admin.settings.update') }}" enctype="multipart/form-data">
        @csrf
        <div class="mb-3">
            <label for="hero_image" class="form-label">Hero Section Image</label>
            <input type="file" class="form-control" name="hero_image" id="hero_image">
            @if($heroImage)
                <img src="{{ asset('storage/' . $heroImage) }}" alt="Current Hero" style="max-width:300px; margin-top:10px;">
            @endif
        </div>
        <button type="submit" class="btn btn-primary">Save</button>
    </form>
</div>
@endsection