@extends('layouts.app')

@section('content')
<div class="container py-4">
    <h2>Edit Hero Section</h2>
    @if(session('success'))
        <div class="alert alert-success">{{ session('success') }}</div>
    @endif
    <form action="{{ route('admin.hero.update') }}" method="POST" enctype="multipart/form-data">
        @csrf

        <div class="mb-3">
            <label for="background_image" class="form-label">Background Image (1920px+ recommended)</label>
            @if($hero->background_image)
                <div class="mb-2">
                    <img src="{{ asset('storage/' . $hero->background_image) }}" style="max-width: 400px;">
                </div>
            @endif
            <input type="file" class="form-control" id="background_image" name="background_image" accept="image/*">
        </div>

        <div class="mb-3">
            <label for="heading" class="form-label">Heading</label>
            <input type="text" class="form-control" id="heading" name="heading" value="{{ old('heading', $hero->heading) }}">
        </div>

        <div class="mb-3">
            <label for="subheading" class="form-label">Subheading</label>
            <input type="text" class="form-control" id="subheading" name="subheading" value="{{ old('subheading', $hero->subheading) }}">
        </div>

        <div class="mb-3">
            <label for="description" class="form-label">Description</label>
            <textarea class="form-control" id="description" name="description" rows="3">{{ old('description', $hero->description) }}</textarea>
        </div>

        <div class="mb-3">
            <label for="button_text" class="form-label">Button Text</label>
            <input type="text" class="form-control" id="button_text" name="button_text" value="{{ old('button_text', $hero->button_text) }}">
        </div>

        <div class="mb-3">
            <label for="button_link" class="form-label">Button Link</label>
            <input type="text" class="form-control" id="button_link" name="button_link" value="{{ old('button_link', $hero->button_link) }}">
        </div>

        <div class="mb-3">
            <label for="overlay_opacity" class="form-label">Overlay Opacity (0 = transparent, 1 = solid)</label>
            <input type="number" step="0.01" min="0" max="1" class="form-control" id="overlay_opacity" name="overlay_opacity" value="{{ old('overlay_opacity', $hero->overlay_opacity ?? 0.4) }}">
        </div>

        <button type="submit" class="btn btn-primary">Save</button>
    </form>
</div>
@endsection
