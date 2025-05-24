@extends('layouts.app')

@section('content')
    @include('partials.hero-section', ['hero' => $hero])
@endsection 

.hero-section {
    position: relative;
    width: 100vw;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
}
.hero-section > .container {
    position: relative;
    z-index: 2;
}
.hero-section > div[style*="background: rgba"] {
    z-index: 1;
} 