@if($hero && $hero->background_image)
<section class="hero-section d-flex align-items-center min-vh-100 position-relative" style="background-image: url('{{ asset('storage/' . $hero->background_image) }}'); background-size: cover; background-position: left center;">
    <div style="position:absolute; inset:0; background:rgba(0,0,0,0.25); z-index:1;"></div>
    <div class="container position-relative" style="z-index:2;">
        <div class="row align-items-center">
            <div class="col-md-7 col-lg-6">
                @if($hero->heading)
                    <span class="text-uppercase text-danger fw-bold mb-3 d-block" style="letter-spacing:2px;">{{ $hero->heading }}</span>
                @endif
                @if($hero->subheading)
                    <h1 class="display-3 fw-bold mb-3">{{ $hero->subheading }}</h1>
                @endif
                @if($hero->description)
                    <p class="lead mb-4" style="color:#222;">{{ $hero->description }}</p>
                @endif
                @if($hero->button_text && $hero->button_link)
                    <a href="{{ $hero->button_link }}" class="btn btn-dark btn-lg px-5 py-3">{{ $hero->button_text }} &rarr;</a>
                @endif
            </div>
        </div>
    </div>
</section>
@endif

<style>
html, body {
    width: 100%;
    margin: 0;
    padding: 0;
    overflow-x: hidden;
}

.hero-section {
    position: relative;
    left: 50%;
    right: 50%;
    width: 100vw;
    min-width: 100vw;
    min-height: 100vh;
    margin-left: -50vw;
    margin-right: -50vw;
    display: flex;
    align-items: center;
    justify-content: flex-start;
    background-size: cover;
    background-position: left center;
    overflow: hidden;
    padding: 0;
}
.hero-section::before {
    content: '';
    position: absolute;
    inset: 0;
    background: rgba(0,0,0,0.35);
    z-index: 1;
}
.hero-content {
    position: relative;
    z-index: 2;
    text-align: left;
    max-width: 600px;
    margin-left: 0;
    padding-left: 5vw;
}
.hero-heading {
    display: block;
    color: #ff3c3c;
    font-size: 1.2rem;
    font-weight: bold;
    letter-spacing: 2px;
    margin-bottom: 1rem;
    text-transform: uppercase;
}
.hero-title {
    color: #fff;
    font-size: 3rem;
    font-weight: bold;
    margin-bottom: 1.5rem;
    line-height: 1.1;
}
.hero-desc {
    color: #f1f1f1;
    font-size: 1.2rem;
    margin-bottom: 2rem;
}
.hero-btn {
    display: inline-block;
    background: #111;
    color: #fff;
    font-size: 1.1rem;
    font-weight: bold;
    padding: 0.9rem 2.5rem;
    border-radius: 0;
    text-decoration: none;
    letter-spacing: 1px;
    transition: background 0.2s;
}
.hero-btn:hover {
    background: #ff3c3c;
    color: #fff;
}
@media (max-width: 768px) {
    .hero-content {
        padding-left: 0;
        text-align: center;
        max-width: 95vw;
    }
    .hero-title { font-size: 2rem; }
    .hero-desc { font-size: 1rem; }
}
</style>

@if(!request()->routeIs('home'))
    @include('layouts.menu')
@endif
