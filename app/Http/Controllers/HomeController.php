<?php

namespace App\Http\Controllers;

use App\Models\HeroSection;

class HomeController extends Controller
{
    public function home()
    {
        $hero = HeroSection::first();
        return view('home', compact('hero'));
    }
} 