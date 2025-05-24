<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use App\Models\HeroSection;

class HeroSectionSeeder extends Seeder
{
    public function run()
    {
        HeroSection::create([
            'title' => 'Welcome to Our Security Service',
            'description' => 'Professional security solutions for your peace of mind',
            'button_text' => 'Get Started',
            'button_link' => '/contact',
            'is_active' => true
        ]);
    }
} 