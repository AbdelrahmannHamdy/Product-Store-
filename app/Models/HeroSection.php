<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class HeroSection extends Model
{
    protected $fillable = [
        'background_image',
        'heading',
        'subheading',
        'description',
        'button_text',
        'button_link',
        'overlay_opacity'
    ];
}
