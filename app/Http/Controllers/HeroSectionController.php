<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\HeroSection;
use Illuminate\Support\Facades\Storage;

class HeroSectionController extends Controller
{
    public function edit()
    {
        $hero = HeroSection::first() ?? new HeroSection();
        return view('admin.hero-section-edit', compact('hero'));
    }

    public function update(Request $request)
    {
        $hero = HeroSection::first() ?? new HeroSection();

        $validated = $request->validate([
            'heading' => 'nullable|string|max:255',
            'subheading' => 'nullable|string|max:255',
            'description' => 'nullable|string|max:1000',
            'button_text' => 'nullable|string|max:255',
            'button_link' => 'nullable|string|max:255',
            'overlay_opacity' => 'nullable|numeric|min:0|max:1',
            'background_image' => 'nullable|image|mimes:jpeg,png,jpg,gif,webp|max:4096'
        ]);

        if ($request->hasFile('background_image')) {
            // Delete old image if exists
            if ($hero->background_image && Storage::disk('public')->exists($hero->background_image)) {
                Storage::disk('public')->delete($hero->background_image);
            }
            $image = $request->file('background_image');
            $imageName = time() . '_' . $image->getClientOriginalName();
            $path = $image->storeAs('hero', $imageName, 'public');
            $validated['background_image'] = $path;
        }

        $hero->fill($validated);
        $hero->save();

        return redirect()->back()->with('success', 'Hero section updated successfully!');
    }
}
