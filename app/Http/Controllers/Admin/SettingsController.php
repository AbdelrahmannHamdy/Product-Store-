<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class SettingsController extends Controller
{
    public function edit()
    {
        $heroImage = DB::table('settings')->where('key', 'hero_image')->value('value');
        return view('admin.settings', compact('heroImage'));
    }

    public function update(Request $request)
    {
        if ($request->hasFile('hero_image')) {
            $image = $request->file('hero_image');
            $imageName = time() . '_' . $image->getClientOriginalName();
            $path = $image->storeAs('hero', $imageName, 'public');
            DB::table('settings')->updateOrInsert(
                ['key' => 'hero_image'],
                ['value' => $path]
            );
        }
        return back()->with('success', 'Hero image updated!');
    }
}
