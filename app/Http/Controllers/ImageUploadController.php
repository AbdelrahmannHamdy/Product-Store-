<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Storage;

class ImageUploadController extends Controller
{
    public function upload(Request $request)
    {
        $request->validate([
            'image' => 'required|image|mimes:jpg,jpeg,png|max:2048'
        ]);

        $path = $request->file('image')->store('images', 'public');

        return response()->json([
            'message' => 'تم رفع الصورة بنجاح',
            'path' => asset('storage/' . $path)
        ]);
    }
}
