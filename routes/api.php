<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
    return $request->user();
});

// Driver Management Routes
Route::get('/drivers/available', [App\Http\Controllers\DriverController::class, 'getAvailableDrivers']);
Route::post('/orders/{order}/assign-driver', [App\Http\Controllers\OrderController::class, 'assignDriver']);
Route::post('/orders/{order}/remove-driver', [App\Http\Controllers\OrderController::class, 'removeDriver']); 