<?php
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Web\UsersController;
use App\Http\Controllers\ProductController;
use App\Http\Controllers\PurchaseController;
use App\Http\Controllers\UserCreditController;
use App\Http\Controllers\EmployeeController;

Route::get('register', [UsersController::class, 'register'])->name('register');
Route::post('register', [UsersController::class, 'doRegister'])->name('do_register');
Route::get('login', [UsersController::class, 'login'])->name('login');
Route::post('login', [UsersController::class, 'doLogin'])->name('do_login');
Route::post('logout', [UsersController::class, 'doLogout'])->name('do_logout');
Route::get('users', [UsersController::class, 'list'])->name('users');
Route::get('users/profile/{user?}', [UsersController::class, 'profile'])->name('users.profile');
Route::get('users/edit/{user?}', [UsersController::class, 'edit'])->name('users_edit');
Route::post('users/save/{user}', [UsersController::class, 'save'])->name('users_save');
Route::get('users/delete/{user}', [UsersController::class, 'delete'])->name('users_delete');
Route::get('users/edit_password/{user?}', [UsersController::class, 'editPassword'])->name('edit_password');
Route::post('users/save_password/{user}', [UsersController::class, 'savePassword'])->name('save_password');

Route::get('/', function () {
    return view('welcome');
})->name('home');

Route::get('/multable', function (Request $request) {
    $j = $request->number??5;
    $msg = $request->msg;
    return view('multable', compact("j", "msg"));
})->name('multiplication-table');

Route::get('/even', function () {
    return view('even');
})->name('even-numbers');

Route::get('/prime', function () {
    return view('prime');
})->name('prime-numbers');

Route::get('/test', function () {
    return view('test');
});

Route::middleware(['auth'])->group(function () {
    // Product routes
    Route::get('/products', [ProductController::class, 'index'])->name('products.index');
    
    // Employee routes for product management
    Route::middleware(['can:manage-products'])->group(function () {
        Route::get('/products/create', [ProductController::class, 'create'])->name('products.create');
        Route::post('/products', [ProductController::class, 'store'])->name('products.store');
        Route::get('/products/{product}/edit', [ProductController::class, 'edit'])->name('products.edit');
        Route::put('/products/{product}', [ProductController::class, 'update'])->name('products.update');
        Route::delete('/products/{product}', [ProductController::class, 'destroy'])->name('products.destroy');
    });
    
    // This needs to be after the create route
    Route::get('/products/{product}', [ProductController::class, 'show'])->name('products.show');
    
    // Purchase routes
    Route::get('/purchases', [PurchaseController::class, 'index'])->name('purchases.index');
    Route::post('/products/{product}/purchase', [PurchaseController::class, 'store'])->name('purchases.store');
    
    // Credit management routes
    Route::middleware(['can:manage-customer-credits'])->group(function () {
        Route::get('/users/{user}/credits', [UserCreditController::class, 'show'])->name('credits.show');
        Route::put('/users/{user}/credits', [UserCreditController::class, 'update'])->name('credits.update');
    });
    
    // User Management Routes
    Route::get('/users/manage', [UsersController::class, 'manageUsers'])->name('users.manage');
    Route::post('/users/{user}/manage-credit', [UsersController::class, 'manageCredit'])->name('users.manage-credit');

    // Employee Management Routes
    Route::middleware(['auth', 'can:manage-employees'])->group(function () {
        Route::resource('employees', EmployeeController::class);
    });
});
