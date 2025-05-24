<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Web\UsersController;
use App\Http\Controllers\ProductController;
use App\Http\Controllers\PurchaseController;
use App\Http\Controllers\UserCreditController;

use App\Http\Controllers\ProductLikeController;
use App\Http\Controllers\GoogleController;
use Illuminate\Auth\Events\Verified;
use Illuminate\Foundation\Auth\EmailVerificationRequest;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Spatie\Permission\Traits\HasRoles;
use App\Http\Controllers\Admin\OrderController;
use App\Http\Controllers\ImageUploadController;
use App\Http\Controllers\HomeController;
use App\Http\Controllers\HeroSectionController;
use App\Models\HeroSection;
use Illuminate\Support\Facades\Hash;
use Spatie\Permission\Models\Role;
use Illuminate\Support\Facades\Storage;

Route::get('register', [UsersController::class, 'register'])->name('register');
Route::post('register', [UsersController::class, 'doRegister'])->name('do_register');
Route::get('login', [UsersController::class, 'login'])->name('login');
Route::post('login', [UsersController::class, 'doLogin'])->name('do_login');
Route::post('logout', [UsersController::class, 'doLogout'])->name('logout');
Route::get('/users', [\App\Http\Controllers\Web\UsersController::class, 'list'])->name('users.index');
Route::get('users/profile/{user?}', [UsersController::class, 'profile'])->name('users.profile');
Route::get('users/edit/{user?}', [UsersController::class, 'edit'])->name('users_edit');
Route::post('users/save/{user}', [UsersController::class, 'save'])->name('users_save');
Route::get('users/delete/{user}', [UsersController::class, 'delete'])->name('users_delete');
Route::get('users/edit_password/{user?}', [UsersController::class, 'editPassword'])->name('edit_password');
Route::post('users/save_password/{user}', [UsersController::class, 'savePassword'])->name('save_password');

Route::get('/', [HomeController::class, 'home'])->name('home');

// Public routes for products and cart
Route::get('/clothes', [ProductController::class, 'index'])->name('products.index');

// ضع هذا قبل روت show
Route::middleware(['auth', 'role:admin|manager'])->group(function () {
    Route::get('/clothes/create', [ProductController::class, 'create'])->name('products.create');
    // باقي روتات الإدارة
});

Route::get('/clothes/{product}', [ProductController::class, 'show'])->name('products.show');

// Cart routes (public)
Route::post('/cart/buy-now/{product}', [\App\Http\Controllers\CartController::class, 'buyNow'])->name('cart.buyNow');
Route::post('/cart/add/{product}', [\App\Http\Controllers\CartController::class, 'add'])->name('cart.add');
Route::get('/cart', [\App\Http\Controllers\CartController::class, 'show'])->name('cart.show');
Route::post('/cart/remove/{product}', [\App\Http\Controllers\CartController::class, 'remove'])->name('cart.remove');
Route::post('/cart/update-qty/{product}', [\App\Http\Controllers\CartController::class, 'updateQty'])->name('cart.updateQty');

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

// Protected routes
Route::middleware(['auth'])->group(function () {
    // Product routes - غيرناها لـ clothes
    Route::get('/clothes/dashboard', [ProductController::class, 'index'])->middleware('auth')->name('products.dashboard');

    // Employee routes for product management
    Route::middleware(['auth', 'role:admin|manager'])->group(function () {
        Route::get('/clothes/create', [ProductController::class, 'create'])->name('products.create');
        Route::post('/clothes', [ProductController::class, 'store'])->name('products.store');
        Route::get('/clothes/{product}/edit', [ProductController::class, 'edit'])->name('products.edit');
        Route::put('/clothes/{product}', [ProductController::class, 'update'])->name('products.update');
        Route::delete('/clothes/{product}', [ProductController::class, 'destroy'])->name('products.destroy');
        Route::post('/clothes/{product}/hold', [ProductController::class, 'toggleHold'])
            ->name('products.hold')
            ->middleware('can:hold_products');
    });

    // Purchase routes
    Route::get('/purchases', [PurchaseController::class, 'index'])->name('purchases.index');
    Route::post('/clothes/{product}/purchase', [PurchaseController::class, 'store'])->name('purchases.store');

    // Credit management routes
    Route::middleware(['can:manage-customer-credits'])->group(function () {
        Route::get('/users/{user}/credits', [UserCreditController::class, 'show'])->name('credits.show');
        Route::put('/users/{user}/credits', [UserCreditController::class, 'update'])->name('credits.update');
    });

    // User Management Routes
    Route::get('/users/manage', [UsersController::class, 'manageUsers'])
        ->middleware(['role:admin|manager'])
        ->name('users.manage');
    
    Route::post('/users/{user}/manage-credit', [UserCreditController::class, 'manageCredit'])
        ->middleware(['role:admin|manager'])
        ->name('users.manage-credit');
    
    // User creation routes (manager only)
    Route::middleware(['role:manager'])->group(function () {
        Route::get('/users/create', [UsersController::class, 'create'])->name('users.create');
        Route::post('/users', [UsersController::class, 'store'])->name('users.store');
    });

    // Product like routes
    Route::post('/clothes/{product}/like', [ProductLikeController::class, 'toggleLike'])
        ->name('products.like')
        ->middleware('auth');

    // Product review routes
    Route::post('/clothes/{product}/review', [ProductController::class, 'addReview'])
        ->name('products.review')
        ->middleware('auth');

    // Checkout routes
    Route::get('/checkout', [\App\Http\Controllers\CheckoutController::class, 'show'])->name('checkout.show');
    Route::post('/checkout', [\App\Http\Controllers\CheckoutController::class, 'process'])->name('checkout.process');

    // Product favourite routes
    Route::post('/clothes/{product}/favourite', [ProductController::class, 'favourite'])->name('products.favourite')->middleware('auth');
});

// Google Authentication Routes
Route::get('auth/google', [GoogleController::class, 'redirectToGoogle'])->name('google.login');
Route::get('auth/google/callback', [GoogleController::class, 'handleGoogleCallback'])->name('google.callback');

// Email Verification Routes
Route::middleware(['auth'])->group(function () {
    Route::get('/email/verify', function () {
        return view('auth.verify-email');
    })->name('verification.notice');

    Route::get('/email/verify/{id}/{hash}', function (EmailVerificationRequest $request) {
        $request->fulfill();
        return redirect()->route('products.index')->with('success', 'Email verified successfully!');
    })->middleware(['signed'])->name('verification.verify');

    Route::post('/email/verification-notification', function (Request $request) {
        $request->user()->sendEmailVerificationNotification();
        return back()->with('success', 'Verification link sent!');
    })->middleware(['throttle:6,1'])->name('verification.send');
});

Route::get('/purchases/{purchase}/tracking', [\App\Http\Controllers\PurchaseController::class, 'tracking'])->name('purchases.tracking');
Route::middleware(['role:admin|driver'])->group(function () {
    Route::post('/purchases/{purchase}/update-status', [\App\Http\Controllers\PurchaseController::class, 'updateStatus'])->name('purchases.updateStatus');
});

// Admin Routes
Route::middleware(['role:admin'])->group(function () {
    Route::get('/admin/orders', [OrderController::class, 'index'])->name('admin.orders.index');
});

Route::post('/upload-image', [ImageUploadController::class, 'store'])->name('image.upload');

Route::get('/upload-image', function () {
    return view('image-upload');
})->name('image.upload.form');

Route::get('/favourites', [App\Http\Controllers\ProductController::class, 'favourites'])->name('products.favourites')->middleware('auth');

Route::middleware(['auth', 'role:admin'])->group(function () {
    Route::get('/admin/hero-section', [HeroSectionController::class, 'edit'])->name('admin.hero.edit');
    Route::post('/admin/hero-section', [HeroSectionController::class, 'update'])->name('admin.hero.update');
});


Route::middleware(['auth', 'role:driver'])->prefix('driver')->group(function () {
    Route::get('/orders', [OrderController::class, 'driverOrders'])->name('driver.orders.index');
    Route::get('/orders/{order}', [OrderController::class, 'driverOrderShow'])->name('driver.orders.show');
    Route::post('/orders/{order}/status', [OrderController::class, 'updateStatus'])->name('driver.orders.updateStatus');
});

// Driver Management Routes
Route::middleware(['auth', 'role:admin'])->group(function () {
    Route::post('/orders/{order}/assign-driver', [App\Http\Controllers\Admin\OrderController::class, 'assignDriver'])->name('orders.assign-driver');
    Route::post('/orders/{order}/remove-driver', [App\Http\Controllers\Admin\OrderController::class, 'removeDriver'])->name('orders.remove-driver');
});

// أو يمكنك وضعها داخل group الـ admin مع باقي الروتس:
Route::middleware(['auth', 'role:admin'])->group(function () {
    Route::get('/admin/orders', [OrderController::class, 'index'])->name('admin.orders.index');
    Route::post('/orders/{order}/assign-driver', [OrderController::class, 'assignDriver'])->name('orders.assign-driver');
    Route::post('/orders/{order}/remove-driver', [OrderController::class, 'removeDriver'])->name('orders.remove-driver');
    
    // إضافة سواق جديد
    Route::get('/admin/drivers/create', [OrderController::class, 'createDriver'])->name('admin.drivers.create');
    Route::post('/admin/drivers', [OrderController::class, 'storeDriver'])->name('admin.drivers.store');
});

// في web.php ضيف الروت ده للاختبار:

Route::get('/test-images', function () {
    // تحقق من الـ symbolic link
    $linkExists = is_link(public_path('storage'));
    
    // اجلب كل الصور في المجلد
    $images = [];
    if (Storage::disk('public')->exists('images')) {
        $images = Storage::disk('public')->files('images');
    }
    
    return [
        'storage_link_exists' => $linkExists,
        'storage_path' => storage_path('app/public'),
        'public_storage_path' => public_path('storage'),
        'images_found' => $images,
        'sample_image_url' => asset('storage/images/sample.jpg'),
        'full_path_check' => file_exists(public_path('storage/images'))
    ];
});

Role::firstOrCreate(['name' => 'driver']);

$admin = App\Models\User::where('email', 'admin@admin.com')->first();
$admin->givePermissionTo('manage-products');

$user = App\Models\User::where('email', 'admin@admin.com')->first();
$user->getRoleNames();