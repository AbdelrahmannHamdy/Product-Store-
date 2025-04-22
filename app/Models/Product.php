<?php
namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;

class Product extends Model
{
    use HasFactory, SoftDeletes;

    protected $fillable = [
        'name',
        'description',
        'price',
        'stock_quantity',
        'image',
        'code',
        'model'
    ];

    protected $casts = [
        'price' => 'decimal:2',
        'stock_quantity' => 'integer'
    ];

    // Add accessor for image URL
    public function getImageUrlAttribute()
    {
        if ($this->image) {
            return asset('storage/' . $this->image);
        }
        return null;
    }

    public function purchases()
    {
        return $this->hasMany(Purchase::class);
    }

    public function isInStock()
    {
        return $this->stock_quantity > 0;
    }

    public function decreaseStock($quantity)
    {
        if ($this->stock_quantity >= $quantity) {
            $this->stock_quantity -= $quantity;
            return $this->save();
        }
        return false;
    }
}