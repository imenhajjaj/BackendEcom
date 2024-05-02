const mongoose = require('mongoose');

const inventoryProductSchema = new mongoose.Schema({
    category: { type: String },
    name: { type: String, required: true },
    sku: { type: String, unique: true },
    barcode: { type: String, unique: true, sparse: true },    brand: { type: String },
    stock: { type: Number, required: true },
    cost: { type: Number, required: true },
    basePrice: { type: Number, required: true },
    taxPercent: { type: Number, required: true },
    price: { type: Number, required: true },
    thumbnail: { type: String, required: true },
    images: [{ type: String }],
    active: { type: Boolean, required: true }
});

const Product = mongoose.model('Product', inventoryProductSchema);
module.exports = Product;
