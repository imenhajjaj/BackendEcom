const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const InventoryVendorSchema = new Schema({
   

    name: { type: String, required: true },
    slug: { type: String, required: true }

    
});

const Vendor = mongoose.model('Vendor', InventoryVendorSchema);

module.exports = Vendor;
