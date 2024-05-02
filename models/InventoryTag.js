const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const InventoryTagSchema = new Schema({
    title: String
});

const Tags = mongoose.model('Tags', InventoryTagSchema);

module.exports = Tags;

