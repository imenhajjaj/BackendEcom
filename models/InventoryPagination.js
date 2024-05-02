const mongoose = require('mongoose');

const inventoryPaginationSchema = new mongoose.Schema({
    length: { type: Number, required: true },
    size: { type: Number, required: true },
    page: { type: Number, required: true },
    lastPage: { type: Number, required: true },
    startIndex: { type: Number, required: true },
    endIndex: { type: Number, required: true }
});

const Pagination = mongoose.model('Pagination', inventoryPaginationSchema);

module.exports = Pagination;
