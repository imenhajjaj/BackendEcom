const mongoose = require('mongoose');

const tagSchema = new mongoose.Schema({
    title: {
        type: String,
        required: true
    }
});

const Tags = mongoose.model('Tags', tagSchema);

module.exports = Tags