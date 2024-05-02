const mongoose = require('mongoose');

const tagsSchema = new mongoose.Schema({
    title: {
        type: String,
        required: true
    }
});

const Tag = mongoose.model('Tag', tagsSchema);

module.exports = Tag;
