const mongoose = require('mongoose');

const labelSchema = new mongoose.Schema({
    title: String
});

const Label = mongoose.model('Label', labelSchema);

module.exports = Label;
