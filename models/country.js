const mongoose = require('mongoose');

const countrySchema = new mongoose.Schema({
    id: { type: String, required: true },
    iso: { type: String, required: true },
    name: { type: String, required: true },
    code: { type: String, required: true },
    flagImagePos: { type: String, required: true }
});

const Country = mongoose.model('Country', countrySchema);

module.exports = Country;
