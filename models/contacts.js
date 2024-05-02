const mongoose = require('mongoose');

const contactSchema = new mongoose.Schema({
    avatar: {
        type: String,
        default: null
    },
    background: {
        type: String,
        default: null
    },
    name: {
        type: String,
        required: true
    },
    emails: [{
        email: String,
        label: String
    }],
    phoneNumbers: [{
        country: String,
        phoneNumber: String,
        label: String
    }],
    title: String,
    company: String,
    birthday: {
        type: String,
        default: null
    },
    address: {
        type: String,
        default: null
    },
    notes: {
        type: String,
        default: null
    },
    tags: [String]
});

const Contact = mongoose.model('Contact', contactSchema);

module.exports = Contact;
