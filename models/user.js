const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true // Le nom de l'utilisateur est requis
    },
    email: {
        type: String,
        required: true, // L'e-mail de l'utilisateur est requis
        unique: true // L'e-mail doit être unique
    },
    password: {
        type: String,
        required: true, // L'e-mail de l'utilisateur est requis
        unique: true 
    },
    company: {
        type: String,
        required: true,
    },
    avatar: {
        type: String,
    },
    status: {
        type: String,// Le statut de l'utilisateur doit être l'un des trois valeurs : active, inactive, ou pending
    }
});

const User = mongoose.model('User', userSchema);

module.exports = User;
