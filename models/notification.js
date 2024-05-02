const mongoose = require('mongoose');
const Schema = mongoose.Schema;

// Définition du schéma pour le modèle Notification
const notificationSchema = new Schema({
    icon: { type: String },
    image: { type: String },
    title: { type: String },
    description: { type: String },
    time: { type: String, required: true },
    link: { type: String },
    useRouter: { type: Boolean },
    read: { type: Boolean, required: true }
});

// Création du modèle à partir du schéma
const Notification = mongoose.model('Notification', notificationSchema);

module.exports = Notification;
