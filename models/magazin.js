const mongoose = require('mongoose');

// Schéma pour la tâche
const taskSchema = new mongoose.Schema({
    content: String,
    completed: Boolean
});

// Schéma pour l'étiquette
const labelSchema = new mongoose.Schema({
    title: String
});

// Schéma pour la note
const noteSchema = new mongoose.Schema({
    title: String,
    content: String,
    tasks: [taskSchema],
    image: String,
    labels: [labelSchema],
    archived: Boolean,
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: null }
});

// Modèle pour la note
const Note = mongoose.model('Note', noteSchema);
module.exports = Note;
