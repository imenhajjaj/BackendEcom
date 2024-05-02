
const mongoose = require('mongoose');

// Définition du schéma pour la tâche
const taskSchema = new mongoose.Schema({
    content: {
        type: String,
        required: true
    },
    completed: {
        type: Boolean,
        default: false
    }
});
// Modèle pour la tâche
const Task = mongoose.model('Tasks', tasksSchema);
module.exports = Task;
