const Note = require('../models/magazin');

async function getNoteById(id) {
    try {
        // Recherchez la note par son ID dans la base de données
        const note = await Note.findById(id);
        // Si aucune note n'est trouvée, lancez une erreur
        if (!note) {
            throw new Error(`Could not find the note with ID ${id}`);
        }
        // Retournez la note
        return note;
    } catch (error) {
        // Attrapez et gérez les erreurs
        throw new Error(`Error while retrieving note: ${error.message}`);
    }
}

module.exports = { getNoteById };