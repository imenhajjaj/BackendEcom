const Contact = require('../models/contacts');


async function getContactById(id) {
    try {
        // Recherchez le contact par son ID dans la base de données
        const contact = await Contact.findById(id);
        // Si aucun contact n'est trouvé, lancez une erreur
        if (!contact) {
            throw new Error(`Could not find the contact with ID ${id}`);
        }
        // Retournez le contact trouvé
        return contact;
    } catch (error) {
        // Attrapez et gérez les erreurs
        throw new Error(`Error while retrieving contact: ${error.message}`);
    }
}

module.exports = { getContactById };