const mongoose = require('mongoose');

// Définir le schéma pour la catégorie d'inventaire
const inventoryCategorySchema = new mongoose.Schema({
    parentId: { type: String, required: true },
    name: { type: String, required: true },
    slug: { type: String, required: true }
});

// Créer le modèle à partir du schéma
const Category = mongoose.model('Category', inventoryCategorySchema);
module.exports = Category;