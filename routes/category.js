const express = require('express');
const router = express.Router();
const Category = require('../models/category');
const  { getCategories, createCategory, getCategory, updateCategory, deleteCategory} = require('../services/categoryService');
const { getCategoryValidator } = require('../utils/validators/categoryValidator');


router.route('/').get(getCategories).post(createCategory);
router.route('/:id').get(getCategoryValidator, getCategory).put(updateCategory).delete(deleteCategory);



// Route pour ajouter une nouvelle catégorie
router.post('/categories', async (req, res) => {
    try {
      // Crée une nouvelle instance de catégorie avec les données de la requête
      const newCategory = new Category({
        id: req.body.id, // Cet ID devrait idéalement être généré automatiquement. Considérez l'utilisation de _id de MongoDB à la place.
        name_Categ: req.body.name_Categ,
        product: req.body.product, // Assurez-vous que ceci est l'ID d'un produit existant dans votre base de données
      });
      // Sauvegarde la nouvelle catégorie dans la base de données
      const savedCategory = await newCategory.save();
      // Envoie la catégorie sauvegardée comme réponse
      res.status(201).send(savedCategory);
    } catch (error) {
      res.status(400).send(error.message);
    }
  });




// Route pour mettre à jour une catégorie
router.put('/categories/:id', async (req, res) => {
    try {
      // Trouver la catégorie à mettre à jour par son ID
      const updatedCategory = await Category.findOneAndUpdate(
        { _id: req.params.id }, // Filtre par ID
        req.body, // Données de mise à jour provenant du corps de la requête
        { new: true } // Options pour retourner le document mis à jour
      );
  
      // Vérifier si la catégorie existe
      if (!updatedCategory) {
        return res.status(404).send("La catégorie spécifiée n'a pas été trouvée.");
      }
  
      // Envoyer la catégorie mise à jour en réponse
      res.send(updatedCategory);
    } catch (error) {
      res.status(400).send(error.message);
    }
  });
  



// Définition de la route DELETE pour supprimer une catégorie par son ID
router.delete('/categories/:categoryId', async (req, res) => {
    try {
        // Récupérer l'identifiant de la catégorie à supprimer depuis les paramètres de la requête
        const categoryId = req.params.categoryId;
        // Recherche de la catégorie dans la base de données et suppression
        const deletedCategory = await Category.findOneAndDelete({ id: categoryId });
        // Vérifier si la catégorie a été trouvée et supprimée
        if (!deletedCategory) {
            return res.status(404).json({ message: "Catégorie non trouvée" });
        }
        // Répondre avec un message de succès
        res.json({ message: "Catégorie supprimée avec succès", deletedCategory });
    } catch (error) {
        // Gérer les erreurs
        console.error(error);
        res.status(500).json({ message: "Une erreur est survenue lors de la suppression de la catégorie" });
    }
});


// Définition de la route GET pour récupérer une catégorie par son ID
router.get('/categories/:categoryId', async (req, res) => {
    try {
        // Récupérer l'identifiant de la catégorie depuis les paramètres de la requête
        const categoryId = req.params.categoryId;

        // Recherche de la catégorie dans la base de données par son ID
        const category = await Category.findOne({ id: categoryId });

        // Vérifier si la catégorie a été trouvée
        if (!category) {
            return res.status(404).json({ message: "Catégorie non trouvée" });
        }

        // Répondre avec la catégorie trouvée
        res.json(category);
    } catch (error) {
        // Gérer les erreurs
        console.error(error);
        res.status(500).json({ message: "Une erreur est survenue lors de la récupération de la catégorie" });
    }
});

// Définition de la route GET pour récupérer toutes les catégories
router.get('/categories', async (req, res) => {
    try {
        // Recherche de toutes les catégories dans la base de données
        const categories = await Category.find();

        // Répondre avec la liste des catégories
        res.json(categories);
    } catch (error) {
        // Gérer les erreurs
        console.error(error);
        res.status(500).json({ message: "Une erreur est survenue lors de la récupération des catégories" });
    }
});



let pointsByUser = {}; // Stocke les points par utilisateur
let products = [{ id: 1, name: "Produit A", points: 100 }]; // Exemple de produits disponibles

// Ajouter des points à un utilisateur
router.post('/addPoints', (req, res) => {
    const { userId, points } = req.body;
    if (!pointsByUser[userId]) {
        pointsByUser[userId] = 0;
    }
    pointsByUser[userId] += points;
    res.send({ userId, totalPoints: pointsByUser[userId] });
});

// Échanger des points contre un produit
router.post('/redeemProduct', (req, res) => {
    const { userId, productId } = req.body;
    const product = products.find(p => p.id === productId);
    if (!product) {
        return res.status(404).send({ error: "Produit non trouvé" });
    }
    if (!pointsByUser[userId] || pointsByUser[userId] < product.points) {
        return res.status(400).send({ error: "Points insuffisants" });
    }

    pointsByUser[userId] -= product.points;
    res.send({ message: "Produit échangé avec succès", userId, remainingPoints: pointsByUser[userId] });
});











module.exports = router;

