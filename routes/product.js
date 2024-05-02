const express = require('express');
const router = express.Router();
const Product = require('../models/product');
const Tags = require('../models/InventoryTag'); // Assurez-vous que le chemin est correct
const Brand = require('../models/InventoryBrand'); // Assurez-vous que le chemin est correct
const Category = require('../models/InventoryCategory'); 
const Vendor = require('../models/InventoryVendor');
const Pagination = require('../models/InventoryPagination');

/*****brands     */
router.get('/api/apps/ecommerce/inventory/brands', async (req, res) => {
  try {
      const brands = await Brand.find();
      res.json(brands);
  } catch (err) {
      res.status(500).json({ message: err.message });
  }
});
router.post('/brands', async (req, res) => {
  try {
      const brandData = req.body;
      const newBrand = new Brand(brandData);
      const savedBrand = await newBrand.save();
      res.status(201).json(savedBrand);
  } catch (err) {
      res.status(500).json({ message: err.message });
  }
});


router.get('/api/apps/ecommerce/inventory/product/:id', async (req, res) => {
  try {
      const productId = req.params.id;
      // Rechercher le produit par son ID dans la base de données
      const product = await Product.findById(productId);
      // Vérifier si le produit existe
      if (!product) {
          return res.status(404).json({ message: `Produit avec l'ID ${productId} introuvable.` });
      }
      // Répondre avec le produit trouvé
      res.status(200).json(product);
  } catch (err) {
      // En cas d'erreur, renvoyer un message d'erreur avec le statut HTTP 500 (Erreur interne du serveur)
      res.status(500).json({ message: err.message });
  }
});



// Route pour créer une nouvelle catégorie
router.post('/api/apps/ecommerce/inventory/categories', async (req, res) => {
  try {
      const { parentId, name, slug } = req.body;
      const newCategory = new Categoryy({ parentId, name, slug });
      const savedCategory = await newCategory.save();
      res.status(201).json(savedCategory);
  } catch (err) {
      res.status(400).json({ message: err.message });
  }
});


router.post('/api/apps/ecommerce/inventory/product', async (req, res) => {
    const productData = req.body;

    try {
        // Créer un nouveau produit dans la base de données
        const newProduct = await Product.create(productData);
        res.status(201).json(newProduct);
    } catch (err) {
        res.status(400).json({ message: err.message });
    }
});














// Route pour récupérer des données paginées
router.post('/api/apps/ecommerce/inventory/pagination', async (req, res) => {
  try {
      // Récupérer les données de pagination à partir du corps de la requête
      const paginationData = req.body;
      // Créer une nouvelle instance du modèle Pagination
      const newPagination = new Pagination(paginationData);
      // Sauvegarder les données de pagination dans la base de données
      const savedPagination = await newPagination.save();
      // Répondre avec les données de pagination sauvegardées
      res.status(201).json(savedPagination);
  } catch (err) {
      res.status(400).json({ message: err.message });
  }
});


// Route pour récupérer les produits avec pagination et recherche
router.get('/api/apps/ecommerce/inventory/products', async (req, res) => {
  try {
      const { page = 0, size = 10, sort = 'name', order = 'asc', search = '' } = req.query;
      // Logique de récupération des produits avec pagination et recherche
      const startIndex = page * size;
      const endIndex = startIndex + parseInt(size);
      const query = {};
      if (search !== '') {
          query.name = { $regex: search, $options: 'i' }; // Recherche insensible à la casse
      }
      const products = await Product.find(query)
          .sort({ [sort]: order })
          .skip(startIndex)
          .limit(parseInt(size));
      const totalProducts = await Product.countDocuments(query);
      const lastPage = Math.ceil(totalProducts / size);
      const paginationData = {
          length: totalProducts,
          size: parseInt(size),
          page: parseInt(page),
          lastPage: lastPage,
          startIndex: startIndex + 1,
          endIndex: Math.min(endIndex, totalProducts)
      };
      const response = {
          pagination: paginationData,
          products: products
      };
      res.status(200).json(response);
  } catch (err) {
      res.status(500).json({ message: err.message });
  }
});

// Route pour récupérer un produit par son ID
router.get('/api/apps/ecommerce/inventory/products/:id', async (req, res) => {
  try {
      const productId = req.params.id;
      // Utilisation de l'opérateur RxJS pour récupérer le produit
      getProductById(productId)
          .subscribe(
              product => res.status(200).json(product),
              error => res.status(404).json({ message: error })
          );
  } catch (err) {
      res.status(500).json({ message: err.message });
  }
});
// Fonction pour récupérer un produit par son ID
function getProductById(id) {
  return Product.find({ id }).pipe(
      take(1),
      map(products => products[0]),
      switchMap(product => {
          if (!product) {
              return throwError(`Product with ID ${id} not found`);
          }
          return of(product);
      })
  );
}









// Route pour créer un nouveau vendeur
router.post('/api/apps/ecommerce/inventory/vendors', async (req, res) => {
  try {
      // Créez un nouveau vendeur en utilisant les données de la requête
      const newVendor = new Vendor({
          // Vous devez spécifier les données nécessaires pour créer un nouveau vendeur ici
          name: req.body.name,
          slug: req.body.slug,
          // Autres propriétés du vendeur...
      });
      // Enregistrez le nouveau vendeur dans la base de données
      const savedVendor = await newVendor.save();
      // Réponse avec le nouveau vendeur créé
      res.status(201).json(savedVendor);
  } catch (err) {
      // En cas d'erreur, renvoyez un message d'erreur avec le statut HTTP 500 (Erreur interne du serveur)
      res.status(500).json({ message: err.message });
  }
});






// Route pour créer un nouveau tag
router.post('/api/apps/ecommerce/inventory/tag', async (req, res) => {
  try {
      // Créez un nouveau tag en utilisant les données de la requête
      const newTag = new Tags(req.body);
      // Enregistrez le nouveau tag dans la base de données
      const savedTag = await newTag.save();
      // Réponse avec le nouveau tag créé
      res.status(201).json(savedTag);
  } catch (err) {
      // En cas d'erreur, renvoyez un message d'erreur avec le statut HTTP 500 (Erreur interne du serveur)
      res.status(500).json({ message: err.message });
  }
});

// Route pour récupérer tous les tags
router.get('/api/apps/ecommerce/inventory/tags', async (req, res) => {
  try {
      // Récupération de tous les tags depuis la base de données
      const tags = await Tags.find();
      // Réponse avec la liste des tags
      res.status(200).json(tags);
  } catch (err) {
      // En cas d'erreur, renvoyer un message d'erreur avec le statut HTTP 500 (Erreur interne du serveur)
      res.status(500).json({ message: err.message });
  }
});


router.patch('/api/apps/ecommerce/inventory/tag/:id', async (req, res) => {
  try {
      const tagId = req.params.id;
      // Recherche du tag à mettre à jour dans la base de données
      const tagToUpdate = await Tags.findById(tagId);
      if (!tagToUpdate) {
          return res.status(404).json({ message: `Tag with ID ${tagId} not found` });
      }
      // Mise à jour des propriétés du tag à partir des données de la requête
      Object.assign(tagToUpdate, req.body);
      // Enregistrement du tag mis à jour dans la base de données
      const updatedTag = await tagToUpdate.save();
      // Réponse avec le tag mis à jour
      res.status(200).json(updatedTag);
  } catch (err) {
      // En cas d'erreur, renvoyer un message d'erreur avec le statut HTTP 500 (Erreur interne du serveur)
      res.status(500).json({ message: err.message });
  }
});
/*****   delete tags  */
router.delete('/api/apps/ecommerce/inventory/tag/:id', async (req, res) => {
  try {
      const tagId = req.params.id;
      // Supprimer le tag de la base de données
      const deletedTag = await Tags.findByIdAndDelete(tagId);
      if (!deletedTag) {
          return res.status(404).json({ message: `Tag with ID ${tagId} not found` });
      }
      // Mettre à jour les produits pour supprimer le tag de ceux qui l'ont
      await Product.updateMany(
          { tags: tagId },
          { $pull: { tags: tagId } }
      );
      // Réponse avec un statut de succès
      res.status(200).json(true);
  } catch (err) {
      // En cas d'erreur, renvoyer un message d'erreur avec le statut HTTP 500 (Erreur interne du serveur)
      res.status(500).json({ message: err.message });
  }
});








// Route pour récupérer tous les vendeurs
router.get('/api/apps/ecommerce/inventory/vendors', async (req, res) => {
  try {
      // Récupération de tous les vendeurs depuis la base de données
      const vendors = await Vendor.find();
      // Réponse avec la liste des vendeurs
      res.status(200).json(vendors);
  } catch (err) {
      // En cas d'erreur, renvoyer un message d'erreur avec le statut HTTP 500 (Erreur interne du serveur)
      res.status(500).json({ message: err.message });
  }
});



// Route pour récupérer toutes les catégories
router.get('/api/apps/ecommerce/inventory/categories', async (req, res) => {
  try {
      const categories = await Category.find();
      res.json(categories);
  } catch (err) {
      res.status(500).json({ message: err.message });
  }
});

router.patch('/api/apps/ecommerce/inventory/product/:id', async (req, res) => {
    const productId = req.params.id;
    const updatedProductData = req.body;

    try {
        // Rechercher et mettre à jour le produit dans la base de données
        const updatedProduct = await Product.findByIdAndUpdate(productId, updatedProductData, { new: true });
        res.json(updatedProduct);
    } catch (err) {
        res.status(400).json({ message: err.message });
    }
});



  router.delete('/api/apps/ecommerce/inventory/product/:id', async (req, res) => {
    const { id } = req.params;

    try {
        // Supprimer le produit de la base de données
        await Product.findByIdAndDelete(id);
        res.json({ message: 'Product deleted successfully' });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});



module.exports = router;










