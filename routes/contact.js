const express = require('express');
const router = express.Router();
const Contact = require('../models/contacts');
const Country = require('../models/country');
const Tag = require('../models/tag');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const { getContactById } = require('../controllers/contact');


// Définissez le dossier de stockage pour les avatars
const uploadDir = path.join(__dirname, 'avatars');
if (!fs.existsSync(uploadDir)){
    fs.mkdirSync(uploadDir);
}

// Configuration de Multer
const storage = multer.diskStorage({
    destination: uploadDir,
    filename: function(req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname);
    }
});



const cors = require('cors');
// Activer CORS pour cette route
router.use(cors());



// Route pour récupérer un contact par son ID
router.get('/contacts/:id', async (req, res) => {
  try {
      const contactId = req.params.id;
      // Appel de la fonction getContactById avec l'ID du contact
      const contact = await getContactById(contactId);
      // Renvoyer le contact au client au format JSON
      res.json(contact);
  } catch (error) {
      // En cas d'erreur, renvoyer un message d'erreur au client
      res.status(404).json({ message: error.message });
  }
});


router.get('/api/apps/contacts/countries', async (req, res) => {
    try {
        const countries = await Country.find();
        res.json(countries);
    } catch (error) {
        console.error('Error retrieving countries:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

router.post('/api/apps/contacts/countries', async (req, res) => {
    const countryData = req.body;
  
    try {
      // Créer un nouveau pays dans la base de données
      const newCountry = await Country.create(countryData);
  
      // Répondre avec le nouveau pays créé
      res.status(201).json(newCountry);
    } catch (error) {
      console.error('Erreur lors de la création du pays :', error);
      // En cas d'erreur, renvoyer un statut 500 (Internal Server Error)
      res.status(500).json({ error: 'Erreur interne du serveur' });
    }
  });


// Route pour récupérer tous les tags
router.get('/api/apps/contacts/tags', async (req, res) => {
    try {
      // Récupérer tous les tags depuis la base de données
      const tags = await Tag.find();
      res.json(tags);
    } catch (error) {
      console.error('Erreur lors de la récupération des tags :', error);
      res.status(500).json({ error: 'Erreur interne du serveur' });
    }
  });



// Route pour mettre à jour un tag
router.patch('/api/apps/contacts/tag/:id', async (req, res) => {
    const { id } = req.params;
  
    try {
      // Rechercher le tag dans la base de données
      const tag = await Tag.findByIdAndUpdate(id, req.body, { new: true });
  
      // Vérifier si le tag existe
      if (!tag) {
        return res.status(404).json({ error: 'Tag not found' });
      }
  
      // Répondre avec le tag mis à jour
      res.json(tag);
    } catch (error) {
      console.error('Error updating tag:', error);
      res.status(500).json({ error: 'Internal Server Error' });
    }
  });




// Route pour supprimer un tag
router.delete('/api/apps/contacts/tag/:id', async (req, res) => {
    const { id } = req.params;
  
    try {
      // Supprimer le tag de la base de données
      const deletedTag = await Tag.findByIdAndDelete(id);
  
      // Vérifier si le tag a été supprimé avec succès
      if (!deletedTag) {
        return res.status(404).json({ error: 'Tag not found' });
      }
  
      // Répondre avec un indicateur de suppression réussie
      res.json({ success: true });
    } catch (error) {
      console.error('Error deleting tag:', error);
      res.status(500).json({ error: 'Internal Server Error' });
    }
  });






// Route pour créer un nouveau tag
router.post('/api/apps/contacts/tag', async (req, res) => {
    try {
      // Créer un nouveau tag à partir des données reçues dans le corps de la requête
      const newTag = new Tag(req.body);
  
      // Sauvegarder le nouveau tag dans la base de données
      const savedTag = await newTag.save();
  
      // Répondre avec le tag créé
      res.status(201).json(savedTag);
    } catch (error) {
      console.error('Erreur lors de la création du tag :', error);
      // Si une erreur se produit, répondre avec un code d'état 500 et un message d'erreur
      res.status(500).json({ error: 'Erreur interne du serveur' });
    }
  });

router.get('/api/apps/contacts/all', async (req, res) => {
    try {
        // Récupérer tous les contacts depuis la base de données
        const contacts = await Contact.find();
        res.json(contacts);
    } catch (error) {
        console.error('Error retrieving contacts', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


router.get('/api/apps/contacts/search', async (req, res) => {
    try {
        const query = req.query.query; // Récupérer la chaîne de recherche de la requête

        // Recherchez les contacts qui correspondent à la requête dans leur nom ou leur email
        const contacts = await Contact.find({
            $or: [
                { name: { $regex: query, $options: 'i' } }, // Recherche par nom, insensible à la casse
                { 'emails.email': { $regex: query, $options: 'i' } } // Recherche par email, insensible à la casse
            ]
        });
        res.json(contacts);
    } catch (error) {
        console.error('Error searching contacts', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});



router.post('/api/apps/contacts/contact', async (req, res) => {
  try {
    // Afficher les données de la requête dans la console
    console.log('Données de la requête:', req.body);

    // Créer un nouveau contact à partir des données de la requête
    const newContact = await Contact.create(req.body);

    // Répondre avec le nouveau contact créé
    res.status(201).json(newContact);
  } catch (error) {
    console.error('Erreur lors de la création du contact :', error);
    res.status(500).json({ error: 'Erreur interne du serveur' });
  }
});


// Route pour mettre à jour un contact
router.patch('/api/apps/contacts/contact', async (req, res) => {
    // Récupérez l'ID et les données de contact envoyées dans la requête
    const { id, contact } = req.body;

    try {
        // Recherchez le contact correspondant dans la base de données et mettez à jour ses données
        const updatedContact = await Contact.findByIdAndUpdate(id, contact, { new: true });
        // Répondez avec le contact mis à jour
        res.json(updatedContact);
    } catch (error) {
        console.error('Error updating contact:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Route pour supprimer un contact par son ID
router.delete('/api/apps/contacts/contact/:id', async (req, res) => {
    const { id } = req.params;

    try {
      // Supprimer le contact de la base de données
      await Contact.findByIdAndDelete(id);
  
      // Répondre avec un statut 204 (No Content) pour indiquer que le contact a été supprimé avec succès
      res.sendStatus(204);
    } catch (error) {
      console.error('Erreur lors de la suppression du contact :', error);
      // Répondre avec un statut 500 (Internal Server Error) en cas d'erreur
      res.status(500).json({ error: 'Erreur interne du serveur' });
    }
  });
  


  const upload = multer({ storage: storage });
  // Route pour l'upload d'avatar
  router.post('/api/apps/contacts/avatar/:id', upload.single('avatar'), async (req, res) => {
      const contactId = req.params.id;
      const avatarPath = req.file.path;
      try {
          // Trouvez le contact par ID
          const contact = await Contact.findById(contactId);
          if (!contact) {
              return res.status(404).json({ error: `Contact with ID ${contactId} not found` });
          }
          // Mettez à jour le chemin de l'avatar dans le contact
          contact.avatar = avatarPath;
          await contact.save();
          res.json(contact);
      } catch (error) {
          console.error('Error updating avatar:', error);
          res.status(500).json({ error: 'Internal Server Error' });
      }
  });











module.exports = router;
