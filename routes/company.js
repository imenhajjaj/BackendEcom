const express = require('express');
const router = express.Router();
const multer = require('multer');
const Company = require('../models/company');
const Product = require('../models/product');
const Historique = require('../models/historique');



// GET /entreprises : Récupérer toutes les entreprises
router.get('/entreprises', async (req, res) => {
  try {
    const entreprises = await Company.find();
    res.json(entreprises);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});



// POST /entreprises : Créer une nouvelle entreprise
router.post('/entreprises', async (req, res) => {
  const entreprise = new Company({
    nom: req.body.nom,
    // autres champs de l'entreprise
  });
  try {
    const newEntreprise = await entreprise.save();
    res.status(201).json(newEntreprise);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});




filename = '';

const mystorage = multer.diskStorage({
    destination: './uploads',
    filename: (req, file , redirect)=>{
        let date = Date.now();
        let fl = date + '.' + file.mimetype.split('/')[1];
        redirect(null , fl);
        filename = fl;
    }
})

const upload = multer({storage: mystorage});





// Route POST pour créer une nouvelle entreprise
router.post('/Ajouter', async (req, res) => {
  try {
      // Créez une nouvelle entreprise en utilisant la fonction create() du modèle Company
      const newCompany = await Company.create(req.body);

      // Envoyez une réponse avec la nouvelle entreprise créée
      res.status(201).json(newCompany);
  } catch (error) {
      // En cas d'erreur, renvoyez une réponse d'erreur avec le code d'erreur et un message d'erreur
      res.status(400).json({ message: error.message });
  }
});


router.get('/liste', async (req, res) => {
  try {
    const companies = await Company.find().select('name description image -_id');
    res.send(companies);
  } catch (error) {
    res.status(500).send('Erreur lors de la récupération des entreprises: ' + error.message);
  }
});


// Route GET pour récupérer toutes les entreprises
router.get('/Alldetails', async (req, res) => {
  try {
      // Récupérez toutes les entreprises depuis la base de données
      const companies = await Company.find();
      // Renvoyez la liste des entreprises
      res.json(companies);
  } catch (error) {
      // En cas d'erreur, renvoyez une réponse d'erreur avec le code d'erreur et un message d'erreur
      res.status(500).json({ message: error.message });
  }
});



router.get('/details/:id', async(req, res)=>{
    try{
        id=req.params.id;
        com = await Company.findById({_id: id})
        res.send(com);
    }catch(error){
        res.send(error)
    }
  })
  
    
  router.delete('/delete/:id',async (req, res)=>{
    try{
      id = req.params.id
      deletCom = await Company.findByIdAndDelete({_id: id});
      res.status(200).send(deletCom)
  
    }catch (error){
      res.status(400).send(error)
    }
  })

  router.put('/upt/:id', async(req, res)=>{
   try{
    id= req.params.id;
    newComp = req.body;
    updated = await Company.findByIdAndUpdate({_id:id}, newComp);
    res.send(updated);      
   }catch(error){
      res.send(error)
   }
   })

//affiche le company avec leur name product
router.get('/companies-with-products', async (req, res) => {
  try {
      const companiesWithProducts = await Company.find().populate('ref_Product', 'name');
      res.json(companiesWithProducts);
  } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Erreur lors de la récupération des entreprises avec les noms de leurs produits associés' });
  }
});

 //get product avec nom d'entreprise
      router.get('/compa', async (req, res) => {
      try {
          // Récupérez tous les produits avec le nom de l'entreprise associée
          const productsWithCompany = await Company.find().populate('ref_Product', 'cashback');
          res.json(productsWithCompany);
      } catch (error) {
          console.error(error);
          res.status(500).json({ message: 'Erreur lors de la récupération des produits avec le nom de l\'entreprise associée' });
      }
  });



module.exports = router;

