const express = require('express');
const router = express.Router();
const Store = require('../models/store');
const multer = require('multer');


const mystorage = multer.diskStorage({
})








// Créer un nouveau magasin
router.post('/ajouter', async (req, res) => {
  const newStore = new Store(req.body);
  try {
    const savedStore = await newStore.save();
    res.status(201).json(savedStore);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

// Route pour récupérer tous les magasins
router.get('/getAllstores', async (req, res) => {
  try {
      // Utiliser la méthode find() de Mongoose pour récupérer tous les magasins
      const stores = await Store.find();   
      // Envoyer la réponse JSON avec les magasins récupérés
      res.json(stores);
  } catch (error) {
      // En cas d'erreur, envoyer une réponse d'erreur avec le code HTTP approprié
      console.error(error);
      res.status(500).json({ message: 'Erreur lors de la récupération des magasins' });
  }
});


// Route GET pour obtenir un magasin par son ID
router.get('/stores/:storeId', async (req, res) => {
  try {
      const store = await Store.findById(req.params.storeId);
      if (!store) {
          return res.status(404).json({ message: 'Magasin non trouvé' });
      }
      res.json(store);
  } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Erreur lors de la récupération du magasin par ID' });
  }
});


router.delete('/del/:id',async (req, res)=>{
    try{
      id = req.params.id
      deletedStor = await Store.findByIdAndDelete({_id: id});
      res.status(200).send(deletedStor)
    }catch (error){
      res.status(400).send(error)
    }
  })



router.put('/updt/:id',(req, res)=>{
    id= req.params.id;
    newData = req.body;
    Store.findByIdAndUpdate({_id: id}, newData )
        .then(
          (updated)=>{
            res.send(updated)
          }
        )
        .catch(
          (err)=>{
            res.send(err)
          }
      ) }) 






      


module.exports = router;

