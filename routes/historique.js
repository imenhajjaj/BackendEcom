const express = require('express');
const router = express.Router();
const Historique = require('../models/historique');

const multer = require('multer');
const mystorage = multer.diskStorage({
})

router.post('/creaatee', (req, res)=>{
    data = req.body;
    his = new Historique(data);
    his.save()
       .then(
         (savedProduct)=>{
           res.status(200).send(savedProduct)
         } )
       .catch(
         (err)=>{
           res.status(400).send(err)  } )
  })










module.exports = Historique;