// Schéma MongoDB pour stocker les références des fichiers
const mongoose =require('mongoose');

const fichierSchema = new mongoose.Schema({
    nom: String,
    chemin: String,
    taille: Number
  });

  


  module.exports = fichierSchema;