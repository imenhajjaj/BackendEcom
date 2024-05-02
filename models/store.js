const mongoose = require('mongoose');

const storeSchema = new mongoose.Schema({
  name: {
    type: String,
  },
  logo: {
    type: String,
  },
  email: {
    type: String,
  },
  image: {
    type: String,
  },
  numTel: {
    type: String,
  },
  adresse: {
    type: String,
  },
  localisation: {
    type: String,
  },
  cashBackTot: {
    type: String,
  },
  description: {
    type: String,
  },
  analyse: {
    type: String,
  },
  contrat: {
    type: String,
  },
  historique: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Historique',
  }],
});

const Store = mongoose.model('Store', storeSchema);

module.exports = Store;