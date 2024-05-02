const mongoose = require('mongoose');

const companySchema = new mongoose.Schema({
    id: {
        type: String
    },
    name: {
        type: String
    },
    email: {
        type: String
    },
    numTel: {
        type: String
    },
    addresse: {
        type: String
    },
    description: {
        type: String
    },
    image: {
        type: String
    },
    contrat: {
        type: String
    },
    Analyse: {
        type: String
    },
    //(référence à la fenêtre d’historique (*) associé exclusivement aux produits de cette société)  
      historique: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Historique'
    },
    

    //(référence à la liste des produits (3) associés exclusivement à cette société)
    ref_Product: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Product'
    }
});

const Company = mongoose.model('Company', companySchema);
module.exports = Company;


