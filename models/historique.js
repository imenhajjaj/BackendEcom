const mongoose =require('mongoose');
const Historique = mongoose.model('Historique', {

    Num_Serie: {
        type: String,
    },
    name_product: {
        type: String,   
    },
    product_id: {
        type: String,   
    },
    date: {
        type:String
    },
    image: {
        type:String
    },
    localisation: {
        type:String
    },
    Cashback_acteur: {
        type:String
    },
    localisation: {
        type:String
    },
    cashBackTot: {
        type:String
    },
    description: {
        type:String
    },
    analyse: {
        type:String
    },
    contrat: {
        type:String
    },
    ref_Product: {
        type: String,
        ref: 'Product'
    },
    ref_Store: {
        type: String,
        ref: 'Store'
    },
    ref_Company: {
        type: String,
        ref: 'Product'
    },
    ref_Consumer: {
        type: String,
        ref: 'Product'
    }
});
module.exports = Historique;