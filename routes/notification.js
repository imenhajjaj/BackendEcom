const express = require('express');
const router = express.Router();
const Notification = require('../models/notification');
const cors = require('cors');
// Activer CORS pour cette route
router.use(cors());







router.get('/api/common/notifications', async (req, res) => {
    try {
        // Récupérer toutes les notifications depuis la base de données
        const notifications = await Notification.find();
        // Envoyer les notifications au format JSON
        res.json(notifications);
    } catch (error) {
        // En cas d'erreur, renvoyer une erreur 500
        res.status(500).json({ message: 'Erreur lors de la récupération des notifications.' });
    }
});



// Définition de la route pour ajouter une nouvelle notification
router.post('/api/common/notifications', async (req, res) => {
    try {
        // Créer une nouvelle instance de la notification avec les données fournies
        const newNotification = new Notification(req.body);
        // Enregistrer la nouvelle notification dans la base de données
        const savedNotification = await newNotification.save();
        // Envoyer la notification nouvellement créée en réponse
        res.status(201).json(savedNotification);
    } catch (error) {
        // En cas d'erreur, renvoyer une erreur 500
        res.status(500).json({ message: 'Erreur lors de l\'ajout de la notification.' });
    }
});


// Route PATCH pour la mise à jour d'une notification
router.patch('/api/common/notifications/:id', async (req, res) => {
    try {
        // Récupérer l'ID de la notification à mettre à jour depuis les paramètres de la requête
        const notificationId = req.params.id;
        // Récupérer les données de la notification mise à jour depuis le corps de la requête
        const updatedNotificationData = req.body;
        // Mettre à jour la notification correspondante dans la base de données
        const updatedNotification = await Notification.findByIdAndUpdate(notificationId, updatedNotificationData, { new: true });
        // Vérifier si la notification a été mise à jour avec succès
        if (!updatedNotification) {
            return res.status(404).json({ message: 'Notification non trouvée' });
        }
        // Envoyer la notification mise à jour en réponse
        res.json(updatedNotification);
    } catch (error) {
        // En cas d'erreur, renvoyer une erreur 500
        res.status(500).json({ message: 'Erreur lors de la mise à jour de la notification.' });
    }
});

router.delete('/api/common/notifications/:id', async (req, res) => {
    try {
        // Récupérer l'ID de la notification à supprimer depuis les paramètres de la requête
        const notificationId = req.params.id;
        // Supprimer la notification correspondante dans la base de données
        const deletedNotification = await Notification.findByIdAndDelete(notificationId);
        // Vérifier si la notification a été supprimée avec succès
        if (!deletedNotification) {
            return res.status(404).json({ message: 'Notification non trouvée' });
        }
        // Envoyer true en réponse pour indiquer que la notification a été supprimée avec succès
        res.json(true);
    } catch (error) {
        // En cas d'erreur, renvoyer une erreur 500
        res.status(500).json({ message: 'Erreur lors de la suppression de la notification.' });
    }
});


router.get('/api/common/notifications/mark-all-as-read', async (req, res) => {
    try {
        // Mettre à jour toutes les notifications pour les marquer comme lues
        await Notification.updateMany({}, { $set: { read: true } });
        // Envoyer true en réponse pour indiquer que toutes les notifications ont été mises à jour avec succès
        res.json(true);
    } catch (error) {
        // En cas d'erreur, renvoyer une erreur 500
        res.status(500).json({ message: 'Erreur lors de la mise à jour des notifications.' });
    }
});



module.exports = router;
