const express = require('express');
const router = express.Router();
const Label = require('../models/label');
const Note = require('../models/magazin');
const Task = require('../models/task');
const cors = require('cors');
const { getNoteById } = require('../controllers/store');

// Activer CORS pour cette route
router.use(cors());



// Route pour récupérer une note par son ID
router.get('/notes/:id', async (req, res) => {
    try {
        const noteId = req.params.id;
        // Appel de la fonction getNoteById avec l'ID de la note
        const note = await getNoteById(noteId);
        // Renvoyer la note au client
        res.json(note);
    } catch (error) {
        // En cas d'erreur, renvoyer un message d'erreur au client
        res.status(404).json({ message: error.message });
    }
});



router.get('/api/apps/notes/labels', async (req, res) => {
    try {
        // Récupérer toutes les étiquettes depuis la base de données
        const labels = await Label.find();
        // Répondre avec les étiquettes
        res.json(labels);
    } catch (error) {
        console.error('Erreur lors de la récupération des étiquettes :', error);
        // Répondre avec une erreur 500 en cas d'erreur
        res.status(500).json({ error: 'Erreur interne du serveur' });
    }
});


// Route pour ajouter une étiquette
router.post('/api/apps/notes/labels', async (req, res) => {
    try {
        const { title } = req.body;
        // Créez une nouvelle instance de Label
        const newLabel = new Label({ title });
        // Enregistrez la nouvelle étiquette dans la base de données
        const savedLabel = await newLabel.save();
        // Envoyez la réponse avec la nouvelle étiquette
        res.status(201).json(savedLabel);
    } catch (error) {
        // En cas d'erreur, envoyez une réponse d'erreur
        res.status(500).json({ message: error.message });
    }
});

router.patch('/api/apps/notes/labels', async (req, res) => {
    const labelId = req.params.id; // Récupérer l'ID de l'étiquette à partir des paramètres de l'URL
    const updatedLabel = req.body; // Récupérer les données mises à jour de l'étiquette depuis le corps de la requête

    try {
        // Recherche de l'étiquette dans la base de données par son ID
        const label = await Label.findById(labelId);

        // Vérifier si l'étiquette existe
        if (!label) {
            return res.status(404).json({ message: 'Label not found' });
        }

        // Mettre à jour les champs de l'étiquette avec les nouvelles données
        label.set(updatedLabel);

        // Enregistrer les modifications dans la base de données
        await label.save();

        // Renvoyer la réponse avec l'étiquette mise à jour
        res.status(200).json(label);
    } catch (error) {
        console.error('Error updating label:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});


// Route pour supprimer une étiquette
router.delete('/api/apps/notes/labels/:id', async (req, res) => {
    try {
        // Récupérer l'ID de l'étiquette depuis les paramètres de la requête
        const { id } = req.params;
        // Supprimer l'étiquette de la base de données
        await Label.findByIdAndDelete(id);
        // Répondre avec un succès
        res.json({ success: true });
    } catch (error) {
        console.error('Erreur lors de la suppression de l\'étiquette :', error);
        // Répondre avec une erreur 500 en cas d'erreur
        res.status(500).json({ error: 'Erreur interne du serveur' });
    }
});





// Route pour récupérer toutes les notes
router.get('/api/apps/notes/all', async (req, res) => {
    try {
        // Récupérer toutes les notes depuis la base de données
        const notes = await Note.find();

        // Répondre avec toutes les notes sous forme de réponse JSON
        res.json(notes);
    } catch (error) {
        console.error('Erreur lors de la récupération de toutes les notes :', error);
        // Répondre avec une erreur 500 en cas d'erreur
        res.status(500).json({ error: 'Erreur interne du serveur' });
    }
});


// GET route to get a note by ID
router.get('/api/apps/notes/:id', async (req, res) => {
    const noteId = req.params.id;
    try {
        const note = await Note.findById(noteId);

        if (!note) {
            return res.status(404).json({ message: 'Note not found' });
        }
        res.json(note);
    } catch (error) {
        console.error('Error fetching note by ID:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});








// Endpoint pour créer une nouvelle note
router.post('/apps', async (req, res) => {
    try {
        const newNote = await Note.create(req.body); // Utilisation directe de req.body pour créer la note
        res.status(201).json(newNote);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});







// GET - Récupérer une note par son ID
router.get('/:id', async (req, res) => {
    try {
        const note = await Note.findById(req.params.id); // Recherche de la note par ID dans la base de données

        if (!note) {
            return res.status(404).json({ error: 'Note not found' }); // Si la note n'est pas trouvée, renvoyer une réponse avec le code 404
        }

        res.json(note); // Renvoyer la note trouvée en tant que réponse JSON avec le code 200
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error' }); // En cas d'erreur serveur, renvoyer une réponse avec le code 500
    }
});











router.post('/api/apps/notes/tasks', async (req, res) => {
    try {
        // Récupérez les données de la note et de la tâche depuis le corps de la requête
        const { noteId, task } = req.body;
        // Recherchez la note dans la base de données par son ID
        const note = await Note.findById(noteId);
        if (!note) {
            return res.status(404).json({ message: "Note not found" });
        }
        // Ajoutez la tâche à la note
        note.tasks.push({ content: task });
        // Enregistrez la note mise à jour dans la base de données
        const updatedNote = await note.save();
        // Renvoyez la note mise à jour en réponse
        res.status(200).json(updatedNote);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Internal server error" });
    }
});


router.post('/api/apps/notes', async (req, res) => { try {
        // Récupérez les données de la note à partir du corps de la requête
        const { title, content, tasks, image, labels, archived } = req.body;
        // Créez une nouvelle instance de Note avec les données reçues
        const newNote = new Note({
            title,
            content,
            tasks,
            image,
            labels,
            archived
        });
        // Enregistrez la nouvelle note dans la base de données
        const createdNote = await newNote.save();
        // Répondez avec la note nouvellement créée
        res.status(201).json(createdNote);
    } catch (error) {
        // En cas d'erreur, répondez avec un code d'erreur 500 et un message d'erreur
        console.error(error);
        res.status(500).json({ message: 'An error occurred while creating the note.' });
    }
});


router.patch('/api/apps/notes/:id', async (req, res) => {
    const noteId = req.params.id;
    const updatedNoteData = req.body.updatedNote; // Supposons que vous envoyez les données de la note mise à jour dans req.body.updatedNote
    try {
        // Vérifiez si la note existe
        const note = await Note.findById(noteId);
        if (!note) {
            return res.status(404).json({ message: 'Note not found' });
        }
        // Mettez à jour les propriétés de la note avec les nouvelles données
        Object.assign(note, updatedNoteData);
        // Enregistrez les modifications dans la base de données
        const updatedNote = await note.save();
        // Répondez avec la note mise à jour
        res.status(200).json(updatedNote);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
// DELETE route pour supprimer une note par ID
router.delete('/api/apps/notes/:id', async (req, res) => {
    try {
        const note = await Note.findByIdAndDelete(req.params.id);
        if (!note) {
            return res.status(404).json({ message: "Note not found" });
        }
        // La note a été supprimée avec succès
        res.status(200).json({ message: "Note deleted successfully" });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Internal server error" });
    }
});




module.exports = router;
