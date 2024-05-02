const express = require('express');
const router = express.Router();
const Task = require('../models/task');
const Tag= require('../models/tag');
const cors = require('cors');

// Activer CORS pour cette route
router.use(cors());

router.get('/api/apps/tasks/tags', async (req, res) => {
    try {
        const tags = await Tag.find({}, 'title');
        res.json(tags);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

router.post('/api/apps/tasks/tag', async (req, res) => {
    try {
        const newTag = new Tag(req.body);
        await newTag.save();
        res.status(201).json(newTag);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

router.patch('/api/apps/tasks/tag/:id', async (req, res) => {
    const { id } = req.params;
    const { title } = req.body;
    try {
        const updatedTag = await Tag.findByIdAndUpdate(id, { title }, { new: true });
        if (!updatedTag) {
            return res.status(404).json({ message: "Tag not found" });
        }
        res.json(updatedTag);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

router.delete('/api/apps/tasks/tag/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const deletedTag = await Tag.findByIdAndDelete(id);
        if (!deletedTag) {
            return res.status(404).json({ message: "Tag not found" });
        }
        res.json({ message: "Tag deleted successfully" });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

router.get('/api/apps/tasks/all', async (req, res) => {
    try {
        const tasks = await Task.find();
        res.json(tasks);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});


router.patch('/api/apps/tasks/order', async (req, res) => {
    const { tasks } = req.body;
    try {
        // Mise à jour de l'ordre des tâches
        for (let task of tasks) {
            await Task.findByIdAndUpdate(task.id, { order: task.order });
        }
        res.json(tasks);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

router.get('/api/apps/tasks/search', async (req, res) => {
    const { query } = req.query;
    try {
        // Recherche des tâches en fonction de la requête
        const tasks = await Task.find({ $text: { $search: query } });
        res.json(tasks);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

router.get('/api/apps/tasks/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const task = await Task.findById(id);
        if (!task) {
            return res.status(404).json({ message: "Task not found" });
        }
        res.json(task);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});


router.get('/api/apps/tasks/task/:id', async (req, res) => {
    try {
        // Extraire l'ID de la tâche à récupérer à partir des paramètres de l'URL
        const taskId = req.params.id;

        // Rechercher la tâche dans la base de données en fonction de son ID
        const task = await Task.findById(taskId);

        // Si la tâche est trouvée, renvoyer la tâche
        if (task) {
            res.status(200).json(task);
        } else {
            // Si la tâche n'est pas trouvée, renvoyer une erreur 404
            res.status(404).json({ message: 'Task not found' });
        }
    } catch (error) {
        // En cas d'erreur, renvoyer une réponse d'erreur avec le code 500
        res.status(500).json({ message: error.message });
    }
});



// Route POST pour créer une nouvelle tâche
router.post('/api/apps/tasks/task', async (req, res) => {
    try {
        // Extraire les données de la requête
        const { type, title, notes, completed, dueDate, priority, tags, order } = req.body;
        // Créer une nouvelle instance de la tâche
        const newTask = new Task({
            type,
            title,
            notes,
            completed,
            dueDate,
            priority,
            tags,
            order
        });
        // Enregistrer la nouvelle tâche dans la base de données
        const savedTask = await newTask.save();
        // Répondre avec la nouvelle tâche créée
        res.status(201).json(savedTask);
    } catch (error) {
        // En cas d'erreur, répondre avec le code d'erreur 500 et le message d'erreur
        res.status(500).json({ message: error.message });
    }
});

// Route DELETE pour supprimer une tâche
router.delete('/api/apps/tasks/task/:id', async (req, res) => {
    try {
        // Extraire l'ID de la tâche à supprimer à partir des paramètres de l'URL
     const taskId = req.params.id;
        // Supprimer la tâche de la base de données en fonction de son ID
        const deletedTask = await Task.findByIdAndDelete(taskId);
        // Si la tâche est supprimée avec succès, renvoyer true
        if (deletedTask) {
            res.status(200).json(true);
        } else {
            // Si la tâche n'est pas trouvée, renvoyer une erreur 404
            res.status(404).json({ message: 'Task not found' });
        }
    } catch (error) {
        // En cas d'erreur, renvoyer une réponse d'erreur avec le code 500
        res.status(500).json({ message: error.message });
    }
});

router.patch('/api/apps/tasks/task/:id', async (req, res) => {
    try {
        // Extraire l'ID de la tâche à mettre à jour à partir des paramètres de l'URL
        const taskId = req.params.id;

        // Extraire les données de la tâche à mettre à jour du corps de la requête
        const { task } = req.body;

        // Mettre à jour la tâche dans la base de données en fonction de son ID
        const updatedTask = await Task.findByIdAndUpdate(taskId, task, { new: true });

        // Si la tâche est mise à jour avec succès, renvoyer la tâche mise à jour
        if (updatedTask) {
            res.status(200).json(updatedTask);
        } else {
            // Si la tâche n'est pas trouvée, renvoyer une erreur 404
            res.status(404).json({ message: 'Task not found' });
        }
    } catch (error) {
        // En cas d'erreur, renvoyer une réponse d'erreur avec le code 500
        res.status(500).json({ message: error.message });
    }
});


module.exports = router;

