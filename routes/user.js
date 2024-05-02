const express = require('express');
const router = express.Router();
const User = require('../models/user');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
dotenv.config();
const bcrypt = require('bcryptjs');
const isAuth = require('../controllers/isAuth');
const user = require('../midelware/user');

const { signUp } = require('../controllers/user');

// Route pour l'inscription d'un utilisateur
router.post('/api/auth/sign-up', signUp);


router.post('/api/auth/forgot-password', (req, res) => {
    const email = req.body.email;
    // Vérification que l'e-mail est fourni
    if (!email) {
        return res.status(400).json({ error: "L'e-mail est requis." });
    }
    // Insérez ici la logique pour envoyer un e-mail de réinitialisation de mot de passe
    // Réponse réussie
    return res.status(200).json({ message: "Un e-mail de réinitialisation de mot de passe a été envoyé." });
});

// Endpoint pour la fonction resetPassword
router.post('/api/auth/reset-password', (req, res) => {
    const password = req.body.password;
    // Vérification que le mot de passe est fourni
    if (!password) {
        return res.status(400).json({ error: "Le mot de passe est requis." });
    }
    // Insérez ici la logique pour réinitialiser le mot de passe de l'utilisateur

    // Réponse réussie
    return res.status(200).json({ message: "Le mot de passe a été réinitialisé avec succès." });
});




// Define the authentication middleware
const authenticate = async (req, res, next) => {
  const token = req.header('x-auth-token');
  if (!token) return res.status(401).send('Access denied. No token provided.');
  try {
    const decoded = jwt.verify(token, process.env.SECRET_KEY);
    req.user = decoded;
    next();
  } catch (ex) {
    res.status(400).send('Invalid token.');
  }
};


 
router.post("/login", user.login);
router.get("/test", isAuth, user.test);


/*
router.post('/api/auth/sign-in', async (req, res) => {
    const { email, password } = req.body;
    try {
        // Recherche de l'utilisateur dans la base de données
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ message: 'Invalid email or password.' });
        }
        // Vérification du mot de passe
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(401).json({ message: 'Invalid email or password.' });
        }
        // Création du jeton d'accès
        const accessToken = jwt.sign({ userId: user._id }, 'secret_key', { expiresIn: '1h' });

        // Envoi de la réponse avec le jeton d'accès et les détails de l'utilisateur
        res.json({
            accessToken,
            user: {
                email: user.email
                // Ajoutez d'autres détails de l'utilisateur si nécessaire
            }
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal server error.' });
    }
});

*/
router.post('/api/auth/register', async (req, res) => {
    const { email, password } = req.body;
    try {
        // Vérification si l'utilisateur existe déjà dans la base de données
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'User already exists.' });
        }
        // Hachage du mot de passe avant de l'enregistrer dans la base de données
        const hashedPassword = await bcrypt.hash(password, 10);
        // Création d'un nouvel utilisateur
        const newUser = new User({
            email,
            password: hashedPassword
        });
        // Enregistrement de l'utilisateur dans la base de données
        await newUser.save();
        // Création du jeton d'accès
        const accessToken = jwt.sign({ userId: newUser._id }, 'secret_key', { expiresIn: '1h' });
        // Envoi de la réponse avec le jeton d'accès et les détails de l'utilisateur
        res.json({
            accessToken,
            user: {
                email: newUser.email
                // Ajoutez d'autres détails de l'utilisateur si nécessaire
            }
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal server error.' });
    }
});




router.get('/api/common/user', (req, res) => {
    // Simuler un délai de traitement
    setTimeout(() => {
        res.json(currentUser);
    }, 1000); // Délai de 1 seconde
});



router.patch('/api/common/user', (req, res) => {
    const updatedUser = req.body.user;
    currentUser = { ...currentUser, ...updatedUser };
    res.json(currentUser);
});

router.post('/api/auth/sign-out', (req, res) => {
    // Supprimer le jeton d'accès de la session du serveur (si nécessaire)
    // Par exemple, si vous stockez le jeton d'accès dans une liste noire pour le révoquer

    // Réponse réussie
    return res.status(200).json({ message: "Déconnexion réussie." });
});


router.post('/api/auth/unlock-session', async (req, res) => {
    const { email, password } = req.body;
    try {
        // Vérification que les identifiants sont fournis
        if (!email || !password) {
            return res.status(400).json({ error: "Veuillez fournir une adresse e-mail et un mot de passe." });
        }
        // Recherche de l'utilisateur dans la base de données
        const user = await User.findOne({ email });
        // Vérification si l'utilisateur existe
        if (!user) {
            return res.status(404).json({ error: "Aucun utilisateur trouvé avec cet e-mail." });
        }
        // Vérification si le mot de passe est correct
        if (password !== user.password) { // Remplacer cette comparaison par la logique de vérification de mot de passe sécurisée
            return res.status(401).json({ error: "Mot de passe incorrect." });
        }
        // Réponse réussie avec les informations de l'utilisateur
        return res.status(200).json(user);
    } catch (error) {
        console.error("Erreur lors du déverrouillage de la session :", error);
        return res.status(500).json({ error: "Erreur lors du déverrouillage de la session de l'utilisateur." });
    }
});





router.get('/api/auth/check', async (req, res) => {
    // Vérifiez si l'utilisateur est authentifié (vous pouvez implémenter votre propre logique ici)
    const authenticated = req.isAuthenticated();
    // Si l'utilisateur est authentifié, renvoyez ses informations
    if (authenticated) {
        const userId = req.user.id; // Supposons que vous stockez l'ID de l'utilisateur dans la session
        try {
            const user = await User.findById(userId);
            return res.status(200).json({ authenticated: true, user });
        } catch (error) {
            console.error("Erreur lors de la recherche de l'utilisateur :", error);
            return res.status(500).json({ error: "Erreur lors de la recherche de l'utilisateur." });
        }
    }
    // Si l'utilisateur n'est pas authentifié, renvoyez false
    return res.status(200).json({ authenticated: false });
});
/*

router.post('/api/auth/sign-up', async (req, res) => {
    try {
        // Récupération des données de l'utilisateur depuis le corps de la requête
        const { name, email, password, company } = req.body;
        // Vérification si toutes les données nécessaires sont fournies
        if (!name || !email || !password || !company) {
            return res.status(400).json({ message: 'Tous les champs sont requis' });
        }
        // Vérification si l'utilisateur existe déjà dans la base de données
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(409).json({ message: 'Cet email est déjà utilisé' });
        }
        // Création d'une nouvelle instance de User avec les données reçues
        const newUser = new User({ name, email, password, company });
        // Sauvegarde de l'utilisateur dans la base de données
        await newUser.save();
        // Réponse avec le code d'état HTTP 201 (Created) en cas de succès
        res.status(201).json({ message: 'Inscription réussie', user: newUser });
    } catch (error) {
        // Gestion des erreurs
        console.error('Erreur lors de l\'inscription :', error);
        res.status(500).json({ message: 'Erreur lors de l\'inscription' });
    }
});


*/




// Simulation de données utilisateur
const users = [
    {
        id: 1,
        email: 'jamila@company.com',
        password: 'admin',
        role: 'admin'
    },
    {
        id: 2,
        email: 'userhajjaj@company.com',
        password: 'user',
        role: 'user'
    }
];

// Fonction pour générer un jeton JWT (à remplacer par votre propre implémentation)
function generateJWTToken() {
    // Votre implémentation pour générer un jeton JWT
    return 'jwt_token_here';
}

// Route pour gérer l'authentification
router.post('/api/auth/sign-in', (req, res) => {
    const { email, password } = req.body;
    
    // Recherchez l'utilisateur correspondant aux informations d'identification fournies
    const user = users.find(u => u.email === email && u.password === password);
    
    if (user) {
        // Authentification réussie, renvoie les données utilisateur et le jeton JWT
        const response = {
            user: {
                id: user.id,
                email: user.email,
                role: user.role
                // Ajoutez d'autres champs utilisateur si nécessaire
            },
            accessToken: generateJWTToken(),
            tokenType: 'bearer'
        };
        
        res.status(200).json(response);
    } else {
        // Identifiants invalides, renvoie une réponse d'erreur
        res.status(401).json({ error: 'Invalid credentials' });
    }
});


// Fonction pour vérifier le jeton JWT (à remplacer par votre propre implémentation)
function verifyJWTToken(accessToken) {
    // Votre implémentation pour vérifier le jeton JWT
    return true; // Par exemple, retourne toujours vrai pour cet exemple
}

// Fonction pour générer un jeton JWT (à remplacer par votre propre implémentation)
function generateJWTToken() {
    // Votre implémentation pour générer un jeton JWT
    return 'jwt_token_here';
}

// Route pour gérer l'authentification avec un jeton JWT
router.post('/api/auth/sign-in-with-token', (req, res) => {
    const { accessToken } = req.body;
    
    // Vérifiez si le jeton JWT est valide
    if (verifyJWTToken(accessToken)) {
        // Jeton JWT valide, renvoie les données utilisateur et un nouveau jeton JWT
        const response = {
            user: {
                // Récupérez les données utilisateur à partir du jeton JWT ou d'une autre source
                // Remarque : cette partie doit être adaptée à votre implémentation spécifique
            },
            accessToken: generateJWTToken(),
            tokenType: 'bearer'
        };
        
        res.status(200).json(response);
    } else {
        // Jeton JWT invalide, renvoie une réponse d'erreur
        res.status(401).json({ error: 'Invalid token' });
    }
});





module.exports = router;



