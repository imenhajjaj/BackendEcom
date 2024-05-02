const User = require('../models/user');

async function signUp(req, res) {
  try {
    const { name, email, password, company } = req.body;

    // Vérifier si l'utilisateur existe déjà
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Créer un nouvel utilisateur
    const newUser = new User({ name, email, password, company });
    await newUser.save();

    // Envoyer une réponse réussie
    res.status(201).json({ message: 'User created successfully' });
  } catch (error) {
    // Gérer les erreurs
    console.error('Error signing up:', error);
    res.status(500).json({ message: 'An error occurred while signing up' });
  }
}

module.exports = { signUp };