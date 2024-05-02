const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');

dotenv.config();

const verifyToken = (req, res, next) => {
    // Récupérer le jeton JWT de l'en-tête Authorization
    const token = req.headers.authorization && req.headers.authorization.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Unauthorized: Token is missing' });
    }

    // Vérifier le jeton JWT
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ error: 'Unauthorized: Invalid token' });
        }

        // Stocker les informations de l'utilisateur dans la demande
        req.user = decoded;
        next();
    });
};

module.exports = verifyToken;
