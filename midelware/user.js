let jwt = require("jsonwebtoken");
require('dotenv').config();

// Define the signIn API
exports.login = (req, res) => {
    // Check if the user is already logged in
    if (req.body.email == "imen@gmail.com" && req.body.password == "admin") {
      let token = jwt.sign({ userId: 10}, process.env.TOKEN_KEY);
      res.status(200).json({token});
    } else {
      res.status(401).json({message: "login ou mots de passe incorret"});
    }
  };


exports.test = (req, res) => {
    res.status(200).json({ message: "vous etes bien authentifie l'id: " + req.token.userId});
}