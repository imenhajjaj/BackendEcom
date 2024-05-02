let jwt = require('jsonwebtoken');
require('dotenv').config();

module.exports = (req, res, next) =>  {
try{
  const token = req.headers.authorization.split(' ')[1];
  req.token = jwt.verify(token, process.env.TOKEN_KEY);
  next(); 

} catch {
  res.status(401).json({ message: "tooken authe invalide "});

}


}