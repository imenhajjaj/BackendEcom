const express = require('express');
const uuid = require('uuid');
const bodyParser = require('body-parser');
const morgan = require('morgan');
const cors = require('cors');
const dotenv= require('dotenv');
dotenv.config({ path: '.env'});
const ApiError = require('./utils/apiErrors');
const verifyToken = require('./routes/verifyToken');




const productRoute = require('./routes/product')
const userRoute = require('./routes/user');
const companytRoute = require('./routes/company');
const storeRoute = require('./routes/store');
const fileRoute = require('./routes/file');
const categoryRoute = require('./routes/category');
const contactRoute = require('./routes/contact');
const magazinRoute = require('./routes/magazin');
const fournisseurRoute = require('./routes/fournisseur');
const notificationRoute = require('./routes/notification');


require('./config/connect');

const app = express();
app.use(express.json());
app.use(morgan('dev'));



app.get('/', (req, res) => {
  res.send('Our running v1');
});


app.use((err, req, res, next) =>  {
  err.statusCode = err.statusCode || 500;
  err.status = err.status || 'error';
  res.status(err.statusCode).json({
   status: err.status,
   error: err,
   message: err.message,
   stack: err.stack, 
  });
});
//products pour récuperer



app.use('/company' , companytRoute);
app.use('/store' , storeRoute);




app.use('/', userRoute);
app.use('/', contactRoute);
app.use('/', magazinRoute);

app.use('/', productRoute);
app.use('/', fournisseurRoute);
app.use('/', notificationRoute);



app.use('/file' , fileRoute);
app.use('/api/v1/category' , categoryRoute);
app.use(bodyParser.json());
app.use(cors());
app.options('*', cors());

const api = process.env.API_URL;


app.all('*', (req, res, next) => {
  next(new ApiError(`Can't find this route: ${req.originalUrl}`, 400));
});




// Routes d'authentification

// Exemple de route protégée
app.get('/api/protected-route', verifyToken, (req, res) => {
    // Vous pouvez accéder aux informations de l'utilisateur via req.user
    res.json({ message: 'Protected route accessed', user: req.user });
});





app.use('/getimage', express.static('./uploads'))

const PORT = process.env.PORT || 8000;
app.listen(PORT, ()=> {
  console.log('server work ${PORT}');
});



