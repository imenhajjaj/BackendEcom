const express = require('express');
const AWS = require('aws-sdk');
const router = express.Router();
const fs = require('fs');
const multer = require('multer');
const multerS3 = require('multer-s3');
const { S3Client, ListObjectsCommand } = require('@aws-sdk/client-s3');
const { fromIni } = require("@aws-sdk/credential-provider-ini");

// Configure the AWS credentials and endpoint URL
const s3Client = new S3Client({
  region: 'eu2',
  credentials: {
    accessKeyId: 'ed2abe07787ef24002a356bc45fb779f',
    secretAccessKey: '32492eaee4100346b0efc3357cbea861',
  },
  endpoint: 'https://eu2.contabostorage.com/',
});

// Configure Multer to use S3 storage
const upload = multer({
  storage: multerS3({
    s3: s3Client,
    bucket: 'inveep-storage',
    key: function (req, file, cb) {
      cb(null, Date.now().toString() + '-' + file.originalname);
    },
  }),
});

// Create an Express app and define a route to handle file uploads
const app = express();
router.post('/telecharger', upload.single('file'), (req, res) => {
  const file = req.file;
  if (!file) {
    return res.status(500).send('Error uploading file');
  }
  res.status(200).send(`File uploaded successfully: ${file.location}`);
});



/*
//get All
const listParams = {
  Bucket: "inveep-storage"
};

// Appel de la commande ListObjects pour lister les objets dans le bucket S3
s3Client.send(new ListObjectsCommand(listParams))
  .then(data => console.log(data.Contents))
  .catch(err => console.error(err));

*/


/*
// Define the parameters for the list objects command
const listParams = {
  Bucket: 'inveep-storage'
};

// List the objects in the bucket
s3Client.send(new ListObjectsCommand(listParams))
  .then((data) => {
    // Download each object
    data.Contents.forEach((object) => {
      const downloadParams = {
        Bucket: 'inveep-storage',
        Key: object.Key,
      };
 // Download the object to a file
 const fileStream = s3Client.send(new GetObjectCommand(downloadParams));
 const writeStream = fs.createWriteStream(`path/to/local/file/${object.Key}`);
 fileStream.pipe(writeStream);
});
})
.catch(console.error);
*/
module.exports = router;
