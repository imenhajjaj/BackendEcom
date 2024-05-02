const { check } = require('express-validator');
const validatorMiddleware = require('../../midelware/validators');

exports.getCategoryValidator = [
    check('id').isMongoId().withMessage('Invalid category id'), 
    validatorMiddleware
];
