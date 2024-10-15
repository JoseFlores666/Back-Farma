const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const passwordController = require('../controllers/passwordController'); 
const { validateRegister } = require('../middlewares/validators');

router.post('/login', authController.login);
router.post('/register', validateRegister, authController.register);
router.post('/verify-email', authController.verifyEmail);

router.post('/storetoken', passwordController.storeToken); 
router.post('/verifytoken', passwordController.verifyToken); 
router.post('/resetpassword', passwordController.resetPassword);

module.exports = router;