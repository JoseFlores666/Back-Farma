const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { validateRegister } = require('../middlewares/validators');

router.post('/login', authController.login);
router.post('/register', validateRegister, authController.register);
router.post('/verify-email', authController.verifyEmail);

module.exports = router;