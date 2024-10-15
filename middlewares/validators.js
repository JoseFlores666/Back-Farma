const { body, validationResult } = require('express-validator');

const validateRegister = [
    body('nombre')
        .isLength({ min: 3 }).withMessage('El nombre debe tener al menos 3 caracteres')
        .matches(/^[a-zA-Z ]+$/).withMessage('El nombre solo puede contener letras y espacios')
        .trim()
        .escape(),

    body('correo')
        .isEmail().withMessage('Debe ser un correo válido')
        .normalizeEmail(), 

    body('password')
        .isLength({ min: 6 }).withMessage('La contraseña debe tener al menos 6 caracteres')
        .matches(/\d/).withMessage('La contraseña debe contener al menos un número')
        .trim(),

    body('edad')
        .isInt({ min: 18 }).withMessage('Debes ser mayor de 18 años')
        .toInt(), 

    body('telefono')
        .isLength({ min: 10, max: 10 }).withMessage('El teléfono debe tener 10 dígitos')
        .isNumeric().withMessage('El teléfono solo debe contener números')
        .trim(),

    (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        next();
    }
];

module.exports = { validateRegister };
