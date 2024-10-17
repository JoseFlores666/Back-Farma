const bcrypt = require('bcryptjs');
const sanitizeHtml = require('sanitize-html');  // Librería para sanitizar HTML
const connection = require('../config/db');

// API para almacenar el token
const storeToken = (req, res) => {
    const { correo, token } = req.body;

    // Sanitizar entradas
    const sanitizedCorreo = sanitizeHtml(correo);
    const sanitizedToken = sanitizeHtml(token);

    // Establecer la expiración del token (15 minutos desde ahora)
    const expirationTime = new Date(Date.now() + 15 * 60 * 1000); // 15 minutos

    // Almacenar el token y la fecha de expiración en la base de datos
    connection.query(
        "UPDATE usuarios SET verification_token = ?, token_expiration = ? WHERE correo = ?",
        [sanitizedToken, expirationTime, sanitizedCorreo], 
        (err, result) => {
            if (err) {
                return res.status(500).send('Error en la base de datos');
            }
            res.status(200).send('Token y tiempo de expiración guardados exitosamente.');
        }
    );
};

// API para verificar el token
const verifyToken = (req, res) => {
    const { token, correo } = req.body;

    // Sanitizar entradas
    const sanitizedToken = sanitizeHtml(token);
    const sanitizedCorreo = sanitizeHtml(correo);

    // Verifica si el token almacenado es igual al que el usuario ha proporcionado
    connection.query(
        "SELECT verification_token, token_expiration FROM usuarios WHERE correo = ?", 
        [sanitizedCorreo], 
        (err, result) => {
            if (err) {
                return res.status(500).send('Error en la base de datos');
            }

            if (result.length === 0 || result[0].verification_token !== sanitizedToken) {
                return res.status(400).send('Token inválido.');
            }

            // Verificar si el token ha expirado
            const now = new Date();
            if (now > new Date(result[0].token_expiration)) {
                return res.status(400).send('Token expirado.');
            }

            res.status(200).send('Token válido y no expirado.');
        }
    );
};

// API para restablecer la contraseña
const resetPassword = (req, res) => {
    const { token, password } = req.body;

    // Sanitizar token
    const sanitizedToken = sanitizeHtml(token);

    // Actualiza la contraseña del usuario si el token es válido
    connection.query(
        "SELECT correo, token_expiration FROM usuarios WHERE verification_token = ?", 
        [sanitizedToken], 
        (err, result) => {
            if (err) {
                return res.status(500).send('Error en la base de datos');
            }

            if (result.length === 0) {
                return res.status(400).send('Token inválido.');
            }

            // Verificar si el token ha expirado
            const now = new Date();
            if (now > new Date(result[0].token_expiration)) {
                return res.status(400).send('Token expirado.');
            }

            const correo = result[0].correo;
            const hashedPassword = bcrypt.hashSync(password, 10); // Asegúrate de usar bcrypt para hashear la nueva contraseña

            // Actualizar la contraseña y eliminar el token
            connection.query(
                "UPDATE usuarios SET password = ?, verification_token = NULL, token_expiration = NULL WHERE correo = ?", 
                [hashedPassword, correo], 
                (err) => {
                    if (err) {
                        return res.status(500).send('Error al actualizar la contraseña.');
                    }

                    res.status(200).send('Contraseña actualizada correctamente.');
                }
            );
        }
    );
};

module.exports = { storeToken, verifyToken, resetPassword };
