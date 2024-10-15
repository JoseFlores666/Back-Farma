const bcrypt = require('bcryptjs');
const connection = require('../config/db');

// API para almacenar el token
const storeToken = (req, res) => {
    const { correo, token } = req.body;

    // Almacena el token en la base de datos asociado al correo
    connection.query("UPDATE usuarios SET verification_token = ? WHERE correo = ?", [token, correo], (err, result) => {
        if (err) {
            return res.status(500).send('Error en la base de datos');
        }
        res.status(200).send('Token guardado exitosamente.');
    });
};

// API para verificar el token
const verifyToken = (req, res) => {
    const { token, correo } = req.body;

    // Verifica si el token almacenado es igual al que el usuario ha proporcionado
    connection.query("SELECT verification_token FROM usuarios WHERE correo = ?", [correo], (err, result) => {
        if (err) {
            return res.status(500).send('Error en la base de datos');
        }

        res.status(200).send('Token válido.');
    });
};

// API para restablecer la contraseña
const resetPassword = (req, res) => {
    const { token, password } = req.body;

    // Actualiza la contraseña del usuario si el token es válido
    connection.query("SELECT correo FROM usuarios WHERE verification_token = ?", [token], (err, result) => {
        if (err) {
            return res.status(500).send('Error en la base de datos');
        }

        if (result.length === 0) {
            return res.status(400).send('Token inválido o expirado.');
        }

        const correo = result[0].correo;
        const hashedPassword = bcrypt.hashSync(password, 10); // Asegúrate de usar bcrypt para hashear la nueva contraseña

        connection.query("UPDATE usuarios SET password = ?, verification_token = NULL WHERE correo = ?", [hashedPassword, correo], (err) => {
            if (err) {
                return res.status(500).send('Error al actualizar la contraseña.');
            }

            res.status(200).send('Contraseña actualizada correctamente.');
        });
    });
};

module.exports = { storeToken, verifyToken, resetPassword };
