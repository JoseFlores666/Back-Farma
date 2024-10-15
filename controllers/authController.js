const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const connection = require('../config/db');

const register = (req, res) => {
    const { nombre, apellidos, edad, telefono, correo, password, verification_token } = req.body;

    connection.query("SELECT * FROM usuarios WHERE correo = ?", [correo], (err, result) => {
        if (err) {
            return res.status(500).send('Error en la base de datos');
        }

        if (result.length > 0) {
            return res.status(400).send('El correo ya está en uso');
        }

        const hashedPassword = bcrypt.hashSync(password, 10);

        const newUser = {
            nombre,
            apellidos,
            edad,
            telefono,
            correo,
            password: hashedPassword,
            verification_token,
            isVerified: false
        };

        connection.query("INSERT INTO usuarios SET ?", newUser, (err) => {
            if (err) {
                return res.status(500).send('Error al registrar el usuario');
            }
            res.status(201).send('Usuario registrado exitosamente. Revisa tu correo para verificar la cuenta.');
        });
    });
};

const login = (req, res) => {
    const { correo, password } = req.body;

    connection.query("SELECT * FROM usuarios WHERE correo = ?", [correo], (err, result) => {
        if (err) {
            return res.status(500).send('Error en la base de datos');
        }

        if (result.length === 0) {
            return res.status(400).send('Correo o contraseña incorrectos');
        }

        const user = result[0];

        if (!user.isVerified) {
            return res.status(400).send('Por favor, verifica tu cuenta antes de iniciar sesión.');
        }

        const passwordIsValid = bcrypt.compareSync(password, user.password);
        if (!passwordIsValid) {
            return res.status(400).send('Correo o contraseña incorrectos');
        }

        connection.query("UPDATE usuarios SET intentos_fallidos = 0 WHERE correo = ?", [correo], (err) => {
            if (err) {
                return res.status(500).send('Error al restablecer intentos fallidos');
            }

            const sessionId = crypto.randomBytes(16).toString('hex');
            req.session.sessionId = sessionId;

            res.cookie('sessionId', sessionId, {
                httpOnly: true,
                secure: true,
                sameSite: 'Strict',
                maxAge: 30 * 60 * 1000
            });

            res.status(200).send({
                id: user.id,
                nombre: user.nombre,
                correo: user.correo,
            });
        });
    });
};
const verifyEmail = (req, res) => {
    const { correo, token } = req.body;

    if (!correo || !token) {
        return res.status(400).send('Faltan datos en la solicitud');
    }

    connection.query("SELECT * FROM usuarios WHERE correo = ? AND verification_token = ?", [correo, token], (err, result) => {
        if (err) {
            return res.status(500).send('Error en la base de datos');
        }

        console.log("Resultado de la consulta:", result);

        if (result.length === 0) {
            return res.status(400).send('Token de verificación incorrecto o usuario no encontrado');
        }

        const user = result[0];

        if (user.isVerified) {
            return res.status(400).send('La cuenta ya ha sido verificada.');
        }

        connection.query("UPDATE usuarios SET isVerified = true WHERE correo = ?", [correo], (err) => {
            if (err) {
                return res.status(500).send('Error al verificar la cuenta');
            }
            res.status(200).send('Cuenta verificada exitosamente.');
        });
    });
};

module.exports = { register, login, verifyEmail };
