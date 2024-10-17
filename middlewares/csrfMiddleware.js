const csrf = require('csurf');

// Configuración del middleware CSRF
const csrfProtection = csrf({ cookie: true });

module.exports = csrfProtection;
