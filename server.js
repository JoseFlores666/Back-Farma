const app = require('./app');
const connection = require('./config/db'); 
const PORT = process.env.PORT || 4000;

app.listen(PORT, () => {
    console.log(`Servidor escuchando en el puerto ${PORT}`);
});

process.on('SIGINT', () => {
    connection.end((err) => {
        console.log('Desconectado de la base de datos MySQL.');
        process.exit(err ? 1 : 0);
    });
});
