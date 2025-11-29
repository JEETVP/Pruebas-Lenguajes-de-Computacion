const express = require('express');
const cryptoRoute = require('./route/cryptoRoute');
const app = express();

app.use(express.json());

app.use(cryptoRoute);

app.get('/', (req, res) => {
  res.json({ status: 'API ChaCha20 funcionando correctamente' });
});

// Puerto
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en puerto ${PORT}`);
});