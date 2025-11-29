const express = require('express');
const cryptoController = require('../controller/cryptoController');
const router = express.Router();

router.post('/api/encrypt/chacha20', cryptoController.chacha20Encrypt);
router.post('/api/decrypt/chacha20', cryptoController.chacha20Decrypt);

// Exportar el router
module.exports = router;