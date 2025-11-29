const express = require('express');
const cryptoController = require('../controller/cryptoController');
const router = express.Router();

router.post('/api/encrypt/chacha20', cryptoController.chacha20Encrypt);
router.post('/api/decrypt/chacha20', cryptoController.chacha20Decrypt);
router.post('/api/encrypt/rsa', cryptoController.encryptRSA);
router.post('/api/decrypt/rsa', cryptoController.decryptRSA);

// Exportar el router
module.exports = router;