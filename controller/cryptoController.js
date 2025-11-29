const chacha20Service = require('../service/cryptoService');

exports.chacha20Encrypt = async (req, res) => {
  try {
    // Extraer datos del body
    const { text, keyBase64, nonceBase64 } = req.body;

    // Validar que el campo text sea obligatorio
    if (!text) {
      return res.status(400).json({
        error: 'El campo text es obligatorio'
      });
    }

    // Validar que text sea un string
    if (typeof text !== 'string') {
      return res.status(400).json({
        error: 'El campo text debe ser una cadena de texto'
      });
    }

    // Llamar al servicio de cifrado
    const result = chacha20Service.encryptChaCha20(
      text,
      keyBase64 || null,
      nonceBase64 || null
    );

    // Responder con los datos cifrados
    return res.status(200).json({
      algorithm: 'chacha20-poly1305',
      cipherTextBase64: result.cipherTextBase64,
      keyBase64: result.keyBase64,
      nonceBase64: result.nonceBase64,
      authTagBase64: result.authTagBase64
    });

  } catch (error) {
    // Log del error para debugging
    console.error('Error en chacha20Encrypt:', error);

    // Determinar si es error de validación o error interno
    const isValidationError = error.message.includes('debe tener') || 
                              error.message.includes('exactamente');

    return res.status(isValidationError ? 400 : 500).json({
      error: error.message
    });
  }
};

exports.chacha20Decrypt = async (req, res) => {
  try {
    // Extraer datos del body
    const { cipherTextBase64, keyBase64, nonceBase64, authTagBase64 } = req.body;

    // Validar que todos los campos requeridos estén presentes
    const missingFields = [];
    if (!cipherTextBase64) missingFields.push('cipherTextBase64');
    if (!keyBase64) missingFields.push('keyBase64');
    if (!nonceBase64) missingFields.push('nonceBase64');
    if (!authTagBase64) missingFields.push('authTagBase64');

    if (missingFields.length > 0) {
      return res.status(400).json({
        error: `Faltan los siguientes campos obligatorios: ${missingFields.join(', ')}`
      });
    }

    // Validar que todos los campos sean strings
    if (typeof cipherTextBase64 !== 'string' || 
        typeof keyBase64 !== 'string' || 
        typeof nonceBase64 !== 'string' || 
        typeof authTagBase64 !== 'string') {
      return res.status(400).json({
        error: 'Todos los campos deben ser cadenas de texto en Base64'
      });
    }

    // Llamar al servicio de descifrado
    const result = chacha20Service.decryptChaCha20(
      cipherTextBase64,
      keyBase64,
      nonceBase64,
      authTagBase64
    );

    // Responder con el texto descifrado
    return res.status(200).json({
      algorithm: 'chacha20-poly1305',
      plainText: result.plainText
    });

  } catch (error) {
    // Log del error para debugging
    console.error('Error en chacha20Decrypt:', error);

    // Determinar si es error de validación o error interno
    const isValidationError = error.message.includes('debe tener') || 
                              error.message.includes('exactamente') ||
                              error.message.includes('Unsupported state');

    return res.status(isValidationError ? 400 : 500).json({
      error: error.message
    });
  }
};