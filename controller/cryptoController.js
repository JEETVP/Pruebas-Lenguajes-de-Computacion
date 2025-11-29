const chacha20Service = require('../service/cryptoService');
const { rsaEncrypt, rsaDecrypt, getPublicKeyPem } = require('../service/cryptoService');
const {getDsaPublicKeyPem,signWithDsa,verifyWithDsa} = require('../service/cryptoService');

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

exports.encryptRSA = async (req, res) => {
  try {
    const { text } = req.body;

    // Validación: el campo text es obligatorio
    if (!text || text.trim() === '') {
      return res.status(400).json({
        error: 'El campo text es obligatorio'
      });
    }

    // Llamar al servicio de cifrado
    const result = rsaEncrypt(text);

    // Responder con el texto cifrado y metadatos
    return res.status(200).json({
      algorithm: 'RSA-OAEP',
      modulusLength: 2048,
      cipherTextBase64: result.cipherTextBase64,
      publicKeyPem: result.publicKeyPem
    });

  } catch (err) {
    console.error('Error al cifrar con RSA-OAEP:', err);
    return res.status(500).json({
      error: 'Error al cifrar con RSA-OAEP'
    });
  }
};


exports.decryptRSA = async (req, res) => {
  try {
    const { cipherTextBase64 } = req.body;

    // Validación: el campo cipherTextBase64 es obligatorio
    if (!cipherTextBase64 || cipherTextBase64.trim() === '') {
      return res.status(400).json({
        error: 'El campo cipherTextBase64 es obligatorio'
      });
    }

    // Llamar al servicio de descifrado
    const result = rsaDecrypt(cipherTextBase64);

    // Responder con el texto descifrado
    return res.status(200).json({
      algorithm: 'RSA-OAEP',
      plainText: result.plainText
    });

  } catch (err) {
    console.error('Error al descifrar con RSA-OAEP:', err);
    return res.status(500).json({
      error: 'Error al descifrar con RSA-OAEP'
    });
  }
};

exports.signDsa = async (req, res) => {
  try {
    const { message } = req.body;

    // Validación: el campo message es obligatorio
    if (!message || message.trim() === '') {
      return res.status(400).json({
        error: 'El campo message es obligatorio'
      });
    }

    // Llamar al servicio de firma
    const result = signWithDsa(message);

    // Responder con la firma y metadatos
    return res.status(200).json({
      algorithm: result.algorithm,
      keySize: result.keySize,
      message: message,
      signatureBase64: result.signatureBase64,
      publicKeyPem: result.publicKeyPem
    });

  } catch (err) {
    console.error('Error al firmar con DSA:', err);
    return res.status(500).json({
      error: 'Error al firmar con DSA'
    });
  }
};

exports.verifyDsa = async (req, res) => {
  try {
    const { message, signatureBase64 } = req.body;

    // Validación: ambos campos son obligatorios
    if (!message || message.trim() === '') {
      return res.status(400).json({
        error: 'El campo message es obligatorio'
      });
    }

    if (!signatureBase64 || signatureBase64.trim() === '') {
      return res.status(400).json({
        error: 'El campo signatureBase64 es obligatorio'
      });
    }

    // Llamar al servicio de verificación
    const result = verifyWithDsa(message, signatureBase64);

    // Responder con el resultado de la verificación
    return res.status(200).json({
      algorithm: result.algorithm,
      keySize: result.keySize,
      message: message,
      signatureBase64: signatureBase64,
      isValid: result.isValid
    });

  } catch (err) {
    console.error('Error al verificar firma DSA:', err);
    return res.status(500).json({
      error: 'Error al verificar con DSA'
    });
  }
};