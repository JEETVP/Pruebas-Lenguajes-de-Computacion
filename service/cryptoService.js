const crypto = require('crypto');

/**
 * Cifra un texto plano usando ChaCha20-Poly1305
 * @param {string} plainText - Texto a cifrar en formato UTF-8
 * @param {string|null} keyBase64 - Clave en Base64 (32 bytes). Si es null, se genera automáticamente
 * @param {string|null} nonceBase64 - Nonce en Base64 (12 bytes). Si es null, se genera automáticamente
 * @returns {Object} Objeto con cipherTextBase64, keyBase64, nonceBase64 y authTagBase64
 */
function encryptChaCha20(plainText, keyBase64, nonceBase64) {
  try {
    // Generar o validar la clave (debe ser de 32 bytes)
    let key;
    if (!keyBase64) {
      // Generar clave aleatoria de 32 bytes
      key = crypto.randomBytes(32);
    } else {
      // Convertir clave de Base64 a Buffer
      key = Buffer.from(keyBase64, 'base64');
      
      // Validar longitud de la clave
      if (key.length !== 32) {
        throw new Error('La clave debe tener exactamente 32 bytes');
      }
    }

    // Generar o validar el nonce (debe ser de 12 bytes)
    let nonce;
    if (!nonceBase64) {
      // Generar nonce aleatorio de 12 bytes
      nonce = crypto.randomBytes(12);
    } else {
      // Convertir nonce de Base64 a Buffer
      nonce = Buffer.from(nonceBase64, 'base64');
      
      // Validar longitud del nonce
      if (nonce.length !== 12) {
        throw new Error('El nonce debe tener exactamente 12 bytes');
      }
    }

    // Crear el cipher con ChaCha20-Poly1305
    const cipher = crypto.createCipheriv('chacha20-poly1305', key, nonce, {
      authTagLength: 16
    });

    // Cifrar el texto plano (convertir de UTF-8 a Buffer)
    let cipherText = cipher.update(plainText, 'utf8');
    cipherText = Buffer.concat([cipherText, cipher.final()]);

    // Obtener el tag de autenticación
    const authTag = cipher.getAuthTag();

    // Retornar todo en Base64
    return {
      cipherTextBase64: cipherText.toString('base64'),
      keyBase64: key.toString('base64'),
      nonceBase64: nonce.toString('base64'),
      authTagBase64: authTag.toString('base64')
    };
  } catch (error) {
    throw new Error(`Error al cifrar: ${error.message}`);
  }
}

/**
 * Descifra un texto cifrado usando ChaCha20-Poly1305
 * @param {string} cipherTextBase64 - Texto cifrado en Base64
 * @param {string} keyBase64 - Clave en Base64 (32 bytes)
 * @param {string} nonceBase64 - Nonce en Base64 (12 bytes)
 * @param {string} authTagBase64 - Tag de autenticación en Base64 (16 bytes)
 * @returns {Object} Objeto con plainText en UTF-8
 */
function decryptChaCha20(cipherTextBase64, keyBase64, nonceBase64, authTagBase64) {
  try {
    // Convertir todos los parámetros de Base64 a Buffer
    const cipherText = Buffer.from(cipherTextBase64, 'base64');
    const key = Buffer.from(keyBase64, 'base64');
    const nonce = Buffer.from(nonceBase64, 'base64');
    const authTag = Buffer.from(authTagBase64, 'base64');

    // Validar longitud de la clave
    if (key.length !== 32) {
      throw new Error('La clave debe tener exactamente 32 bytes');
    }

    // Validar longitud del nonce
    if (nonce.length !== 12) {
      throw new Error('El nonce debe tener exactamente 12 bytes');
    }

    // Crear el decipher con ChaCha20-Poly1305
    const decipher = crypto.createDecipheriv('chacha20-poly1305', key, nonce, {
      authTagLength: 16
    });

    // Establecer el tag de autenticación
    decipher.setAuthTag(authTag);

    // Descifrar el texto
    let plainText = decipher.update(cipherText);
    plainText = Buffer.concat([plainText, decipher.final()]);

    // Retornar el texto plano en UTF-8
    return {
      plainText: plainText.toString('utf8')
    };
  } catch (error) {
    throw new Error(`Error al descifrar: ${error.message}`);
  }
}

// Exportar las funciones
module.exports = {
  encryptChaCha20,
  decryptChaCha20
};