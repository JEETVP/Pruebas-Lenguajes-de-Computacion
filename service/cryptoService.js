const crypto = require('crypto');

/**
 * Cifra un texto plano usando ChaCha20-Poly1305
 * @param {string} plainText - Texto a cifrar en formato UTF-8
 * @param {string|null} keyBase64 - Clave en Base64 (32 bytes). Si es null, se genera automáticamente
 * @param {string|null} nonceBase64 - Nonce en Base64 (12 bytes). Si es null, se genera automáticamente
 * @returns {Object} Objeto con cipherTextBase64, keyBase64, nonceBase64 y authTagBase64
 */

const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048, // Tamaño de la llave: 2048 bits
  publicKeyEncoding: {
    type: 'spki',     // SubjectPublicKeyInfo (estándar X.509)
    format: 'pem'     // Formato PEM (texto ASCII armored)
  },
  privateKeyEncoding: {
    type: 'pkcs8',    // PKCS#8 (estándar para llaves privadas)
    format: 'pem'     // Formato PEM
  }
});

console.log('✓ Par de llaves RSA generadas (2048 bits)');

const { publicKey: dsaPublicKey, privateKey: dsaPrivateKey } = 
  crypto.generateKeyPairSync('dsa', {
    modulusLength: 1024,  // Tamaño de la llave: 1024 bits
    divisorLength: 224,   // Tamaño del subgrupo primo (recomendado para DSA-1024)
    publicKeyEncoding: {
      type: 'spki',       // SubjectPublicKeyInfo (estándar X.509)
      format: 'pem'       // Formato PEM (texto ASCII armored)
    },
    privateKeyEncoding: {
      type: 'pkcs8',      // PKCS#8 (estándar para llaves privadas)
      format: 'pem'       // Formato PEM
    }
  });

console.log('✓ Par de llaves DSA generadas (1024 bits, divisor 224 bits)');

function getDsaPublicKeyPem() {
  return dsaPublicKey;
}

/**
 * Firma un mensaje usando DSA con SHA-256
 * 
 * @param {string} message - Mensaje a firmar (UTF-8)
 * @returns {object} Objeto con signatureBase64, algorithm, keySize y publicKeyPem
 * @throws {Error} Si el mensaje es inválido o la firma falla
 */
function signWithDsa(message) {
  if (!message || typeof message !== 'string') {
    throw new Error('El mensaje a firmar debe ser un string no vacío');
  }

  // Crear objeto Sign con algoritmo SHA-256
  const sign = crypto.createSign('sha256');
  
  // Actualizar el objeto Sign con el mensaje a firmar
  sign.update(message, 'utf8');
  
  // Finalizar el proceso de actualización
  sign.end();

  // Firmar el mensaje usando la llave privada DSA
  // La firma resultante es un Buffer binario
  const signature = sign.sign(dsaPrivateKey);

  // Convertir la firma a Base64 para transmisión/almacenamiento
  const signatureBase64 = signature.toString('base64');

  return {
    algorithm: 'DSA-SHA256',
    keySize: 1024,
    signatureBase64,
    publicKeyPem: dsaPublicKey // Opcional: para mostrar en la respuesta
  };
}

/**
 * Verifica una firma DSA de un mensaje
 * 
 * @param {string} message - Mensaje original (UTF-8)
 * @param {string} signatureBase64 - Firma en formato Base64
 * @returns {object} Objeto con isValid (boolean), algorithm y keySize
 * @throws {Error} Si los parámetros son inválidos o la verificación falla
 */
function verifyWithDsa(message, signatureBase64) {
  if (!message || typeof message !== 'string') {
    throw new Error('El mensaje debe ser un string no vacío');
  }

  if (!signatureBase64 || typeof signatureBase64 !== 'string') {
    throw new Error('La firma debe ser un string Base64 no vacío');
  }

  // Convertir la firma de Base64 a Buffer
  const signatureBuffer = Buffer.from(signatureBase64, 'base64');

  // Crear objeto Verify con algoritmo SHA-256
  const verify = crypto.createVerify('sha256');
  
  // Actualizar el objeto Verify con el mensaje original
  verify.update(message, 'utf8');
  
  // Finalizar el proceso de actualización
  verify.end();

  // Verificar la firma usando la llave pública DSA
  // Retorna true si la firma es válida, false en caso contrario
  const isValid = verify.verify(dsaPublicKey, signatureBuffer);

  return {
    algorithm: 'DSA-SHA256',
    keySize: 1024,
    isValid
  };
}

/**
 * Obtiene la llave pública en formato PEM
 * @returns {string} Llave pública PEM
 */
function getPublicKeyPem() {
  return publicKey;
}

/**
 * Cifra un texto plano usando RSA-OAEP con SHA-256
 * 
 * @param {string} plainText - Texto plano a cifrar (UTF-8)
 * @returns {object} Objeto con cipherTextBase64 y publicKeyPem
 * @throws {Error} Si el texto es demasiado grande para RSA-2048
 */
function rsaEncrypt(plainText) {
  if (!plainText || typeof plainText !== 'string') {
    throw new Error('El texto a cifrar debe ser un string no vacío');
  }

  // Convertir el texto plano a Buffer (UTF-8)
  const plainBuffer = Buffer.from(plainText, 'utf8');

  // Cifrar usando la llave pública con RSA-OAEP + SHA-256
  // RSA-2048 puede cifrar hasta ~190 bytes con OAEP-SHA256
  const cipherBuffer = crypto.publicEncrypt(
    {
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256' // Función hash para OAEP
    },
    plainBuffer
  );

  // Convertir el texto cifrado a Base64 para transmisión
  const cipherTextBase64 = cipherBuffer.toString('base64');

  return {
    cipherTextBase64,
    publicKeyPem: publicKey // Opcional: para mostrar en la respuesta
  };
}

/**
 * Descifra un texto cifrado usando RSA-OAEP con SHA-256
 * 
 * @param {string} cipherTextBase64 - Texto cifrado en Base64
 * @returns {object} Objeto con plainText descifrado
 * @throws {Error} Si el texto cifrado es inválido o está corrupto
 */
function rsaDecrypt(cipherTextBase64) {
  if (!cipherTextBase64 || typeof cipherTextBase64 !== 'string') {
    throw new Error('El texto cifrado debe ser un string Base64 no vacío');
  }

  // Convertir de Base64 a Buffer
  const cipherBuffer = Buffer.from(cipherTextBase64, 'base64');

  // Descifrar usando la llave privada con RSA-OAEP + SHA-256
  const plainBuffer = crypto.privateDecrypt(
    {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256' // Debe coincidir con el usado en el cifrado
    },
    cipherBuffer
  );

  // Convertir el Buffer descifrado a string UTF-8
  const plainText = plainBuffer.toString('utf8');

  return {
    plainText
  };
}

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
  decryptChaCha20,
  getPublicKeyPem,
  rsaEncrypt,
  rsaDecrypt,
  getDsaPublicKeyPem,
  signWithDsa,
  verifyWithDsa
};