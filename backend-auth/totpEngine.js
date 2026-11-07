/**
 * totpEngine.js (Backend)
 * 
 * Implementación matemática pura de TOTP según RFC 6238 y RFC 4226 (HOTP).
 * REGLA INVIOLABLE: Cero librerías de alto nivel (ni otplib, ni speakeasy).
 * Utiliza únicamente el módulo 'crypto' nativo de Node.js para HMAC-SHA1.
 */

const crypto = require('crypto');

/**
 * Tabla de decodificación Base32 (RFC 4648)
 */
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * Decodifica una cadena Base32 a Buffer binario sin librerías externas
 * @param {string} base32String 
 * @returns {Buffer}
 */
function base32ToBuffer(base32String) {
  // Limpiar espacios, guiones y padding '='
  const cleanStr = base32String.toUpperCase().replace(/[\s\-=]/g, '');
  let bits = 0;
  let value = 0;
  const bytes = [];

  for (let i = 0; i < cleanStr.length; i++) {
    const char = cleanStr[i];
    const index = BASE32_ALPHABET.indexOf(char);
    if (index === -1) {
      throw new Error(`Carácter Base32 no válido detectado: '${char}'`);
    }

    // Cada carácter Base32 aporta 5 bits
    value = (value << 5) | index;
    bits += 5;

    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }

  return Buffer.from(bytes);
}

/**
 * Calcula un código HOTP (RFC 4226) dado un secreto y un contador entero de 64 bits
 * @param {Buffer} keyBuffer 
 * @param {bigint|number} counter 
 * @param {number} digits 
 * @returns {string} Código numérico con relleno de ceros a la izquierda
 */
function generateHOTP(keyBuffer, counter, digits = 6) {
  // Paso 1: Formatear el contador en un Buffer de 8 bytes Big-Endian
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(BigInt(counter), 0);

  // Paso 2: Calcular HMAC-SHA1
  const hmac = crypto.createHmac('sha1', keyBuffer).update(counterBuffer).digest();

  // Paso 3: Truncamiento Dinámico (RFC 4226 Sección 5.4)
  // Tomar los 4 bits menos significativos del último byte para obtener el offset (0..15)
  const offset = hmac[hmac.length - 1] & 0x0f;

  // Extraer 4 bytes a partir del offset, ignorando el bit más significativo (0x7f)
  const binaryCode =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  // Paso 4: Reducir módulo 10^digits
  const otpNumber = binaryCode % Math.pow(10, digits);
  return otpNumber.toString().padStart(digits, '0');
}

/**
 * Genera el código TOTP para un instante de tiempo dado (RFC 6238)
 * @param {string|Buffer} secret - Semilla en Base32 o Buffer
 * @param {number} [timestampSeconds] - Tiempo Unix en segundos (Date.now() / 1000 por defecto)
 * @param {number} [timeStep=30] - Ventana de rotación en segundos
 * @param {number} [digits=6] - Cantidad de dígitos del código
 * @returns {string} Código TOTP de 6 dígitos
 */
function generateTOTP(secret, timestampSeconds = Math.floor(Date.now() / 1000), timeStep = 30, digits = 6) {
  const keyBuffer = Buffer.isBuffer(secret) ? secret : base32ToBuffer(secret);
  const timeStepCount = Math.floor(timestampSeconds / timeStep);
  return generateHOTP(keyBuffer, timeStepCount, digits);
}

/**
 * Valida un código TOTP evaluando las 3 ventanas temporales C-1, C, C+1 (RFC 6238)
 * @param {string} tokenCode - Código de 6 dígitos ingresado por el usuario
 * @param {string} base32Secret - Semilla Base32 del usuario
 * @param {number} [windowSteps=1] - Tolerancia de desfase horario (1 = -30s a +30s)
 * @returns {{ valid: boolean, matchedStep?: number }}
 */
function verifyTOTP(tokenCode, base32Secret, windowSteps = 1) {
  if (!tokenCode || tokenCode.trim().length !== 6) {
    return { valid: false };
  }

  const cleanToken = tokenCode.trim();
  const keyBuffer = base32ToBuffer(base32Secret);
  const currentTimestamp = Math.floor(Date.now() / 1000);
  const currentStep = Math.floor(currentTimestamp / 30);

  // Iterar por las ventanas temporales: [C - 1, C, C + 1]
  for (let offset = -windowSteps; offset <= windowSteps; offset++) {
    const stepToTest = currentStep + offset;
    const expectedOtp = generateHOTP(keyBuffer, stepToTest, 6);

    // Comparación segura en tiempo constante para evitar Timing Attacks
    const tokenBuffer = Buffer.from(cleanToken);
    const expectedBuffer = Buffer.from(expectedOtp);

    if (tokenBuffer.length === expectedBuffer.length && crypto.timingSafeEqual(tokenBuffer, expectedBuffer)) {
      return { valid: true, matchedStep: stepToTest };
    }
  }

  return { valid: false };
}

module.exports = {
  base32ToBuffer,
  generateHOTP,
  generateTOTP,
  verifyTOTP
};

