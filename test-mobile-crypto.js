/**
 * test-mobile-crypto.js
 * 
 * Verificación matemática del motor cliente (mobile-app/src/utils/totpEngine.ts)
 * Compara los resultados de sha1, hmacSha1, base32ToBytes y generateTOTP
 * contra la implementación nativa del backend y los estándares RFC 3174, RFC 2104, RFC 6238.
 */

const crypto = require('crypto');

// 1. Algoritmo Base32 RFC 4648
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function base32ToBytes(base32Str) {
  const cleanStr = base32Str.toUpperCase().replace(/[\s\-=]/g, '');
  let bits = 0;
  let value = 0;
  const bytes = [];
  for (let i = 0; i < cleanStr.length; i++) {
    const char = cleanStr[i];
    const index = BASE32_ALPHABET.indexOf(char);
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(bytes);
}

// 2. SHA-1 Puro RFC 3174 (El mismo código de mobile-app/src/utils/totpEngine.ts)
function rotl32(value, count) {
  return ((value << count) | (value >>> (32 - count))) >>> 0;
}

function clientSha1(message) {
  const msgLen = message.length;
  const bitLenBigInt = BigInt(msgLen) * 8n;
  let paddedLen = msgLen + 1;
  while ((paddedLen % 64) !== 56) paddedLen++;
  paddedLen += 8;

  const padded = new Uint8Array(paddedLen);
  padded.set(message, 0);
  padded[msgLen] = 0x80;

  const view = new DataView(padded.buffer);
  view.setBigUint64(paddedLen - 8, bitLenBigInt, false);

  let h0 = 0x67452301;
  let h1 = 0xefcdab89;
  let h2 = 0x98badcfe;
  let h3 = 0x10325476;
  let h4 = 0xc3d2e1f0;

  const w = new Uint32Array(80);

  for (let offset = 0; offset < paddedLen; offset += 64) {
    for (let t = 0; t < 16; t++) {
      w[t] =
        (padded[offset + t * 4] << 24) |
        (padded[offset + t * 4 + 1] << 16) |
        (padded[offset + t * 4 + 2] << 8) |
        padded[offset + t * 4 + 3];
    }

    for (let t = 16; t < 80; t++) {
      w[t] = rotl32(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1);
    }

    let a = h0, b = h1, c = h2, d = h3, e = h4;

    for (let t = 0; t < 80; t++) {
      let f, k;
      if (t < 20) {
        f = (b & c) | (~b & d);
        k = 0x5a827999;
      } else if (t < 40) {
        f = b ^ c ^ d;
        k = 0x6ed9eba1;
      } else if (t < 60) {
        f = (b & c) | (b & d) | (c & d);
        k = 0x8f1bbcdc;
      } else {
        f = b ^ c ^ d;
        k = 0xca62c1d6;
      }
      const temp = (rotl32(a, 5) + f + e + k + w[t]) >>> 0;
      e = d;
      d = c;
      c = rotl32(b, 30);
      b = a;
      a = temp;
    }

    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
  }

  const result = new Uint8Array(20);
  const outView = new DataView(result.buffer);
  outView.setUint32(0, h0, false);
  outView.setUint32(4, h1, false);
  outView.setUint32(8, h2, false);
  outView.setUint32(12, h3, false);
  outView.setUint32(16, h4, false);
  return result;
}

// 3. HMAC-SHA1 RFC 2104
function clientHmacSha1(key, message) {
  const BLOCK_SIZE = 64;
  let kPrime;
  if (key.length > BLOCK_SIZE) {
    kPrime = clientSha1(key);
  } else {
    kPrime = new Uint8Array(BLOCK_SIZE);
    kPrime.set(key, 0);
  }

  const ipad = new Uint8Array(BLOCK_SIZE);
  const opad = new Uint8Array(BLOCK_SIZE);
  for (let i = 0; i < BLOCK_SIZE; i++) {
    ipad[i] = kPrime[i] ^ 0x36;
    opad[i] = kPrime[i] ^ 0x5c;
  }

  const innerMsg = new Uint8Array(BLOCK_SIZE + message.length);
  innerMsg.set(ipad, 0);
  innerMsg.set(message, BLOCK_SIZE);
  const innerHash = clientSha1(innerMsg);

  const outerMsg = new Uint8Array(BLOCK_SIZE + innerHash.length);
  outerMsg.set(opad, 0);
  outerMsg.set(innerHash, BLOCK_SIZE);
  return clientSha1(outerMsg);
}

// 4. HOTP / TOTP Dynamic Truncation
function clientGenerateHOTP(secretBytes, counter, digits = 6) {
  const counterBuffer = new Uint8Array(8);
  const view = new DataView(counterBuffer.buffer);
  view.setBigUint64(0, BigInt(counter), false);

  const hmac = clientHmacSha1(secretBytes, counterBuffer);
  const offset = hmac[19] & 0x0f;
  const binCode =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  const otp = binCode % Math.pow(10, digits);
  return otp.toString().padStart(digits, '0');
}

function clientGenerateTOTP(secret, timestampSeconds = Math.floor(Date.now() / 1000)) {
  const bytes = base32ToBytes(secret);
  const counter = Math.floor(timestampSeconds / 30);
  return clientGenerateHOTP(bytes, counter, 6);
}

// Ejecutar pruebas cruzadas
console.log('=== VERIFICACIÓN MOTOR TOTP CLIENTE (TypeScript/JavaScript Puro) ===\n');

// A. Test SHA-1 vs Node crypto
const testData = Buffer.from('Seguridad Móvil Unisabana 2026');
const hashNode = crypto.createHash('sha1').update(testData).digest('hex');
const hashClient = Buffer.from(clientSha1(new Uint8Array(testData))).toString('hex');

console.log(`SHA-1 Node:   ${hashNode}`);
console.log(`SHA-1 Client: ${hashClient}`);
if (hashNode === hashClient) {
  console.log('✓ SHA-1 Puro coincide exactamente con OpenSSL/Node.');
} else {
  console.error('✗ Fallo en SHA-1');
  process.exit(1);
}

// B. Test HMAC-SHA1 vs Node crypto
const key = Buffer.from('ClaveSecretaLaboratorio');
const hmacNode = crypto.createHmac('sha1', key).update(testData).digest('hex');
const hmacClient = Buffer.from(clientHmacSha1(new Uint8Array(key), new Uint8Array(testData))).toString('hex');

console.log(`\nHMAC-SHA1 Node:   ${hmacNode}`);
console.log(`HMAC-SHA1 Client: ${hmacClient}`);
if (hmacNode === hmacClient) {
  console.log('✓ HMAC-SHA1 RFC 2104 Puro coincide exactamente con OpenSSL/Node.');
} else {
  console.error('✗ Fallo en HMAC-SHA1');
  process.exit(1);
}

// C. Test TOTP cruzado en 10 intervalos temporales diferentes
console.log('\nComprobando coherencia TOTP en 10 ventanas temporales distintas...');
const secretBase32 = 'JBSWY3DPEHPK3PXP';
const { generateTOTP: backendGenerateTOTP } = require('./backend-auth/totpEngine');

let allMatch = true;
const baseTime = 1700000000;
for (let i = 0; i < 10; i++) {
  const t = baseTime + (i * 30);
  const clientCode = clientGenerateTOTP(secretBase32, t);
  const backendCode = backendGenerateTOTP(secretBase32, t);
  if (clientCode !== backendCode) {
    console.error(`✗ Discrepancia en t=${t}: Client=${clientCode}, Backend=${backendCode}`);
    allMatch = false;
  }
}

if (allMatch) {
  console.log('✓ 10/10 códigos TOTP idénticos entre Cliente Móvil y Backend.');
} else {
  process.exit(1);
}

console.log('\n====================================================');
console.log(' VALIDACIÓN DEL MOTOR MÓVIL EXITOSA');
console.log('====================================================');

