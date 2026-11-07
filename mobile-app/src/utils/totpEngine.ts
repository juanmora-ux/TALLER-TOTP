/**
 * totpEngine.ts
 * 
 * Motor Criptográfico TOTP RFC 6238 y HOTP RFC 4226 para React Native / Expo.
 * REGLA INVIOLABLE: Cero dependencias de alto nivel (ni otplib, ni speakeasy).
 * 
 * Implementación Matemática Paso a Paso:
 * 1. Decodificación Base32 (RFC 4648) a bytes binarios.
 * 2. Cálculo del contador de tiempo T = floor(UnixTimestamp / 30s) como 8 bytes Big-Endian.
 * 3. HMAC-SHA1(Key, T) según especificación RFC 2104.
 * 4. Truncamiento Dinámico (Dynamic Truncation - RFC 4226 sección 5.4).
 * 5. Reducción módulo 10^6 con relleno de ceros a la izquierda (6 dígitos).
 * 
 * Garantiza funcionamiento 100% Offline (Modo Avión).
 */

import { base32ToBytes } from './base32';

// ==========================================
// 1. Implementación Criptográfica de SHA-1 (RFC 3174)
// ==========================================

/**
 * Rotación circular a la izquierda de 32 bits
 */
function rotl32(value: number, count: number): number {
  return ((value << count) | (value >>> (32 - count))) >>> 0;
}

/**
 * Calcula el digest SHA-1 de un Uint8Array según RFC 3174
 * @param message Datos de entrada
 * @returns Uint8Array de 20 bytes con el hash SHA-1
 */
export function sha1(message: Uint8Array): Uint8Array {
  const msgLen = message.length;
  // Longitud en bits representada en 64 bits (Big-Endian)
  const bitLenBigInt = BigInt(msgLen) * 8n;

  // Paso de Padding: añadir bit 1 (0x80) y ceros hasta longitud congruente con 56 mod 64
  let paddedLen = msgLen + 1;
  while ((paddedLen % 64) !== 56) {
    paddedLen++;
  }
  // Añadir 8 bytes de longitud final
  paddedLen += 8;

  const padded = new Uint8Array(paddedLen);
  padded.set(message, 0);
  padded[msgLen] = 0x80;

  // Escribir longitud en bits en los últimos 8 bytes (Big Endian)
  const view = new DataView(padded.buffer);
  view.setBigUint64(paddedLen - 8, bitLenBigInt, false);

  // Inicializar variables de estado SHA-1
  let h0 = 0x67452301;
  let h1 = 0xefcdab89;
  let h2 = 0x98badcfe;
  let h3 = 0x10325476;
  let h4 = 0xc3d2e1f0;

  const w = new Uint32Array(80);

  // Procesar en bloques de 64 bytes (512 bits)
  for (let offset = 0; offset < paddedLen; offset += 64) {
    // Cargar primeras 16 palabras de 32 bits
    for (let t = 0; t < 16; t++) {
      w[t] =
        (padded[offset + t * 4] << 24) |
        (padded[offset + t * 4 + 1] << 16) |
        (padded[offset + t * 4 + 2] << 8) |
        padded[offset + t * 4 + 3];
    }

    // Extender a 80 palabras
    for (let t = 16; t < 80; t++) {
      w[t] = rotl32(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1);
    }

    let a = h0;
    let b = h1;
    let c = h2;
    let d = h3;
    let e = h4;

    // 80 rondas divididas en 4 bloques funcionales
    for (let t = 0; t < 80; t++) {
      let f: number;
      let k: number;

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

  // Empaquetar el digest resultante de 20 bytes
  const result = new Uint8Array(20);
  const outView = new DataView(result.buffer);
  outView.setUint32(0, h0, false);
  outView.setUint32(4, h1, false);
  outView.setUint32(8, h2, false);
  outView.setUint32(12, h3, false);
  outView.setUint32(16, h4, false);

  return result;
}

// ==========================================
// 2. Implementación HMAC-SHA1 (RFC 2104)
// ==========================================

/**
 * Calcula HMAC-SHA1 a nivel binario según RFC 2104
 * HMAC(K, M) = H((K' ^ opad) || H((K' ^ ipad) || M))
 * @param key Clave secreta (bytes)
 * @param message Mensaje (bytes)
 * @returns Uint8Array de 20 bytes con el resultado del HMAC
 */
export function hmacSha1(key: Uint8Array, message: Uint8Array): Uint8Array {
  const BLOCK_SIZE = 64; // Block size de SHA-1 en bytes
  let kPrime: Uint8Array;

  if (key.length > BLOCK_SIZE) {
    kPrime = sha1(key);
  } else {
    kPrime = new Uint8Array(BLOCK_SIZE);
    kPrime.set(key, 0);
    // El resto queda en ceros
  }

  // Preparar ipad (0x36) y opad (0x5c)
  const ipad = new Uint8Array(BLOCK_SIZE);
  const opad = new Uint8Array(BLOCK_SIZE);

  for (let i = 0; i < BLOCK_SIZE; i++) {
    ipad[i] = kPrime[i] ^ 0x36;
    opad[i] = kPrime[i] ^ 0x5c;
  }

  // Inner Hash: H((K' ^ ipad) || message)
  const innerMsg = new Uint8Array(BLOCK_SIZE + message.length);
  innerMsg.set(ipad, 0);
  innerMsg.set(message, BLOCK_SIZE);
  const innerHash = sha1(innerMsg);

  // Outer Hash: H((K' ^ opad) || innerHash)
  const outerMsg = new Uint8Array(BLOCK_SIZE + innerHash.length);
  outerMsg.set(opad, 0);
  outerMsg.set(innerHash, BLOCK_SIZE);
  return sha1(outerMsg);
}

// ==========================================
// 3. HOTP (RFC 4226) & Dynamic Truncation
// ==========================================

/**
 * Calcula HOTP para un contador de 64 bits (RFC 4226)
 * @param secretBytes Semilla decodificada
 * @param counter Contador entero
 * @param digits Cantidad de dígitos requeridos (por defecto 6)
 * @returns Código OTP en formato string con relleno de ceros
 */
export function generateHOTP(secretBytes: Uint8Array, counter: number | bigint, digits: number = 6): string {
  // 1. Formatear contador en 8 bytes Big-Endian
  const counterBuffer = new Uint8Array(8);
  const view = new DataView(counterBuffer.buffer);
  view.setBigUint64(0, BigInt(counter), false);

  // 2. Ejecutar HMAC-SHA1
  const hmac = hmacSha1(secretBytes, counterBuffer);

  // 3. Dynamic Truncation (RFC 4226 sección 5.4)
  // Tomar los 4 bits menos significativos del último byte (índice 19)
  const offset = hmac[19] & 0x0f;

  // Extraer 4 bytes contiguos a partir del offset ignorando el bit más significativo (0x7f)
  const binCode =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  // 4. Módulo 10^digits
  const otp = binCode % Math.pow(10, digits);

  return otp.toString().padStart(digits, '0');
}

// ==========================================
// 4. TOTP (RFC 6238)
// ==========================================

/**
 * Calcula el código TOTP a partir de la semilla Base32 y el tiempo Unix (RFC 6238)
 * T = floor((CurrentTime - T0) / X), donde T0 = 0 y X = 30 segundos
 * @param base32Secret Semilla en formato Base32
 * @param timestampSeconds Tiempo Unix en segundos (Date.now() / 1000 por defecto)
 * @param timeStep Ventana de rotación en segundos (30 por defecto)
 * @param digits Cantidad de dígitos (6 por defecto)
 * @returns Código TOTP de 6 dígitos
 */
export function generateTOTP(
  base32Secret: string,
  timestampSeconds: number = Math.floor(Date.now() / 1000),
  timeStep: number = 30,
  digits: number = 6
): string {
  const secretBytes = base32ToBytes(base32Secret);
  const timeStepCount = Math.floor(timestampSeconds / timeStep);
  return generateHOTP(secretBytes, timeStepCount, digits);
}

/**
 * Retorna los segundos restantes en el ciclo actual de 30 segundos
 */
export function getRemainingSeconds(timeStep: number = 30): number {
  const now = Math.floor(Date.now() / 1000);
  return timeStep - (now % timeStep);
}

// ==========================================
// 5. Parser de URI otpauth://
// ==========================================

export interface ParsedOtpAuthUri {
  type: 'totp' | 'hotp';
  issuer: string;
  account: string;
  secret: string;
  digits: number;
  period: number;
  algorithm: string;
}

/**
 * Parsea una URI estándar otpauth://totp/... proveniente de un código QR
 */
export function parseOtpAuthUri(uri: string): ParsedOtpAuthUri {
  if (!uri.startsWith('otpauth://')) {
    throw new Error('La URI no tiene el protocolo otpauth://');
  }

  const url = new URL(uri);
  const type = url.host as 'totp' | 'hotp';
  if (type !== 'totp') {
    throw new Error(`Tipo de OTP '${type}' no soportado (se requiere 'totp')`);
  }

  // El pathname contiene el label "[Issuer:]Account"
  let label = decodeURIComponent(url.pathname.replace(/^\//, ''));
  let issuer = '';
  let account = label;

  if (label.includes(':')) {
    const parts = label.split(':');
    issuer = parts[0].trim();
    account = parts[1].trim();
  }

  const searchParams = url.searchParams;
  const secret = searchParams.get('secret');
  if (!secret) {
    throw new Error('La URI otpauth:// no incluye el parámetro obligatorio "secret"');
  }

  const issuerParam = searchParams.get('issuer');
  if (issuerParam) {
    issuer = issuerParam;
  }

  const digits = parseInt(searchParams.get('digits') || '6', 10);
  const period = parseInt(searchParams.get('period') || '30', 10);
  const algorithm = (searchParams.get('algorithm') || 'SHA1').toUpperCase();

  return {
    type,
    issuer: issuer || 'Unisabana',
    account: account || 'Usuario',
    secret,
    digits,
    period,
    algorithm
  };
}

