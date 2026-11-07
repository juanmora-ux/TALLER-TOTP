/**
 * base32.ts
 * 
 * Implementación pura del Decodificador y Codificador Base32 según RFC 4648.
 * REGLA INVIOLABLE: Cero librerías de terceros (ni otplib, ni speakeasy, ni hi-base32).
 */

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * Valida si una cadena cumple con el formato Base32
 */
export function isValidBase32(str: string): boolean {
  if (!str || typeof str !== 'string') return false;
  const clean = str.toUpperCase().replace(/[\s\-=]/g, '');
  if (clean.length === 0) return false;
  return /^[A-Z2-7]+$/.test(clean);
}

/**
 * Decodifica una semilla Base32 a un Uint8Array (bytes) según RFC 4648
 * @param base32Str Cadena Base32 (ej: "JBSWY3DPEHPK3PXP")
 * @returns Uint8Array de bytes decodificados
 */
export function base32ToBytes(base32Str: string): Uint8Array {
  if (!base32Str || typeof base32Str !== 'string') {
    throw new Error('La semilla Base32 no puede estar vacía');
  }

  // Sanitizar: mayúsculas, remover espacios, guiones y padding '='
  const cleanStr = base32Str.toUpperCase().replace(/[\s\-=]/g, '');

  if (cleanStr.length === 0) {
    throw new Error('La semilla Base32 sanitizada está vacía');
  }

  let bits = 0;
  let value = 0;
  const bytes: number[] = [];

  for (let i = 0; i < cleanStr.length; i++) {
    const char = cleanStr[i];
    const index = BASE32_ALPHABET.indexOf(char);

    if (index === -1) {
      throw new Error(`Carácter Base32 inválido: '${char}' en posición ${i}`);
    }

    // Cada carácter aporta 5 bits significativos
    value = (value << 5) | index;
    bits += 5;

    // Al acumular al menos 8 bits, extraer el byte superior
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }

  return new Uint8Array(bytes);
}

/**
 * Codifica un Uint8Array de bytes a cadena Base32 (RFC 4648)
 * @param bytes Uint8Array
 * @returns Cadena Base32 sin padding
 */
export function bytesToBase32(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let output = '';

  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i];
    bits += 8;

    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }

  return output;
}

