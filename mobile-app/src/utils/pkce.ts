/**
 * pkce.ts
 * 
 * Generador Criptográfico de Parámetros PKCE (RFC 7636) y Anti-CSRF State
 * para Flujo Authorization Code con Proof Key for Code Exchange.
 */

import * as Crypto from 'expo-crypto';
import { PKCECodes } from '../types/auth';

/**
 * Caracteres permitidos por el RFC 7636 para el code_verifier:
 * [A-Z], [a-z], [0-9], "-", ".", "_", "~"
 */
const PKCE_CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';

/**
 * Convierte una cadena Base64 estándar a Base64URL sin padding (RFC 7636 sección 4.2)
 * Reemplaza '+' por '-', '/' por '_' y elimina el padding '='
 */
export function toBase64UrlUnpadded(base64Str: string): string {
  return base64Str
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/**
 * Genera un code_verifier criptográficamente seguro
 * Longitud estándar recomendada: 64 caracteres (entre 43 y 128 caracteres según RFC 7636)
 */
export async function generateCodeVerifier(length: number = 64): Promise<string> {
  if (length < 43 || length > 128) {
    throw new Error('La longitud del code_verifier debe estar comprendida entre 43 y 128 caracteres (RFC 7636)');
  }

  const randomBytes = await Crypto.getRandomBytesAsync(length);
  let verifier = '';
  for (let i = 0; i < length; i++) {
    // Selección uniforme dentro del charset permitido
    const index = randomBytes[i] % PKCE_CHARSET.length;
    verifier += PKCE_CHARSET[index];
  }

  return verifier;
}

/**
 * Genera el code_challenge derivado del code_verifier mediante SHA-256
 * code_challenge = Base64URL_Unpadded(SHA256(code_verifier))
 */
export async function generateCodeChallenge(verifier: string): Promise<string> {
  // Calcular digest SHA-256 en Base64 utilizando el motor nativo de expo-crypto
  const sha256Base64 = await Crypto.digestStringAsync(
    Crypto.CryptoDigestAlgorithm.SHA256,
    verifier,
    { encoding: Crypto.CryptoEncoding.BASE64 }
  );

  return toBase64UrlUnpadded(sha256Base64);
}

/**
 * Genera un valor aleatorio de 'state' anti-CSRF para blindar la transacción OAuth 2.0
 */
export async function generateState(bytesCount: number = 24): Promise<string> {
  const bytes = await Crypto.getRandomBytesAsync(bytesCount);
  let state = '';
  const hex = '0123456789abcdef';
  for (let i = 0; i < bytes.length; i++) {
    state += hex[(bytes[i] >> 4) & 0x0f] + hex[bytes[i] & 0x0f];
  }
  return state;
}

/**
 * Genera el paquete completo de parámetros PKCE listos para iniciar el flujo
 */
export async function createPKCEParams(): Promise<PKCECodes> {
  const codeVerifier = await generateCodeVerifier(64);
  const codeChallenge = await generateCodeChallenge(codeVerifier);
  const state = await generateState(24);

  return {
    codeVerifier,
    codeChallenge,
    state,
    codeChallengeMethod: 'S256'
  };
}

