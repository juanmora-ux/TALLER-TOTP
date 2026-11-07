/**
 * secureStorage.ts
 * 
 * Abstracción de Almacenamiento Criptográfico Seguro
 * Utiliza iOS Keychain y Android Keystore mediante expo-secure-store.
 * 
 * POLÍTICA DE SEGURIDAD CRÍTICA:
 * - El 'access_token' NUNCA se almacena aquí (permanece única y exclusivamente en memoria RAM).
 * - Aquí se almacenan únicamente secretos de larga duración:
 *   1. 'refresh_token' (TTL largo 30 días, cifrado en hardware enclave).
 *   2. Semilla Base32 de la cuenta TOTP local.
 */

import * as SecureStore from 'expo-secure-store';
import { Platform } from 'react-native';

const STORAGE_KEYS = {
  REFRESH_TOKEN: 'unisabana_auth_refresh_token',
  TOTP_SECRET: 'unisabana_totp_secret_key',
  TOTP_ACCOUNT_INFO: 'unisabana_totp_account_metadata',
} as const;

// Fallback en memoria si la plataforma no soporta hardware keychain (ej. entorno web de testing)
const memoryFallback = new Map<string, string>();

/**
 * Guarda un valor en el Enclave Seguro (Keychain / Keystore)
 */
export async function saveSecureItem(key: string, value: string): Promise<void> {
  try {
    if (Platform.OS === 'web') {
      memoryFallback.set(key, value);
      return;
    }

    await SecureStore.setItemAsync(key, value, {
      keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
    });
  } catch (error) {
    console.error(`[SecureStorage] Error al guardar clave '${key}':`, error);
    memoryFallback.set(key, value);
  }
}

/**
 * Recupera un valor descifrado desde el Enclave Seguro
 */
export async function getSecureItem(key: string): Promise<string | null> {
  try {
    if (Platform.OS === 'web') {
      return memoryFallback.get(key) || null;
    }

    const value = await SecureStore.getItemAsync(key);
    return value;
  } catch (error) {
    console.error(`[SecureStorage] Error al leer clave '${key}':`, error);
    return memoryFallback.get(key) || null;
  }
}

/**
 * Elimina de forma segura un valor del Enclave Seguro
 */
export async function deleteSecureItem(key: string): Promise<void> {
  try {
    if (Platform.OS === 'web') {
      memoryFallback.delete(key);
      return;
    }

    await SecureStore.deleteItemAsync(key);
  } catch (error) {
    console.error(`[SecureStorage] Error al eliminar clave '${key}':`, error);
    memoryFallback.delete(key);
  }
}

// ==========================================
// Métodos de Dominio de Seguridad
// ==========================================

export async function saveRefreshToken(token: string): Promise<void> {
  await saveSecureItem(STORAGE_KEYS.REFRESH_TOKEN, token);
}

export async function getRefreshToken(): Promise<string | null> {
  return await getSecureItem(STORAGE_KEYS.REFRESH_TOKEN);
}

export async function removeRefreshToken(): Promise<void> {
  await deleteSecureItem(STORAGE_KEYS.REFRESH_TOKEN);
}

export async function saveTOTPSecret(secret: string): Promise<void> {
  await saveSecureItem(STORAGE_KEYS.TOTP_SECRET, secret);
}

export async function getTOTPSecret(): Promise<string | null> {
  return await getSecureItem(STORAGE_KEYS.TOTP_SECRET);
}

export async function removeTOTPSecret(): Promise<void> {
  await deleteSecureItem(STORAGE_KEYS.TOTP_SECRET);
}

export async function saveTOTPMetadata(metadata: object): Promise<void> {
  await saveSecureItem(STORAGE_KEYS.TOTP_ACCOUNT_INFO, JSON.stringify(metadata));
}

export async function getTOTPMetadata<T = any>(): Promise<T | null> {
  const json = await getSecureItem(STORAGE_KEYS.TOTP_ACCOUNT_INFO);
  if (!json) return null;
  try {
    return JSON.parse(json) as T;
  } catch {
    return null;
  }
}

/**
 * Destruye todas las credenciales persistentes al cerrar sesión
 */
export async function clearAllSecureCredentials(): Promise<void> {
  await removeRefreshToken();
  // Nota: La semilla TOTP puede conservarse o borrarse según la política
  // En este laboratorio dejamos la opción de reset completo
}

