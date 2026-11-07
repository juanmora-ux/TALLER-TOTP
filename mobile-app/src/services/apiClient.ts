/**
 * apiClient.ts
 * 
 * Cliente HTTP Seguro con Cola de Silent Refresh Concurrente (RFC 6749)
 * 
 * Arquitectura de Seguridad:
 * 1. Acceso a Tokens: Lee el 'access_token' EXCLUSIVAMENTE desde memoria RAM.
 * 2. Detección de Expiración (401 Unauthorized):
 *    - Detiene las peticiones concurrentes y las encola.
 *    - Realiza un único llamado atómico a POST /auth/refresh con el 'refresh_token' de SecureStore.
 *    - Si es exitoso, actualiza el 'access_token' en memoria RAM, vacía la cola y reintenta las peticiones originales.
 *    - Si falla o el refresh token expiró, purga credenciales y notifica el cierre de sesión forzoso.
 */

import { Platform } from 'react-native';
import { getRefreshToken, removeRefreshToken } from './secureStorage';

// URL base del backend: en Android Emulator es 10.0.2.2, en iOS simulator / Web es localhost
// Se permite configurar la IP para dispositivos físicos en la misma red Wi-Fi
export const API_BASE_URL = Platform.select({
  android: 'http://10.0.2.2:4000',
  default: 'http://localhost:4000',
});

// ==========================================
// Estado en Memoria RAM (Cero persistencia de access_token)
// ==========================================
let memoryAccessToken: string | null = null;
let memoryElevatedToken: string | null = null;

// Callbacks para comunicar eventos con el AuthContext
type TokenRefreshedCallback = (newToken: string) => void;
type SessionExpiredCallback = () => void;

let onTokenRefreshed: TokenRefreshedCallback | null = null;
let onSessionExpired: SessionExpiredCallback | null = null;

export function setMemoryTokens(accessToken: string | null, elevatedToken: string | null = null): void {
  memoryAccessToken = accessToken;
  if (elevatedToken !== undefined) {
    memoryElevatedToken = elevatedToken;
  }
}

export function getMemoryAccessToken(): string | null {
  return memoryAccessToken;
}

export function getMemoryElevatedToken(): string | null {
  return memoryElevatedToken;
}

export function registerAuthCallbacks(
  onRefresh: TokenRefreshedCallback,
  onExpire: SessionExpiredCallback
): void {
  onTokenRefreshed = onRefresh;
  onSessionExpired = onExpire;
}

// ==========================================
// Silent Refresh Queue
// ==========================================
interface QueuedRequest {
  resolve: (token: string) => void;
  reject: (error: any) => void;
}

let isRefreshing = false;
let failedQueue: QueuedRequest[] = [];

function processQueue(error: any, token: string | null = null): void {
  failedQueue.forEach((prom) => {
    if (error) {
      prom.reject(error);
    } else if (token) {
      prom.resolve(token);
    }
  });
  failedQueue = [];
}

/**
 * Cliente Fetch Custom con soporte de Interceptores y Silent Refresh Queue
 */
export async function secureFetch<T = any>(
  endpoint: string,
  options: RequestInit = {}
): Promise<{ data: T; status: number; headers: Headers }> {
  const url = endpoint.startsWith('http') ? endpoint : `${API_BASE_URL}${endpoint}`;

  // 1. Inyectar Authorization Header desde Memoria RAM
  const headers = new Headers(options.headers || {});
  if (!headers.has('Content-Type') && !(options.body instanceof FormData)) {
    headers.set('Content-Type', 'application/json');
  }

  // Si tenemos elevated_token (para bóveda) o access_token, adjuntarlo
  const tokenToUse = memoryElevatedToken || memoryAccessToken;
  if (tokenToUse && !headers.has('Authorization')) {
    headers.set('Authorization', `Bearer ${tokenToUse}`);
  }

  const fetchConfig: RequestInit = {
    ...options,
    headers,
  };

  // 2. Ejecutar la petición original
  let response: Response;
  try {
    response = await fetch(url, fetchConfig);
  } catch (netError) {
    console.error(`[API Network Error] Fallo al conectar con ${url}:`, netError);
    throw netError;
  }

  // 3. Interceptar 401 Unauthorized (Expiración de Token)
  // Nota: Si el endpoint ya era /auth/refresh o /auth/oauth/token, no se debe reintentar
  const isAuthEndpoint = endpoint.includes('/auth/refresh') || endpoint.includes('/auth/oauth/token');

  if (response.status === 401 && !isAuthEndpoint) {
    console.warn(`[API Interceptor] 401 Unauthorized recibido en ${endpoint}. Evaluando Silent Refresh...`);

    // Si ya hay un proceso de refresco activo, encolar esta petición
    if (isRefreshing) {
      return new Promise<{ data: T; status: number; headers: Headers }>((resolve, reject) => {
        failedQueue.push({
          resolve: async (newToken: string) => {
            try {
              const retryHeaders = new Headers(options.headers || {});
              retryHeaders.set('Authorization', `Bearer ${newToken}`);
              if (!retryHeaders.has('Content-Type')) retryHeaders.set('Content-Type', 'application/json');

              const retryResponse = await fetch(url, { ...options, headers: retryHeaders });
              const data = await retryResponse.json().catch(() => ({}));
              resolve({ data, status: retryResponse.status, headers: retryResponse.headers });
            } catch (err) {
              reject(err);
            }
          },
          reject: (err: any) => {
            reject(err);
          },
        });
      });
    }

    // Iniciar proceso atómico de Silent Refresh
    isRefreshing = true;

    try {
      const storedRefreshToken = await getRefreshToken();

      if (!storedRefreshToken) {
        throw new Error('No existe refresh_token en el enclave seguro. Sesión expirada.');
      }

      console.log('[Silent Refresh] Solicitando nuevo access_token con refresh_token de SecureStore...');

      const refreshResponse = await fetch(`${API_BASE_URL}/auth/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: storedRefreshToken }),
      });

      if (!refreshResponse.ok) {
        throw new Error(`Fallo en rotación de refresh_token. HTTP Status: ${refreshResponse.status}`);
      }

      const refreshData = await refreshResponse.json();
      const newAccessToken = refreshData.access_token;

      // Actualizar token en memoria RAM
      memoryAccessToken = newAccessToken;
      if (onTokenRefreshed) {
        onTokenRefreshed(newAccessToken);
      }

      console.log('[Silent Refresh] Nuevo access_token obtenido con éxito. Procesando peticiones encoladas...');

      // Procesar la cola de peticiones retenidas
      processQueue(null, newAccessToken);

      // Reintentar la petición actual
      const retryHeaders = new Headers(options.headers || {});
      retryHeaders.set('Authorization', `Bearer ${newAccessToken}`);
      if (!retryHeaders.has('Content-Type')) retryHeaders.set('Content-Type', 'application/json');

      const retryRes = await fetch(url, { ...options, headers: retryHeaders });
      const retryData = await retryRes.json().catch(() => ({}));
      return { data: retryData, status: retryRes.status, headers: retryRes.headers };
    } catch (refreshErr) {
      console.error('[Silent Refresh Error] Error crítico renovando sesión:', refreshErr);
      processQueue(refreshErr, null);
      await removeRefreshToken();
      memoryAccessToken = null;
      memoryElevatedToken = null;

      if (onSessionExpired) {
        onSessionExpired();
      }

      throw refreshErr;
    } finally {
      isRefreshing = false;
    }
  }

  // 4. Procesar respuesta estándar
  let responseData: any = null;
  const contentType = response.headers.get('content-type');
  if (contentType && contentType.includes('application/json')) {
    responseData = await response.json().catch(() => ({}));
  } else {
    responseData = await response.text().catch(() => '');
  }

  return {
    data: responseData as T,
    status: response.status,
    headers: response.headers,
  };
}

