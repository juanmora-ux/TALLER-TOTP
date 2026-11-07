/**
 * AuthContext.tsx
 * 
 * Contexto Central de Autenticación y Ciclo de Vida de Credenciales
 * 
 * Principios Criptográficos y de Seguridad Móvil:
 * 1. El 'access_token' reside EXCLUSIVAMENTE en memoria RAM (React State).
 * 2. Se destruye inmediatamente al matar la app o al invocar logout().
 * 3. El 'refresh_token' se recupera desde el enclave seguro de hardware (SecureStore).
 * 4. Orquestación del flujo OAuth 2.0 con PKCE (RFC 7636) y validación de 'state' anti-CSRF.
 */

import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import * as WebBrowser from 'expo-web-browser';
import * as Linking from 'expo-linking';
import { AuthContextType, UserProfile, OAuthTokenResponse } from '../types/auth';
import { createPKCEParams } from '../utils/pkce';
import {
  saveRefreshToken,
  getRefreshToken,
  removeRefreshToken,
} from '../services/secureStorage';
import {
  API_BASE_URL,
  setMemoryTokens,
  registerAuthCallbacks,
} from '../services/apiClient';

// Asegurar que WebBrowser complete correctamente cualquier sesión residual
WebBrowser.maybeCompleteAuthSession();

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  // Estado en Memoria RAM estricta
  const [user, setUser] = useState<UserProfile | null>(null);
  const [accessToken, setAccessToken] = useState<string | null>(null);
  const [elevatedToken, setElevatedTokenState] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  // Sincronizar tokens en memoria con el módulo apiClient
  const updateAccessToken = (newToken: string | null) => {
    setAccessToken(newToken);
    setMemoryTokens(newToken, elevatedToken);
  };

  const setElevatedToken = (token: string | null) => {
    setElevatedTokenState(token);
    setMemoryTokens(accessToken, token);
  };

  // Inicialización: Silent Login mediante Refresh Token almacenado en Hardware Enclave
  useEffect(() => {
    const initializeAuth = async () => {
      try {
        const storedRefreshToken = await getRefreshToken();

        if (storedRefreshToken) {
          console.log('[AuthContext] Refresh Token detectado en enclave seguro. Ejecutando handshake silencioso...');

          const response = await fetch(`${API_BASE_URL}/auth/refresh`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ refresh_token: storedRefreshToken }),
          });

          if (response.ok) {
            const data = await response.json();
            updateAccessToken(data.access_token);
            // Reconstruir perfil básico
            setUser({
              id: 'usr_unisabana_1001',
              email: 'estudiante@unisabana.edu.co',
              name: 'Estudiante Ciberseguridad Unisabana',
              role: 'student',
            });
            console.log('[AuthContext] Sesión restaurada silenciosamente.');
          } else {
            console.warn('[AuthContext] Refresh Token caducado o inválido. Limpiando credenciales...');
            await removeRefreshToken();
          }
        }
      } catch (err) {
        console.error('[AuthContext] Error en inicialización de sesión:', err);
      } finally {
        setIsLoading(false);
      }
    };

    // Registrar callbacks para el Silent Refresh Queue del apiClient
    registerAuthCallbacks(
      (newToken: string) => {
        setAccessToken(newToken);
        setMemoryTokens(newToken, elevatedToken);
      },
      () => {
        // Callback al expirar sesión
        setUser(null);
        setAccessToken(null);
        setElevatedTokenState(null);
        setMemoryTokens(null, null);
      }
    );

    initializeAuth();
  }, []);

  /**
   * Inicia el flujo OAuth 2.0 con PKCE (RFC 7636) usando el navegador del sistema
   * REGLA DE SEGURIDAD: Nunca usar WebViews embebidas (RFC 8252 BCP).
   */
  const loginWithPKCE = async (): Promise<boolean> => {
    try {
      setIsLoading(true);

      // 1. Generar parámetros PKCE criptográficos y State anti-CSRF
      const { codeVerifier, codeChallenge, state } = await createPKCEParams();

      const redirectUri = 'unisabana-auth://callback';
      const clientId = 'unisabana_mobile_client';

      const authUrl = `${API_BASE_URL}/auth/oauth/authorize?` +
        `response_type=code` +
        `&client_id=${encodeURIComponent(clientId)}` +
        `&redirect_uri=${encodeURIComponent(redirectUri)}` +
        `&code_challenge=${encodeURIComponent(codeChallenge)}` +
        `&code_challenge_method=S256` +
        `&state=${encodeURIComponent(state)}`;

      console.log('[PKCE] Abriendo navegador del sistema para autorización...');

      // 2. Abrir ASWebAuthenticationSession / Custom Tabs
      const authResult = await WebBrowser.openAuthSessionAsync(authUrl, redirectUri);

      if (authResult.type !== 'success' || !authResult.url) {
        console.log('[PKCE] Flujo de autenticación cancelado por el usuario.');
        return false;
      }

      console.log('[PKCE] Deep Link recibido:', authResult.url);

      // 3. Parsear el deep link retornado unisabana-auth://callback?code=...&state=...
      const parsedUrl = Linking.parse(authResult.url);
      const queryParams = parsedUrl.queryParams || {};

      const returnedCode = queryParams.code as string;
      const returnedState = queryParams.state as string;

      // 4. Validación estricta anti-CSRF del parámetro State
      if (!returnedState || returnedState !== state) {
        throw new Error('Alerta de Seguridad: State anti-CSRF inválido o manipulado en la transacción.');
      }

      if (!returnedCode) {
        throw new Error('No se recibió el parámetro authorization_code en el callback.');
      }

      // 5. Intercambio de tokens enviando code y code_verifier (POST /auth/oauth/token)
      console.log('[PKCE] Intercambiando authorization_code y code_verifier...');

      const tokenResponse = await fetch(`${API_BASE_URL}/auth/oauth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          grant_type: 'authorization_code',
          code: returnedCode,
          code_verifier: codeVerifier,
          client_id: clientId,
          redirect_uri: redirectUri,
        }),
      });

      if (!tokenResponse.ok) {
        const errorData = await tokenResponse.json().catch(() => ({}));
        throw new Error(errorData.error_description || 'Fallo en el intercambio de tokens PKCE');
      }

      const tokenData: OAuthTokenResponse = await tokenResponse.json();

      // 6. Almacenamiento Seguro según especificación:
      // - refresh_token -> SecureStore (Keychain / Keystore)
      // - access_token -> RAM exclusivamente
      await saveRefreshToken(tokenData.refresh_token);
      updateAccessToken(tokenData.access_token);
      setUser(tokenData.user);

      console.log(`[PKCE] Autenticación completada con éxito. Usuario: ${tokenData.user.email}`);
      return true;
    } catch (error: any) {
      console.error('[PKCE Error] Error durante el proceso de login:', error);
      alert(`Error de autenticación: ${error.message || error}`);
      return false;
    } finally {
      setIsLoading(false);
    }
  };

  /**
   * Cierre de sesión seguro: destruye tokens en memoria y en enclave de hardware
   */
  const logout = async (): Promise<void> => {
    try {
      setIsLoading(true);
      await removeRefreshToken();
      setUser(null);
      setAccessToken(null);
      setElevatedTokenState(null);
      setMemoryTokens(null, null);
      console.log('[AuthContext] Sesión destruida completamente.');
    } finally {
      setIsLoading(false);
    }
  };

  const getEffectiveAccessToken = (): string | null => {
    return elevatedToken || accessToken;
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        accessToken,
        elevatedToken,
        isAuthenticated: !!accessToken && !!user,
        isLoading,
        loginWithPKCE,
        logout,
        setElevatedToken,
        getEffectiveAccessToken,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth debe ser utilizado dentro de un AuthProvider');
  }
  return context;
};

