/**
 * auth.ts
 * 
 * Definiciones e Interfaces TypeScript para el Flujo de Seguridad Móvil:
 * - OAuth 2.0 con PKCE (RFC 7636)
 * - Tokens JWT & Enclave Seguro (SecureStore)
 * - Step-Up 2FA Challenge & Elevación de Privilegios
 * - Motor Criptográfico TOTP (RFC 6238 / RFC 4226)
 */

export interface PKCECodes {
  codeVerifier: string;
  codeChallenge: string;
  state: string;
  codeChallengeMethod: 'S256';
}

export interface UserProfile {
  id: string;
  email: string;
  name: string;
  role: string;
}

export interface OAuthTokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
  user: UserProfile;
}

export interface RefreshTokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
}

export interface StepUpChallengeResponse {
  error: 'mfa_required';
  message: string;
  stepUpToken: string;
}

export interface StepUpVerificationResult {
  status: 'success';
  message: string;
  elevated_token: string;
  expires_in: number;
}

export interface VaultConfidentialData {
  studentId: string;
  studentName: string;
  academicRecords: string;
  financialStatus: string;
  cryptographicKeys: {
    masterSeedVault: string;
    hsmEnclaveSignature: string;
    zkpVerificationRoot: string;
  };
  confidentialDocuments: Array<{
    name: string;
    size: string;
    hash: string;
  }>;
  authorizedAt: string;
}

export interface VaultResponse {
  status: string;
  classification: string;
  vaultData: VaultConfidentialData;
}

export interface TOTPConfig {
  secret: string;
  account: string;
  issuer: string;
  digits: number;
  period: number;
  algorithm: 'SHA1' | 'SHA256';
}

export interface TOTPAccountRecord {
  id: string;
  issuer: string;
  account: string;
  secret: string; // Guardado en SecureStore
  createdAt: number;
}

export interface AuthContextType {
  user: UserProfile | null;
  accessToken: string | null;
  elevatedToken: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  loginWithPKCE: () => Promise<boolean>;
  logout: () => Promise<void>;
  setElevatedToken: (token: string | null) => void;
  getEffectiveAccessToken: () => string | null;
}

