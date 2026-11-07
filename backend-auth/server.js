/**
 * server.js
 * 
 * Servidor Backend de Autenticación y Autorización
 * Especificación: OAuth 2.0 con PKCE (RFC 7636), JWT Tokens, Silent Refresh,
 * Step-Up 2FA (RFC 6238 TOTP nativo) y Caché Anti-Replay con TTL de 90 segundos.
 */

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const antiReplayCache = require('./antiReplayCache');
const { generateTOTP, verifyTOTP } = require('./totpEngine');

const app = express();
const PORT = process.env.PORT || 4000;

// Secretos criptográficos para firma de Tokens JWT
const JWT_SECRET = process.env.JWT_SECRET || 'unisabana_super_secret_jwt_key_2026_ciberseguridad';
const STEP_UP_SECRET = process.env.STEP_UP_SECRET || 'unisabana_step_up_challenge_secret_key_9941';

app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ==========================================
// Base de Datos en Memoria (PoC Académica)
// ==========================================

// Usuario de prueba del laboratorio
const USERS = {
  'usr_unisabana_1001': {
    id: 'usr_unisabana_1001',
    email: 'estudiante@unisabana.edu.co',
    passwordHash: crypto.createHash('sha256').update('SeguridadMovil2026!').digest('hex'),
    name: 'Estudiante Ciberseguridad Unisabana',
    role: 'student',
    // Semilla Base32 compartida para TOTP RFC 6238
    totpSecret: 'JBSWY3DPEHPK3PXP'
  }
};

// Almacén de códigos de autorización OAuth 2.0 PKCE en vuelo
// Clave: code -> { codeChallenge, clientId, redirectUri, userId, expiresAt }
const authCodesStore = new Map();

// Almacén de Refresh Tokens activos
// Clave: refreshToken -> { userId, expiresAt, createdAt }
const refreshTokensStore = new Map();

// Limpieza periódica de auth_codes expirados
setInterval(() => {
  const now = Date.now();
  for (const [code, data] of authCodesStore.entries()) {
    if (now > data.expiresAt) {
      authCodesStore.delete(code);
    }
  }
}, 30000);

// ==========================================
// Rutas de OAuth 2.0 con PKCE (RFC 7636)
// ==========================================

/**
 * GET /auth/oauth/authorize
 * Interfaz de autorización visual mostrada en el navegador del sistema (WebBrowser)
 */
app.get('/auth/oauth/authorize', (req, res) => {
  const { response_type, client_id, redirect_uri, code_challenge, code_challenge_method, state } = req.query;

  // Validación de parámetros obligatorios según RFC 7636
  if (response_type !== 'code') {
    return res.status(400).send('Parámetro response_type debe ser "code"');
  }
  if (!code_challenge || code_challenge_method !== 'S256') {
    return res.status(400).send('PKCE obligatorio: se requiere code_challenge con método S256');
  }
  if (!redirect_uri) {
    return res.status(400).send('Falta parámetro redirect_uri');
  }

  // Renderizar interfaz HTML responsiva universitaria
  res.send(`
    <!DOCTYPE html>
    <html lang="es">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Universidad de La Sabana - Autenticación Segura</title>
      <style>
        :root {
          --primary: #003366;
          --primary-dark: #002244;
          --accent: #E5A823;
          --bg: #f4f6f9;
          --card: #ffffff;
          --text: #2c3e50;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        body { background: var(--bg); display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 20px; }
        .card { background: var(--card); border-radius: 12px; box-shadow: 0 10px 25px rgba(0,0,0,0.1); width: 100%; max-width: 420px; overflow: hidden; border: 1px solid #e1e8ed; }
        .header { background: var(--primary); color: white; padding: 28px 20px; text-align: center; }
        .header h1 { font-size: 1.25rem; font-weight: 700; letter-spacing: 0.5px; }
        .header p { font-size: 0.85rem; color: #cbd5e1; margin-top: 6px; }
        .badge { display: inline-block; background: var(--accent); color: #000; font-size: 0.7rem; font-weight: bold; padding: 3px 8px; border-radius: 20px; margin-top: 8px; }
        .body { padding: 24px 20px; }
        .form-group { margin-bottom: 16px; }
        label { display: block; font-size: 0.85rem; font-weight: 600; color: var(--text); margin-bottom: 6px; }
        input[type="text"], input[type="password"] {
          width: 100%; padding: 12px; border: 1.5px solid #d1d5db; border-radius: 8px; font-size: 0.95rem; outline: none; transition: border-color 0.2s;
        }
        input:focus { border-color: var(--primary); ring: 2px solid rgba(0,51,102,0.2); }
        .btn { width: 100%; background: var(--primary); color: white; border: none; padding: 14px; border-radius: 8px; font-size: 1rem; font-weight: 600; cursor: pointer; transition: background 0.2s; margin-top: 10px; }
        .btn:hover { background: var(--primary-dark); }
        .security-info { margin-top: 20px; background: #f8fafc; border-left: 4px solid var(--accent); padding: 10px 12px; font-size: 0.75rem; color: #64748b; line-height: 1.4; }
        .credentials-hint { background: #e0f2fe; border: 1px solid #bae6fd; border-radius: 6px; padding: 10px; margin-bottom: 16px; font-size: 0.8rem; color: #0369a1; }
      </style>
    </head>
    <body>
      <div class="card">
        <div class="header">
          <h1>UNIVERSIDAD DE LA SABANA</h1>
          <p>Servicio de Identidad Centralizado (OAuth 2.0 + PKCE)</p>
          <span class="badge">RFC 7636 SECURE LOGIN</span>
        </div>
        <div class="body">
          <div class="credentials-hint">
            <strong>Credenciales académicas de prueba:</strong><br/>
            Usuario: <code>estudiante@unisabana.edu.co</code><br/>
            Contraseña: <code>SeguridadMovil2026!</code>
          </div>

          <form action="/auth/oauth/login-submit" method="POST">
            <input type="hidden" name="client_id" value="${client_id || ''}" />
            <input type="hidden" name="redirect_uri" value="${redirect_uri || ''}" />
            <input type="hidden" name="code_challenge" value="${code_challenge || ''}" />
            <input type="hidden" name="state" value="${state || ''}" />

            <div class="form-group">
              <label for="email">Correo Institucional</label>
              <input type="text" id="email" name="email" value="estudiante@unisabana.edu.co" required />
            </div>

            <div class="form-group">
              <label for="password">Contraseña</label>
              <input type="password" id="password" name="password" value="SeguridadMovil2026!" required />
            </div>

            <button type="submit" class="btn">Iniciar Sesión y Autorizar</button>
          </form>

          <div class="security-info">
            <strong>Protección Criptográfica Activa:</strong> Esta sesión valida el intercambio de tokens mediante SHA-256 PKCE Code Challenge sin exposición de credenciales del cliente.
          </div>
        </div>
      </div>
    </body>
    </html>
  `);
});

/**
 * POST /auth/oauth/login-submit
 * Procesa el formulario de login, valida credenciales y redirige con authorization_code
 */
app.post('/auth/oauth/login-submit', (req, res) => {
  const { email, password, client_id, redirect_uri, code_challenge, state } = req.body;

  // Buscar usuario
  const user = Object.values(USERS).find(u => u.email === email);
  const passwordHash = crypto.createHash('sha256').update(password || '').digest('hex');

  if (!user || user.passwordHash !== passwordHash) {
    return res.status(401).send(`
      <script>
        alert("Credenciales incorrectas. Verifique su usuario y contraseña.");
        window.history.back();
      </script>
    `);
  }

  // Generar un authorization_code criptográficamente seguro de un solo uso
  const authCode = 'authcode_' + crypto.randomBytes(32).toString('hex');
  const expiresAt = Date.now() + (2 * 60 * 1000); // 2 minutos de vigencia

  // Registrar en memoria vinculado al code_challenge de PKCE
  authCodesStore.set(authCode, {
    codeChallenge: code_challenge,
    clientId: client_id,
    redirectUri: redirect_uri,
    userId: user.id,
    expiresAt
  });

  console.log(`[OAuth] Código emitido: ${authCode} para usuario ${user.email}`);

  // Redireccionar al Custom Scheme Deep Link con code y state
  const callbackUrl = new URL(redirect_uri);
  callbackUrl.searchParams.set('code', authCode);
  if (state) {
    callbackUrl.searchParams.set('state', state);
  }

  // Redirigir al cliente móvil
  return res.redirect(callbackUrl.toString());
});

/**
 * POST /auth/oauth/token
 * Intercambio seguro de código por tokens con validación estricta de PKCE RFC 7636
 */
app.post('/auth/oauth/token', (req, res) => {
  const { grant_type, code, code_verifier, client_id, redirect_uri } = req.body;

  if (grant_type !== 'authorization_code') {
    return res.status(400).json({
      error: 'unsupported_grant_type',
      error_description: 'grant_type debe ser "authorization_code"'
    });
  }

  if (!code || !code_verifier) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'Se requieren parámetros "code" y "code_verifier"'
    });
  }

  const authSession = authCodesStore.get(code);

  if (!authSession) {
    return res.status(400).json({
      error: 'invalid_grant',
      error_description: 'Código de autorización expirado, inválido o ya utilizado'
    });
  }

  // DESTRUIR EL CÓDIGO INMEDIATAMENTE (Uso único estricto)
  authCodesStore.delete(code);

  if (Date.now() > authSession.expiresAt) {
    return res.status(400).json({
      error: 'invalid_grant',
      error_description: 'El código de autorización ha expirado'
    });
  }

  // ==========================================
  // Validación Criptográfica PKCE (RFC 7636)
  // code_challenge = Base64URL_Unpadded(SHA256(code_verifier))
  // ==========================================
  const computedHash = crypto
    .createHash('sha256')
    .update(code_verifier)
    .digest('base64url'); // base64url no incluye padding '=' y es URL safe

  const challengeBuffer = Buffer.from(authSession.codeChallenge);
  const computedBuffer = Buffer.from(computedHash);

  const isValidPkce =
    challengeBuffer.length === computedBuffer.length &&
    crypto.timingSafeEqual(challengeBuffer, computedBuffer);

  if (!isValidPkce) {
    console.warn(`[PKCE Warning] Rechazado. Challenge guardado: ${authSession.codeChallenge}, Calculado: ${computedHash}`);
    return res.status(400).json({
      error: 'invalid_grant',
      error_description: 'Falla criptográfica PKCE: code_verifier no corresponde al code_challenge enviado'
    });
  }

  const user = USERS[authSession.userId];

  // 1. Emitir access_token (TTL corto: 5 minutos / 300s)
  // mfa_verified arranca en false
  const accessTokenPayload = {
    sub: user.id,
    email: user.email,
    name: user.name,
    role: user.role,
    mfa_verified: false
  };

  const accessToken = jwt.sign(accessTokenPayload, JWT_SECRET, {
    expiresIn: '5m'
  });

  // 2. Emitir refresh_token (TTL largo: 30 días)
  const refreshToken = 'rt_' + crypto.randomBytes(48).toString('hex');
  const refreshExpiresAt = Date.now() + (30 * 24 * 60 * 60 * 1000);

  refreshTokensStore.set(refreshToken, {
    userId: user.id,
    expiresAt: refreshExpiresAt,
    createdAt: Date.now()
  });

  console.log(`[OAuth] Intercambio PKCE exitoso para ${user.email}. Emitidos access_token y refresh_token.`);

  return res.json({
    access_token: accessToken,
    refresh_token: refreshToken,
    token_type: 'Bearer',
    expires_in: 300,
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role
    }
  });
});

/**
 * POST /auth/refresh
 * Silent Refresh Queue: Rotación y emisión de nuevo access_token mediante refresh_token
 */
app.post('/auth/refresh', (req, res) => {
  const { refresh_token } = req.body;

  if (!refresh_token) {
    return res.status(400).json({
      error: 'invalid_request',
      message: 'Falta parámetro refresh_token'
    });
  }

  const session = refreshTokensStore.get(refresh_token);

  if (!session) {
    return res.status(401).json({
      error: 'invalid_token',
      message: 'El refresh_token no existe o ha sido revocado'
    });
  }

  if (Date.now() > session.expiresAt) {
    refreshTokensStore.delete(refresh_token);
    return res.status(401).json({
      error: 'token_expired',
      message: 'El refresh_token ha expirado. Se requiere reautenticación completa.'
    });
  }

  const user = USERS[session.userId];
  if (!user) {
    return res.status(401).json({
      error: 'user_not_found',
      message: 'Usuario no encontrado'
    });
  }

  // Generar nuevo access_token con TTL de 5 minutos
  const newAccessToken = jwt.sign({
    sub: user.id,
    email: user.email,
    name: user.name,
    role: user.role,
    mfa_verified: false
  }, JWT_SECRET, {
    expiresIn: '5m'
  });

  console.log(`[Auth Refresh] Token renovado en background para ${user.email}`);

  return res.json({
    access_token: newAccessToken,
    token_type: 'Bearer',
    expires_in: 300
  });
});

// ==========================================
// Middleware de Autenticación JWT Bearer
// ==========================================
function authenticateBearer(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'unauthorized',
      message: 'Cabecera Authorization: Bearer <token> ausente o malformada'
    });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({
        error: 'token_expired',
        message: 'El access_token ha expirado'
      });
    }
    return res.status(401).json({
      error: 'invalid_token',
      message: 'Firma o estructura de access_token inválida'
    });
  }
}

// ==========================================
// Bóveda Crítica con Step-Up Authentication
// ==========================================

/**
 * GET /api/boveda-critica
 * Requiere access_token con mfa_verified === true.
 * Si mfa_verified === false, responde 403 Forbidden con un stepUpToken firmado.
 */
app.get('/api/boveda-critica', authenticateBearer, (req, res) => {
  // Inspeccionar estado de elevación 2FA
  if (req.user.mfa_verified !== true) {
    // Generar stepUpToken firmado con TTL corto de 3 minutos
    const stepUpToken = jwt.sign({
      sub: req.user.sub,
      action: 'vault_step_up_challenge',
      nonce: crypto.randomBytes(16).toString('hex')
    }, STEP_UP_SECRET, {
      expiresIn: '3m'
    });

    console.log(`[Step-Up] Acceso a Bóveda denegado para ${req.user.email}: se requiere MFA. Emitido stepUpToken.`);

    return res.status(403).json({
      error: 'mfa_required',
      message: 'Privilegios insuficientes: el recurso "Bóveda Crítica" exige elevación Step-Up 2FA (TOTP RFC 6238).',
      stepUpToken: stepUpToken
    });
  }

  // Acceso autorizado a la Bóveda Crítica
  console.log(`[Step-Up] Acceso AUTORIZADO a Bóveda Crítica para usuario ${req.user.email}`);

  return res.json({
    status: 'success',
    classification: 'TOP_SECRET // UNIVERSIDAD DE LA SABANA - SEGURIDAD MÓVIL',
    vaultData: {
      studentId: req.user.sub,
      studentName: req.user.name,
      academicRecords: 'Promedio acumulado: 4.88 / 5.00 — Mención Meritoria en Ciberseguridad Defensiva',
      financialStatus: 'Beca de Excelencia Académica Activa (100% Cobertura)',
      cryptographicKeys: {
        masterSeedVault: '0x7F9B1E4A8D3C2B1F0A9E8D7C6B5A4F3E',
        hsmEnclaveSignature: 'SHA256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        zkpVerificationRoot: '0x8849201a0bcdef5541289410adfacde12890'
      },
      confidentialDocuments: [
        { name: 'Examen_Parcial_Seguridad_Avanzada.pdf.enc', size: '2.4 MB', hash: 'd41d8cd98f00b204e9800998ecf8427e' },
        { name: 'Certificado_Digital_Firma_Maestra.pem', size: '4.1 KB', hash: 'a1b2c3d4e5f60718293a4b5c6d7e8f90' }
      ],
      authorizedAt: new Date().toISOString()
    }
  });
});

/**
 * POST /auth/mfa/verify
 * Valida el stepUpToken y el código TOTP ingresado en las 3 ventanas temporales (C-1, C, C+1).
 * Consulta la caché Anti-Replay con TTL de 90 segundos.
 * Si el código ya fue usado, responde 409 Conflict.
 * Si es válido, registra el código en la caché y retorna elevated_token (mfa_verified: true, TTL 10 min).
 */
app.post('/auth/mfa/verify', (req, res) => {
  const { stepUpToken, totpCode } = req.body;

  if (!stepUpToken || !totpCode) {
    return res.status(400).json({
      error: 'invalid_request',
      message: 'Se requieren stepUpToken y totpCode'
    });
  }

  // 1. Validar el stepUpToken
  let stepUpPayload;
  try {
    stepUpPayload = jwt.verify(stepUpToken, STEP_UP_SECRET);
  } catch (err) {
    return res.status(401).json({
      error: 'invalid_challenge_token',
      message: 'El stepUpToken es inválido o ha expirado. Solicite un nuevo desafío.'
    });
  }

  const userId = stepUpPayload.sub;
  const user = USERS[userId];

  if (!user) {
    return res.status(404).json({
      error: 'user_not_found',
      message: 'Usuario asociado al desafío no existe'
    });
  }

  const cleanTotp = totpCode.toString().trim();

  // 2. Consulta Anti-Replay Cache con TTL de 90 segundos
  if (antiReplayCache.has(userId, cleanTotp)) {
    console.warn(`[Anti-Replay Attack Alert] Código TOTP ${cleanTotp} reutilizado por usuario ${userId}!`);
    return res.status(409).json({
      error: 'replay_attack_detected',
      message: 'Conflicto de Seguridad: Ataque de Replay Detectado. Este código TOTP ya fue utilizado en su ventana de validez de 90 segundos y ha quedado invalidado.'
    });
  }

  // 3. Verificación matemática TOTP RFC 6238 en ventanas [C-1, C, C+1]
  const verification = verifyTOTP(cleanTotp, user.totpSecret, 1);

  if (!verification.valid) {
    console.warn(`[TOTP Failed] Código incorrecto o desfasado: ${cleanTotp} para usuario ${user.email}`);
    return res.status(400).json({
      error: 'invalid_totp_code',
      message: 'Código TOTP incorrecto o expirado. Verifique la sincronización de reloj en su dispositivo.'
    });
  }

  // 4. Registrar código en Anti-Replay Cache
  antiReplayCache.record(userId, cleanTotp, 90000);

  // 5. Emitir elevated_token con mfa_verified: true (TTL 10 minutos / 600 segundos)
  const elevatedToken = jwt.sign({
    sub: user.id,
    email: user.email,
    name: user.name,
    role: user.role,
    mfa_verified: true
  }, JWT_SECRET, {
    expiresIn: '10m'
  });

  console.log(`[Step-Up Success] Privilegios elevados otorgados con éxito a ${user.email} (TTL 10m)`);

  return res.json({
    status: 'success',
    message: 'Elevación de privilegios Step-Up 2FA completada exitosamente',
    elevated_token: elevatedToken,
    expires_in: 600
  });
});

/**
 * GET /auth/mfa/setup
 * Información de configuración para el Authenticator del cliente móvil
 */
app.get('/auth/mfa/setup', (req, res) => {
  const secret = USERS['usr_unisabana_1001'].totpSecret;
  const email = USERS['usr_unisabana_1001'].email;
  const issuer = 'Unisabana';
  const qrUri = `otpauth://totp/${issuer}:${email}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`;

  return res.json({
    secret,
    email,
    issuer,
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
    qrUri
  });
});

/**
 * GET /health
 * Estado del servicio y estadísticas del caché Anti-Replay
 */
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    uptime: process.uptime(),
    antiReplay: antiReplayCache.getStats()
  });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`=======================================================`);
  console.log(` Servidor Backend Auth Unisabana en http://localhost:${PORT}`);
  console.log(` - OAuth 2.0 PKCE Authorize: http://localhost:${PORT}/auth/oauth/authorize`);
  console.log(` - Token Exchange:           POST http://localhost:${PORT}/auth/oauth/token`);
  console.log(` - Bóveda Crítica Step-Up:    GET  http://localhost:${PORT}/api/boveda-critica`);
  console.log(` - TOTP 2FA Verification:     POST http://localhost:${PORT}/auth/mfa/verify`);
  console.log(` - Anti-Replay TTL:          90 segundos activo`);
  console.log(`=======================================================`);
});

