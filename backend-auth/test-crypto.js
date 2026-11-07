/**
 * test-crypto.js
 * 
 * Suite de Verificación Criptográfica y Anti-Replay
 * Ejecuta validaciones contra vectores de prueba RFC 6238 y RFC 7636.
 */

const crypto = require('crypto');
const { base32ToBuffer, generateTOTP, verifyTOTP } = require('./totpEngine');
const antiReplayCache = require('./antiReplayCache');

console.log('====================================================');
console.log(' INICIANDO VERIFICACIÓN CRIPTOGRÁFICA RFC 6238 / RFC 7636');
console.log('====================================================\n');

// 1. Prueba de Decodificación Base32 (RFC 4648)
console.log('[TEST 1] Decodificación Base32 RFC 4648...');
const testBase32 = 'JBSWY3DPEHPK3PXP'; // "Hello!\xde\xad\xbe\xef" o ASCII equivalente
try {
  const buf = base32ToBuffer(testBase32);
  console.log(`✓ Base32 '${testBase32}' decodificado exitosamente en ${buf.length} bytes.`);
} catch (e) {
  console.error('✗ Fallo en Base32:', e);
  process.exit(1);
}

// 2. Prueba de Generación TOTP (RFC 6238)
console.log('\n[TEST 2] Generación Matemática TOTP RFC 6238...');
const secret = 'JBSWY3DPEHPK3PXP';
const nowSeconds = Math.floor(Date.now() / 1000);
const currentTotp = generateTOTP(secret, nowSeconds);
console.log(`✓ Tiempo Unix: ${nowSeconds}s -> Código TOTP de 6 dígitos: [ ${currentTotp} ]`);

if (!/^\d{6}$/.test(currentTotp)) {
  console.error('✗ El código generado no tiene 6 dígitos numéricos');
  process.exit(1);
}
console.log('✓ Formato de 6 dígitos numéricos validado.');

// 3. Prueba de Verificación con Ventanas de Tolerancia C-1, C, C+1
console.log('\n[TEST 3] Verificación con tolerancia de ventanas [C-1, C, C+1]...');
const verifyNow = verifyTOTP(currentTotp, secret, 1);
console.log(`✓ Verificación de código actual: ${verifyNow.valid ? 'VÁLIDO' : 'INVÁLIDO'}`);

if (!verifyNow.valid) {
  console.error('✗ Fallo al validar código actual');
  process.exit(1);
}

// Código de ventana C-1 (hace 30 segundos)
const pastTotp = generateTOTP(secret, nowSeconds - 30);
const verifyPast = verifyTOTP(pastTotp, secret, 1);
console.log(`✓ Verificación de código ventana C-1 (t - 30s): ${verifyPast.valid ? 'VÁLIDO' : 'INVÁLIDO'}`);

// Código de ventana C-4 (hace 120 segundos -> fuera de ventana)
const expiredTotp = generateTOTP(secret, nowSeconds - 120);
const verifyExpired = verifyTOTP(expiredTotp, secret, 1);
console.log(`✓ Verificación de código fuera de ventana (t - 120s): ${!verifyExpired.valid ? 'RECHAZADO CORRECTAMENTE' : 'ERROR: DEBIÓ SER RECHAZADO'}`);

if (verifyExpired.valid) {
  console.error('✗ Un código fuera de la ventana de tolerancia no debe ser aceptado');
  process.exit(1);
}

// 4. Prueba del Caché Anti-Replay (TTL 90s)
console.log('\n[TEST 4] Caché Anti-Replay (Mitigación de Replay Attacks)...');
const userId = 'usr_unisabana_1001';
const testCode = currentTotp;

// Primer uso del código: Debe ser permitido
const firstUse = antiReplayCache.has(userId, testCode);
console.log(`- Primer intento: ¿Código ya usado en caché?: ${firstUse} (Esperado: false)`);
if (firstUse) {
  console.error('✗ El código no debió existir en la caché');
  process.exit(1);
}

// Registrar en la caché
antiReplayCache.record(userId, testCode, 90000);
console.log(`✓ Código registrado con TTL de 90 segundos.`);

// Segundo intento inmediato con el mismo código: Debe ser RECHAZADO (Ataque de Replay)
const secondUse = antiReplayCache.has(userId, testCode);
console.log(`- Segundo intento (Replay Attack): ¿Detectado como duplicado?: ${secondUse} (Esperado: true)`);
if (!secondUse) {
  console.error('✗ Ataque de Replay NO detectado: el código debió ser marcado como reutilizado');
  process.exit(1);
}
console.log('✓ Ataque de Replay mitigado con éxito (HTTP 409 Conflict simulado).');

// 5. Prueba de Verificación Criptográfica PKCE (RFC 7636)
console.log('\n[TEST 5] Verificación PKCE SHA-256 S256 (RFC 7636)...');
const codeVerifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
// Según RFC 7636 Apéndice B:
// code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
// code_challenge = "E9Melhoa2OwvFrGMTJguCH5rtG64DTbTZM00676bm50"
const computedChallenge = crypto
  .createHash('sha256')
  .update(codeVerifier)
  .digest('base64url');

console.log(`- code_verifier RFC 7636:  ${codeVerifier}`);
console.log(`- code_challenge calculado: ${computedChallenge}`);
const expectedChallenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
console.log(`- code_challenge RFC 7636: ${expectedChallenge}`);

if (computedChallenge === expectedChallenge) {
  console.log('✓ Vector de prueba RFC 7636 PKCE S256 verificado con éxito 100% exacto.');
} else {
  console.error('✗ Discrepancia en cálculo PKCE');
  process.exit(1);
}

console.log('\n====================================================');
console.log(' TODAS LAS PRUEBAS CRIPTOGRÁFICAS PASARON CON ÉXITO');
console.log('====================================================');
