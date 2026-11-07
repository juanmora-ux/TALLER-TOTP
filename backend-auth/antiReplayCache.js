/**
 * antiReplayCache.js
 * 
 * Implementación de Caché en Memoria con TTL (Time-To-Live) de 90 segundos
 * para mitigación de ataques de retransmisión (Replay Attacks) sobre códigos TOTP RFC 6238.
 * 
 * Ventana de tolerancia TOTP: C-1 (t-30s), C (actual), C+1 (t+30s).
 * En consecuencia, un código TOTP permanece criptográficamente válido durante 90 segundos.
 * Esta caché garantiza que ningún código pueda reutilizarse dentro de su ciclo de vida activo.
 */

class AntiReplayCache {
  constructor(defaultTtlMs = 90000) {
    this.defaultTtlMs = defaultTtlMs;
    /** @type {Map<string, { timestamp: number, expiresAt: number, userId: string, code: string }>} */
    this.cache = new Map();

    // Limpieza periódica de entradas expiradas cada 30 segundos
    this.cleanupTimer = setInterval(() => {
      this.cleanup();
    }, 30000);

    // Evitar que el timer impida que el proceso Node termine si está en idle
    if (this.cleanupTimer.unref) {
      this.cleanupTimer.unref();
    }
  }

  /**
   * Genera una clave única por usuario y código TOTP
   * @param {string} userId
   * @param {string} code
   * @returns {string}
   */
  _buildKey(userId, code) {
    return `${userId}:${code.trim()}`;
  }

  /**
   * Comprueba si un código TOTP ya fue utilizado por el usuario dentro del TTL
   * @param {string} userId 
   * @param {string} code 
   * @returns {boolean} true si el código ya fue usado (ataque de replay)
   */
  has(userId, code) {
    const key = this._buildKey(userId, code);
    const entry = this.cache.get(key);

    if (!entry) {
      return false;
    }

    const now = Date.now();
    if (now > entry.expiresAt) {
      // Expiró; se elimina
      this.cache.delete(key);
      return false;
    }

    return true;
  }

  /**
   * Registra un código TOTP como consumido
   * @param {string} userId 
   * @param {string} code 
   * @param {number} [customTtlMs]
   * @returns {boolean} true si se registró con éxito, false si ya existía
   */
  record(userId, code, customTtlMs) {
    const key = this._buildKey(userId, code);
    if (this.has(userId, code)) {
      return false; // Conflicto: Ya usado
    }

    const now = Date.now();
    const ttl = customTtlMs || this.defaultTtlMs;
    const expiresAt = now + ttl;

    this.cache.set(key, {
      timestamp: now,
      expiresAt,
      userId,
      code: code.trim()
    });

    console.log(`[AntiReplayCache] Código TOTP ${code} registrado para usuario ${userId}. Expira en ${ttl / 1000}s`);
    return true;
  }

  /**
   * Elimina todas las entradas vencidas de la memoria
   * @returns {number} cantidad de entradas eliminadas
   */
  cleanup() {
    const now = Date.now();
    let purged = 0;

    for (const [key, entry] of this.cache.entries()) {
      if (now > entry.expiresAt) {
        this.cache.delete(key);
        purged++;
      }
    }

    if (purged > 0) {
      console.log(`[AntiReplayCache] Limpieza completada. ${purged} códigos expirados eliminados.`);
    }

    return purged;
  }

  /**
   * Devuelve estadísticas actuales para telemetría y auditoría de seguridad
   */
  getStats() {
    return {
      activeTokensCount: this.cache.size,
      ttlSeconds: this.defaultTtlMs / 1000,
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Limpia toda la caché (útil en tests)
   */
  clear() {
    this.cache.clear();
  }
}

module.exports = new AntiReplayCache(90000);

