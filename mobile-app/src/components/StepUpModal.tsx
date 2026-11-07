/**
 * StepUpModal.tsx
 * 
 * Componente Modal para Elevación de Privilegios Step-Up 2FA
 * Se despliega al recibir HTTP 403 Forbidden ({ error: "mfa_required" }).
 * 
 * Validación Criptográfica y Detección de Ataques:
 * - Envía 'stepUpToken' + 'totpCode' a POST /auth/mfa/verify
 * - Maneja respuesta 409 Conflict: Replay Attack Detected con alerta visual de alta prioridad
 * - Retorna el 'elevated_token' (mfa_verified: true, TTL 10 min) para desbloquear la Bóveda
 */

import React, { useState } from 'react';
import {
  Modal,
  StyleSheet,
  Text,
  View,
  TextInput,
  TouchableOpacity,
  ActivityIndicator,
  KeyboardAvoidingView,
  Platform,
} from 'react-native';
import { API_BASE_URL } from '../services/apiClient';

interface StepUpModalProps {
  visible: boolean;
  stepUpToken: string | null;
  onClose: () => void;
  onSuccess: (elevatedToken: string) => void;
}

export const StepUpModal: React.FC<StepUpModalProps> = ({
  visible,
  stepUpToken,
  onClose,
  onSuccess,
}) => {
  const [code, setCode] = useState<string>('');
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isReplayAttack, setIsReplayAttack] = useState<boolean>(false);

  const handleSubmit = async () => {
    if (!stepUpToken) {
      setErrorMessage('Desafío inválido o expirado. Vuelva a intentar.');
      return;
    }

    const cleanCode = code.replace(/\D/g, '').trim();
    if (cleanCode.length !== 6) {
      setErrorMessage('El código TOTP debe contener exactamente 6 dígitos numéricos.');
      return;
    }

    try {
      setIsSubmitting(true);
      setErrorMessage(null);
      setIsReplayAttack(false);

      console.log(`[Step-Up] Enviando código ${cleanCode} para verificación con Anti-Replay...`);

      const response = await fetch(`${API_BASE_URL}/auth/mfa/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          stepUpToken,
          totpCode: cleanCode,
        }),
      });

      const data = await response.json().catch(() => ({}));

      // ==========================================
      // Caso 1: Ataque de Replay Detectado (HTTP 409)
      // ==========================================
      if (response.status === 409) {
        setIsReplayAttack(true);
        setErrorMessage(
          data.message || 'ATAQUE DE REPLAY DETECTADO: Este código ya fue consumido en la ventana de 90 segundos.'
        );
        return;
      }

      // Caso 2: Código inválido o expirado (HTTP 400 / 401)
      if (!response.ok) {
        setIsReplayAttack(false);
        setErrorMessage(data.message || 'Código TOTP incorrecto o fuera de sincronización.');
        return;
      }

      // Caso 3: Éxito (HTTP 200) -> Emitir elevated_token
      console.log('[Step-Up] Elevación aprobada por el backend.');
      setCode('');
      onSuccess(data.elevated_token);
      onClose();
    } catch (error: any) {
      console.error('[Step-Up Error]', error);
      setErrorMessage('Error de red al verificar el código TOTP.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleModalClose = () => {
    setCode('');
    setErrorMessage(null);
    setIsReplayAttack(false);
    onClose();
  };

  return (
    <Modal
      visible={visible}
      transparent
      animationType="fade"
      onRequestClose={handleModalClose}
    >
      <KeyboardAvoidingView
        behavior={Platform.OS === 'ios' ? 'padding' : 'height'}
        style={styles.overlay}
      >
        <View style={styles.modalCard}>
          {/* Header */}
          <View style={styles.header}>
            <View style={styles.iconCircle}>
              <Text style={styles.iconText}>🛡️</Text>
            </View>
            <Text style={styles.title}>Elevación Step-Up 2FA</Text>
            <Text style={styles.subtitle}>
              El recurso solicitado exige nivel de seguridad superior. Ingrese el código TOTP de su Authenticator.
            </Text>
          </View>

          {/* Banner de Ataque de Replay si ocurre */}
          {isReplayAttack && (
            <View style={styles.replayAlertBox}>
              <Text style={styles.replayAlertTitle}>⚠️ ALERTA DE SEGURIDAD</Text>
              <Text style={styles.replayAlertText}>{errorMessage}</Text>
            </View>
          )}

          {/* Banner de Error Común */}
          {!isReplayAttack && errorMessage && (
            <View style={styles.errorBox}>
              <Text style={styles.errorText}>{errorMessage}</Text>
            </View>
          )}

          {/* Campo de Código TOTP */}
          <View style={styles.inputContainer}>
            <Text style={styles.inputLabel}>Código TOTP RFC 6238 (6 Dígitos):</Text>
            <TextInput
              style={styles.input}
              value={code}
              onChangeText={(text) => {
                setCode(text);
                if (errorMessage) setErrorMessage(null);
              }}
              placeholder="000 000"
              placeholderTextColor="#64748b"
              keyboardType="number-pad"
              maxLength={6}
              autoFocus
              textAlign="center"
            />
          </View>

          <Text style={styles.infoFooter}>
            Tolerancia de ventana: C-1, C, C+1 (±30s). Protegido contra ataques de repetición con TTL de 90 segundos.
          </Text>

          {/* Botones de Acción */}
          <View style={styles.actions}>
            <TouchableOpacity
              style={styles.cancelButton}
              onPress={handleModalClose}
              disabled={isSubmitting}
            >
              <Text style={styles.cancelButtonText}>Cancelar</Text>
            </TouchableOpacity>

            <TouchableOpacity
              style={[styles.verifyButton, isSubmitting && styles.buttonDisabled]}
              onPress={handleSubmit}
              disabled={isSubmitting}
            >
              {isSubmitting ? (
                <ActivityIndicator color="#ffffff" size="small" />
              ) : (
                <Text style={styles.verifyButtonText}>Elevar Privilegios</Text>
              )}
            </TouchableOpacity>
          </View>
        </View>
      </KeyboardAvoidingView>
    </Modal>
  );
};

const styles = StyleSheet.create({
  overlay: {
    flex: 1,
    backgroundColor: 'rgba(0, 0, 0, 0.75)',
    justifyContent: 'center',
    alignItems: 'center',
    padding: 20,
  },
  modalCard: {
    backgroundColor: '#0a2540',
    borderRadius: 18,
    width: '100%',
    maxWidth: 400,
    padding: 24,
    borderWidth: 1.5,
    borderColor: '#1e3a5f',
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 8 },
    shadowOpacity: 0.5,
    shadowRadius: 16,
    elevation: 12,
  },
  header: {
    alignItems: 'center',
    marginBottom: 16,
  },
  iconCircle: {
    width: 56,
    height: 56,
    borderRadius: 28,
    backgroundColor: 'rgba(229, 168, 35, 0.15)',
    borderWidth: 1.5,
    borderColor: '#e5a823',
    justifyContent: 'center',
    alignItems: 'center',
    marginBottom: 12,
  },
  iconText: {
    fontSize: 26,
  },
  title: {
    fontSize: 19,
    fontWeight: 'bold',
    color: '#ffffff',
    textAlign: 'center',
  },
  subtitle: {
    fontSize: 12.5,
    color: '#94a3b8',
    textAlign: 'center',
    marginTop: 6,
    lineHeight: 18,
  },
  replayAlertBox: {
    backgroundColor: 'rgba(220, 38, 38, 0.25)',
    borderLeftWidth: 4,
    borderLeftColor: '#ef4444',
    padding: 12,
    borderRadius: 6,
    marginBottom: 16,
  },
  replayAlertTitle: {
    color: '#f87171',
    fontWeight: 'bold',
    fontSize: 12,
    marginBottom: 2,
    letterSpacing: 0.5,
  },
  replayAlertText: {
    color: '#fca5a5',
    fontSize: 11.5,
    lineHeight: 16,
  },
  errorBox: {
    backgroundColor: 'rgba(239, 68, 68, 0.12)',
    padding: 10,
    borderRadius: 6,
    marginBottom: 14,
    borderWidth: 1,
    borderColor: 'rgba(239, 68, 68, 0.3)',
  },
  errorText: {
    color: '#f87171',
    fontSize: 12,
    textAlign: 'center',
  },
  inputContainer: {
    marginBottom: 12,
  },
  inputLabel: {
    fontSize: 12,
    fontWeight: '600',
    color: '#cbd5e1',
    marginBottom: 8,
    textAlign: 'center',
  },
  input: {
    backgroundColor: '#051829',
    borderWidth: 1.5,
    borderColor: '#0284c7',
    borderRadius: 12,
    paddingVertical: 14,
    paddingHorizontal: 16,
    fontSize: 28,
    fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
    fontWeight: 'bold',
    color: '#38bdf8',
    letterSpacing: 8,
  },
  infoFooter: {
    fontSize: 10.5,
    color: '#64748b',
    textAlign: 'center',
    lineHeight: 14,
    marginBottom: 20,
  },
  actions: {
    flexDirection: 'row',
    gap: 12,
  },
  cancelButton: {
    flex: 1,
    backgroundColor: '#1e293b',
    paddingVertical: 12,
    borderRadius: 8,
    alignItems: 'center',
    borderWidth: 1,
    borderColor: '#334155',
  },
  cancelButtonText: {
    color: '#cbd5e1',
    fontSize: 14,
    fontWeight: '600',
  },
  verifyButton: {
    flex: 1.4,
    backgroundColor: '#e5a823',
    paddingVertical: 12,
    borderRadius: 8,
    alignItems: 'center',
  },
  buttonDisabled: {
    backgroundColor: '#64748b',
  },
  verifyButtonText: {
    color: '#001a33',
    fontSize: 14,
    fontWeight: 'bold',
  },
});

