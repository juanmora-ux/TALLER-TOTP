/**
 * VaultScreen.tsx
 * 
 * Pantalla de Bóveda Crítica con Step-Up Authentication (2FA)
 * 
 * Arquitectura de Seguridad:
 * 1. Acceso Inicial: La app envía el 'access_token' estándar (mfa_verified: false).
 * 2. Desafío 403 Forbidden: El backend rechaza el acceso y emite un 'stepUpToken'.
 * 3. Apertura Automática de StepUpModal: El usuario proporciona el código TOTP RFC 6238.
 * 4. Elevación de Privilegios: Al verificarse con éxito, se almacena temporalmente
 *    el 'elevated_token' (mfa_verified: true, TTL 10 min) y se desbloquea la Bóveda.
 */

import React, { useState } from 'react';
import {
  StyleSheet,
  Text,
  View,
  TouchableOpacity,
  ScrollView,
  SafeAreaView,
  ActivityIndicator,
  Alert,
  Platform,
} from 'react-native';
import { useAuth } from '../context/AuthContext';
import { secureFetch } from '../services/apiClient';
import { VaultResponse, VaultConfidentialData, StepUpChallengeResponse } from '../types/auth';
import { StepUpModal } from '../components/StepUpModal';

export const VaultScreen: React.FC = () => {
  const { user, logout, elevatedToken, setElevatedToken } = useAuth();

  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [vaultData, setVaultData] = useState<VaultConfidentialData | null>(null);
  const [stepUpModalVisible, setStepUpModalVisible] = useState<boolean>(false);
  const [currentStepUpToken, setCurrentStepUpToken] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  /**
   * Intenta acceder al endpoint de Bóveda Crítica
   */
  const handleAccessVault = async () => {
    try {
      setIsLoading(true);
      setErrorMessage(null);

      console.log('[Vault] Solicitando acceso a /api/boveda-critica...');

      const response = await secureFetch<VaultResponse | StepUpChallengeResponse>(
        '/api/boveda-critica',
        { method: 'GET' }
      );

      // ==========================================
      // Caso 1: Desafío Step-Up 403 Forbidden
      // ==========================================
      if (response.status === 403) {
        const challenge = response.data as StepUpChallengeResponse;
        console.warn('[Vault] 403 Forbidden capturado. Se requiere desafío Step-Up.');

        if (challenge.stepUpToken) {
          setCurrentStepUpToken(challenge.stepUpToken);
          setStepUpModalVisible(true);
        } else {
          setErrorMessage('El servidor no proporcionó un stepUpToken válido.');
        }
        return;
      }

      // ==========================================
      // Caso 2: Autorizado 200 OK (MFA Elevado)
      // ==========================================
      if (response.status === 200) {
        const successData = response.data as VaultResponse;
        console.log('[Vault] Bóveda desbloqueada con éxito.');
        setVaultData(successData.vaultData);
        return;
      }

      // Otros errores
      setErrorMessage(`Error inesperado del servidor: HTTP ${response.status}`);
    } catch (err: any) {
      console.error('[Vault Error]', err);
      setErrorMessage(err.message || 'Error de comunicación con el enclave de bóveda.');
    } finally {
      setIsLoading(false);
    }
  };

  /**
   * Callback ejecutado cuando el usuario supera exitosamente el desafío TOTP en el StepUpModal
   */
  const handleStepUpSuccess = (newElevatedToken: string) => {
    console.log('[Vault] Step-Up exitoso. Registrando elevated_token en memoria...');
    setElevatedToken(newElevatedToken);

    // Reintentar de inmediato el acceso a la bóveda con los privilegios elevados
    setTimeout(() => {
      handleAccessVault();
    }, 300);
  };

  /**
   * Revoca la elevación de privilegios para permitir al usuario probar el flujo nuevamente
   */
  const handleRevokeElevation = () => {
    setElevatedToken(null);
    setVaultData(null);
    Alert.alert('Privilegios Revocados', 'Se eliminó el elevated_token. El acceso volverá a solicitar TOTP.');
  };

  return (
    <SafeAreaView style={styles.container}>
      <ScrollView contentContainerStyle={styles.scrollContent}>
        {/* Encabezado de Sesión */}
        <View style={styles.sessionHeader}>
          <View>
            <Text style={styles.welcomeText}>Sesión Activa:</Text>
            <Text style={styles.userName}>{user?.name || 'Estudiante Unisabana'}</Text>
            <Text style={styles.userEmail}>{user?.email || 'estudiante@unisabana.edu.co'}</Text>
          </View>
          <TouchableOpacity style={styles.logoutButton} onPress={logout}>
            <Text style={styles.logoutButtonText}>Cerrar Sesión</Text>
          </TouchableOpacity>
        </View>

        {/* Estado de Seguridad Actual */}
        <View style={styles.securityStatusCard}>
          <Text style={styles.securityStatusTitle}>Estado de Privilegios de Seguridad</Text>
          <View style={styles.statusPillRow}>
            <View
              style={[
                styles.statusPill,
                elevatedToken ? styles.statusPillElevated : styles.statusPillStandard,
              ]}
            >
              <Text
                style={[
                  styles.statusPillText,
                  elevatedToken ? styles.statusTextElevated : styles.statusTextStandard,
                ]}
              >
                {elevatedToken ? '🛡️ NIVEL 2: 2FA STEP-UP ELEVADO' : '🔒 NIVEL 1: OAUTH 2.0 ESTÁNDAR'}
              </Text>
            </View>
          </View>
          <Text style={styles.securityDesc}>
            {elevatedToken
              ? 'Credencial elevada en memoria RAM (TTL 10m). Acceso autorizado a información confidencial.'
              : 'El acceso a expedientes clasificados y llaves maestras requiere elevación criptográfica TOTP.'}
          </Text>

          {elevatedToken && (
            <TouchableOpacity style={styles.revokeButton} onPress={handleRevokeElevation}>
              <Text style={styles.revokeButtonText}>↺ Revocar Elevación (Probar Desafío de Nuevo)</Text>
            </TouchableOpacity>
          )}
        </View>

        {/* Mensaje de Error si lo hay */}
        {errorMessage && (
          <View style={styles.errorCard}>
            <Text style={styles.errorCardText}>{errorMessage}</Text>
          </View>
        )}

        {/* Botón de Petición a Bóveda */}
        {!vaultData && (
          <View style={styles.actionCard}>
            <Text style={styles.actionCardTitle}>Bóveda Crítica Institucional</Text>
            <Text style={styles.actionCardDesc}>
              Presione el botón para consultar el recurso protegido. Si su sesión no ha sido elevada con
              TOTP, el backend responderá con HTTP 403 y se iniciará el Step-Up automático.
            </Text>

            <TouchableOpacity
              style={[styles.unlockButton, isLoading && styles.buttonDisabled]}
              onPress={handleAccessVault}
              disabled={isLoading}
              activeOpacity={0.8}
            >
              {isLoading ? (
                <ActivityIndicator color="#001a33" />
              ) : (
                <Text style={styles.unlockButtonText}>Desbloquear Bóveda Crítica</Text>
              )}
            </TouchableOpacity>
          </View>
        )}

        {/* Visualización de Datos Confidenciales Desbloqueados */}
        {vaultData && (
          <View style={styles.vaultUnlockedCard}>
            <View style={styles.vaultHeader}>
              <Text style={styles.vaultBadge}>CONFIDENCIAL // NIVEL 4</Text>
              <Text style={styles.vaultTitle}>Expediente Criptográfico Desbloqueado</Text>
              <Text style={styles.vaultTimestamp}>Autorizado: {vaultData.authorizedAt}</Text>
            </View>

            <View style={styles.dataSection}>
              <Text style={styles.sectionHeader}>DATOS ACADÉMICOS Y FINANCIEROS</Text>
              <View style={styles.dataRow}>
                <Text style={styles.dataLabel}>ID Estudiante:</Text>
                <Text style={styles.dataValue}>{vaultData.studentId}</Text>
              </View>
              <View style={styles.dataRow}>
                <Text style={styles.dataLabel}>Calificaciones:</Text>
                <Text style={styles.dataValue}>{vaultData.academicRecords}</Text>
              </View>
              <View style={styles.dataRow}>
                <Text style={styles.dataLabel}>Financiero:</Text>
                <Text style={styles.dataValue}>{vaultData.financialStatus}</Text>
              </View>
            </View>

            <View style={styles.dataSection}>
              <Text style={styles.sectionHeader}>LLAVES MAESTRAS DEL ENCLAVE</Text>
              <View style={styles.keyBox}>
                <Text style={styles.keyLabel}>Master Seed Vault:</Text>
                <Text style={styles.keyValue}>{vaultData.cryptographicKeys.masterSeedVault}</Text>
              </View>
              <View style={styles.keyBox}>
                <Text style={styles.keyLabel}>HSM Enclave Signature:</Text>
                <Text style={styles.keyValue}>{vaultData.cryptographicKeys.hsmEnclaveSignature}</Text>
              </View>
            </View>

            <View style={styles.dataSection}>
              <Text style={styles.sectionHeader}>DOCUMENTOS CIFRADOS EN CUSTODIA</Text>
              {vaultData.confidentialDocuments.map((doc, idx) => (
                <View key={idx} style={styles.docItem}>
                  <Text style={styles.docIcon}>📄</Text>
                  <View style={{ flex: 1 }}>
                    <Text style={styles.docName}>{doc.name}</Text>
                    <Text style={styles.docHash}>MD5: {doc.hash} ({doc.size})</Text>
                  </View>
                </View>
              ))}
            </View>

            <TouchableOpacity
              style={styles.lockAgainButton}
              onPress={() => setVaultData(null)}
            >
              <Text style={styles.lockAgainButtonText}>Ocultar Información Confidencial</Text>
            </TouchableOpacity>
          </View>
        )}
      </ScrollView>

      {/* Modal Desafío Step-Up */}
      <StepUpModal
        visible={stepUpModalVisible}
        stepUpToken={currentStepUpToken}
        onClose={() => setStepUpModalVisible(false)}
        onSuccess={handleStepUpSuccess}
      />
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#001a33',
  },
  scrollContent: {
    padding: 20,
    paddingBottom: 40,
  },
  sessionHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    backgroundColor: '#0a2540',
    padding: 16,
    borderRadius: 14,
    borderWidth: 1,
    borderColor: '#1e3a5f',
    marginBottom: 16,
  },
  welcomeText: {
    fontSize: 11,
    color: '#94a3b8',
    textTransform: 'uppercase',
  },
  userName: {
    fontSize: 15,
    fontWeight: 'bold',
    color: '#ffffff',
  },
  userEmail: {
    fontSize: 12,
    color: '#38bdf8',
  },
  logoutButton: {
    backgroundColor: '#ef4444',
    paddingHorizontal: 12,
    paddingVertical: 8,
    borderRadius: 8,
  },
  logoutButtonText: {
    color: '#ffffff',
    fontSize: 11.5,
    fontWeight: 'bold',
  },
  securityStatusCard: {
    backgroundColor: '#0a2540',
    borderRadius: 14,
    padding: 16,
    borderWidth: 1,
    borderColor: '#1e3a5f',
    marginBottom: 16,
  },
  securityStatusTitle: {
    fontSize: 13,
    fontWeight: 'bold',
    color: '#cbd5e1',
    marginBottom: 8,
  },
  statusPillRow: {
    marginBottom: 8,
  },
  statusPill: {
    paddingHorizontal: 10,
    paddingVertical: 5,
    borderRadius: 20,
    alignSelf: 'flex-start',
    borderWidth: 1,
  },
  statusPillStandard: {
    backgroundColor: 'rgba(56, 189, 248, 0.1)',
    borderColor: '#38bdf8',
  },
  statusPillElevated: {
    backgroundColor: 'rgba(16, 185, 129, 0.15)',
    borderColor: '#10b981',
  },
  statusPillText: {
    fontSize: 11,
    fontWeight: 'bold',
    letterSpacing: 0.5,
  },
  statusTextStandard: {
    color: '#38bdf8',
  },
  statusTextElevated: {
    color: '#10b981',
  },
  securityDesc: {
    fontSize: 12,
    color: '#94a3b8',
    lineHeight: 16,
  },
  revokeButton: {
    marginTop: 10,
    paddingVertical: 6,
    alignItems: 'center',
    backgroundColor: 'rgba(239, 68, 68, 0.1)',
    borderRadius: 6,
    borderWidth: 1,
    borderColor: 'rgba(239, 68, 68, 0.3)',
  },
  revokeButtonText: {
    color: '#f87171',
    fontSize: 11,
    fontWeight: '600',
  },
  errorCard: {
    backgroundColor: 'rgba(239, 68, 68, 0.15)',
    padding: 12,
    borderRadius: 8,
    borderLeftWidth: 4,
    borderLeftColor: '#ef4444',
    marginBottom: 16,
  },
  errorCardText: {
    color: '#fca5a5',
    fontSize: 12,
  },
  actionCard: {
    backgroundColor: '#0a2540',
    borderRadius: 16,
    padding: 20,
    borderWidth: 1,
    borderColor: '#1e3a5f',
    alignItems: 'center',
  },
  actionCardTitle: {
    fontSize: 17,
    fontWeight: 'bold',
    color: '#ffffff',
    marginBottom: 6,
  },
  actionCardDesc: {
    fontSize: 12.5,
    color: '#94a3b8',
    textAlign: 'center',
    lineHeight: 18,
    marginBottom: 20,
  },
  unlockButton: {
    backgroundColor: '#e5a823',
    width: '100%',
    paddingVertical: 14,
    borderRadius: 10,
    alignItems: 'center',
  },
  buttonDisabled: {
    backgroundColor: '#64748b',
  },
  unlockButtonText: {
    color: '#001a33',
    fontSize: 15,
    fontWeight: 'bold',
    letterSpacing: 0.5,
  },
  vaultUnlockedCard: {
    backgroundColor: '#051829',
    borderRadius: 16,
    padding: 18,
    borderWidth: 1.5,
    borderColor: '#10b981',
  },
  vaultHeader: {
    borderBottomWidth: 1,
    borderBottomColor: '#163354',
    paddingBottom: 12,
    marginBottom: 14,
  },
  vaultBadge: {
    color: '#10b981',
    fontSize: 10,
    fontWeight: 'bold',
    letterSpacing: 1,
    marginBottom: 4,
  },
  vaultTitle: {
    fontSize: 17,
    fontWeight: 'bold',
    color: '#ffffff',
  },
  vaultTimestamp: {
    fontSize: 11,
    color: '#64748b',
    marginTop: 2,
  },
  dataSection: {
    marginBottom: 16,
  },
  sectionHeader: {
    fontSize: 11,
    fontWeight: 'bold',
    color: '#38bdf8',
    letterSpacing: 0.8,
    marginBottom: 8,
  },
  dataRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    paddingVertical: 4,
    borderBottomWidth: 1,
    borderBottomColor: '#0e243d',
  },
  dataLabel: {
    fontSize: 12,
    color: '#94a3b8',
  },
  dataValue: {
    fontSize: 12,
    color: '#f8fafc',
    fontWeight: '500',
    flexShrink: 1,
    textAlign: 'right',
  },
  keyBox: {
    backgroundColor: '#0a2540',
    padding: 8,
    borderRadius: 6,
    marginBottom: 6,
  },
  keyLabel: {
    fontSize: 10,
    color: '#94a3b8',
    marginBottom: 2,
  },
  keyValue: {
    fontSize: 11,
    fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
    color: '#e5a823',
  },
  docItem: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: '#0a2540',
    padding: 10,
    borderRadius: 8,
    marginBottom: 6,
    gap: 10,
  },
  docIcon: {
    fontSize: 18,
  },
  docName: {
    fontSize: 12,
    fontWeight: '600',
    color: '#f1f5f9',
  },
  docHash: {
    fontSize: 10,
    color: '#64748b',
  },
  lockAgainButton: {
    marginTop: 8,
    backgroundColor: '#1e293b',
    borderWidth: 1,
    borderColor: '#334155',
    paddingVertical: 10,
    borderRadius: 8,
    alignItems: 'center',
  },
  lockAgainButtonText: {
    color: '#cbd5e1',
    fontSize: 12,
    fontWeight: '600',
  },
});

