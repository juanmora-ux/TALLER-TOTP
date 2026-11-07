/**
 * AuthenticatorScreen.tsx
 * 
 * Pantalla de Generador TOTP RFC 6238 en Modo Avión (100% Offline)
 * 
 * Características:
 * 1. Tipografía monoespaciada grande con espaciado 3-3 (ej. "482 193").
 * 2. Temporizador circular / indicador regresivo de 30 a 0 segundos con auto-refresh.
 * 3. Lector QR con expo-camera para URIs otpauth://.
 * 4. Ingesta manual de semilla Base32 validada con RFC 4648.
 * 5. Cero peticiones de red para la generación de claves OTP.
 */

import React, { useState, useEffect, useRef } from 'react';
import {
  StyleSheet,
  Text,
  View,
  TouchableOpacity,
  TextInput,
  ScrollView,
  SafeAreaView,
  Platform,
  Alert,
  Modal,
} from 'react-native';
import { CameraView, useCameraPermissions } from 'expo-camera';
import {
  generateTOTP,
  getRemainingSeconds,
  parseOtpAuthUri,
} from '../utils/totpEngine';
import { isValidBase32 } from '../utils/base32';
import {
  saveTOTPSecret,
  getTOTPSecret,
  saveTOTPMetadata,
  getTOTPMetadata,
} from '../services/secureStorage';

// Semilla estándar de demostración académica (RFC 6238 Test Vector compatible)
const DEFAULT_LAB_SECRET = 'JBSWY3DPEHPK3PXP';

export const AuthenticatorScreen: React.FC = () => {
  const [secret, setSecret] = useState<string>(DEFAULT_LAB_SECRET);
  const [accountName, setAccountName] = useState<string>('estudiante@unisabana.edu.co');
  const [issuer, setIssuer] = useState<string>('Unisabana');
  const [totpCode, setTotpCode] = useState<string>('------');
  const [remainingSeconds, setRemainingSeconds] = useState<number>(30);
  const [isCopied, setIsCopied] = useState<boolean>(false);

  // Estados de entrada manual y cámara QR
  const [manualSecretInput, setManualSecretInput] = useState<string>('');
  const [manualAccountInput, setManualAccountInput] = useState<string>('');
  const [showManualModal, setShowManualModal] = useState<boolean>(false);
  const [showCameraModal, setShowCameraModal] = useState<boolean>(false);
  const [cameraPermission, requestCameraPermission] = useCameraPermissions();
  const [scanned, setScanned] = useState<boolean>(false);

  // Cargar semilla desde Enclave Seguro al inicializar
  useEffect(() => {
    const loadStoredSecret = async () => {
      try {
        const storedSecret = await getTOTPSecret();
        const storedMeta = await getTOTPMetadata<{ account?: string; issuer?: string }>();
        if (storedSecret && isValidBase32(storedSecret)) {
          setSecret(storedSecret);
          if (storedMeta?.account) setAccountName(storedMeta.account);
          if (storedMeta?.issuer) setIssuer(storedMeta.issuer);
        }
      } catch (err) {
        console.error('[Authenticator] Error al cargar semilla desde SecureStore:', err);
      }
    };
    loadStoredSecret();
  }, []);

  // Reloj de rotación de 30 segundos (RFC 6238)
  useEffect(() => {
    const updateCode = () => {
      try {
        if (isValidBase32(secret)) {
          const code = generateTOTP(secret);
          setTotpCode(code);
        } else {
          setTotpCode('ERR-32');
        }
      } catch (e) {
        setTotpCode('ERROR');
      }
    };

    // Actualización inmediata
    updateCode();
    setRemainingSeconds(getRemainingSeconds(30));

    const interval = setInterval(() => {
      const remaining = getRemainingSeconds(30);
      setRemainingSeconds(remaining);

      // Si el temporizador llega a 30 (nuevo ciclo), recalcular el código TOTP
      if (remaining === 30 || remaining === 29) {
        updateCode();
      }
    }, 1000);

    return () => clearInterval(interval);
  }, [secret]);

  // Guardar nueva semilla en SecureStore
  const applyNewSecret = async (newSecret: string, accName?: string, issName?: string) => {
    const clean = newSecret.toUpperCase().replace(/[\s\-=]/g, '');
    if (!isValidBase32(clean)) {
      Alert.alert('Error Criptográfico', 'La clave ingresada no es una semilla Base32 válida (RFC 4648).');
      return;
    }

    setSecret(clean);
    if (accName) setAccountName(accName);
    if (issName) setIssuer(issName);

    await saveTOTPSecret(clean);
    await saveTOTPMetadata({ account: accName || accountName, issuer: issName || issuer });

    try {
      const newOtp = generateTOTP(clean);
      setTotpCode(newOtp);
    } catch {
      // Ignorar error transitorio
    }

    Alert.alert('Éxito', 'Semilla TOTP configurada y guardada en el enclave seguro.');
  };

  // Manejador del escaneo QR
  const handleBarCodeScanned = ({ data }: { data: string }) => {
    if (scanned) return;
    setScanned(true);

    try {
      const parsed = parseOtpAuthUri(data);
      applyNewSecret(parsed.secret, parsed.account, parsed.issuer);
      setShowCameraModal(false);
    } catch (err: any) {
      Alert.alert('QR Inválido', err.message || 'El código escaneado no es un URI otpauth:// compatible.');
    } finally {
      setTimeout(() => setScanned(false), 2000);
    }
  };

  const handleOpenScanner = async () => {
    if (!cameraPermission?.granted) {
      const res = await requestCameraPermission();
      if (!res.granted) {
        Alert.alert('Permiso Denegado', 'Se requiere acceso a la cámara para escanear el código QR de 2FA.');
        return;
      }
    }
    setScanned(false);
    setShowCameraModal(true);
  };

  const formattedCode =
    totpCode.length === 6 ? `${totpCode.slice(0, 3)} ${totpCode.slice(3, 6)}` : totpCode;

  // Color dinámico según la urgencia de expiración
  const timerColor = remainingSeconds <= 5 ? '#ef4444' : remainingSeconds <= 10 ? '#eab308' : '#10b981';
  const timerPercentage = (remainingSeconds / 30) * 100;

  return (
    <SafeAreaView style={styles.container}>
      <ScrollView contentContainerStyle={styles.scrollContent}>
        {/* Encabezado */}
        <View style={styles.header}>
          <View style={styles.offlineBadge}>
            <Text style={styles.offlineBadgeText}>✈️ MODO AVIÓN (100% OFFLINE)</Text>
          </View>
          <Text style={styles.headerTitle}>Unisabana Authenticator</Text>
          <Text style={styles.headerSubtitle}>Motor Criptográfico Nativo RFC 6238</Text>
        </View>

        {/* Tarjeta Principal del Token */}
        <View style={styles.tokenCard}>
          <View style={styles.accountRow}>
            <View>
              <Text style={styles.issuerText}>{issuer.toUpperCase()}</Text>
              <Text style={styles.accountText}>{accountName}</Text>
            </View>
            <View style={[styles.timerBadge, { borderColor: timerColor }]}>
              <Text style={[styles.timerText, { color: timerColor }]}>{remainingSeconds}s</Text>
            </View>
          </View>

          {/* Barra de progreso visual regresiva */}
          <View style={styles.progressTrack}>
            <View
              style={[
                styles.progressBar,
                { width: `${timerPercentage}%`, backgroundColor: timerColor },
              ]}
            />
          </View>

          {/* Código TOTP en Tipografía Monoespaciada Grande */}
          <View style={styles.codeContainer}>
            <Text style={styles.totpText}>{formattedCode}</Text>
          </View>

          {/* Semilla activa enmascarada */}
          <View style={styles.secretInfoRow}>
            <Text style={styles.secretInfoLabel}>Semilla Base32:</Text>
            <Text style={styles.secretInfoValue}>
              {secret.slice(0, 4)}••••••••{secret.slice(-4)}
            </Text>
          </View>

          {/* Botón rápido de copia informativa */}
          <TouchableOpacity
            style={styles.copyButton}
            onPress={() => {
              setIsCopied(true);
              setTimeout(() => setIsCopied(false), 2000);
            }}
          >
            <Text style={styles.copyButtonText}>
              {isCopied ? '✓ Código Listo para Step-Up' : '📋 Usar en Desafío 2FA'}
            </Text>
          </TouchableOpacity>
        </View>

        {/* Sección de Gestión de Semillas */}
        <View style={styles.configCard}>
          <Text style={styles.configTitle}>Configuración de Semilla Criptográfica</Text>
          <Text style={styles.configDesc}>
            Vincule su cuenta escaneando el código QR institucional o ingrese manualmente la clave secreta Base32.
          </Text>

          <View style={styles.actionButtonsRow}>
            <TouchableOpacity
              style={styles.qrButton}
              onPress={handleOpenScanner}
              activeOpacity={0.8}
            >
              <Text style={styles.buttonIcon}>📷</Text>
              <Text style={styles.qrButtonText}>Escanear QR</Text>
            </TouchableOpacity>

            <TouchableOpacity
              style={styles.manualButton}
              onPress={() => setShowManualModal(true)}
              activeOpacity={0.8}
            >
              <Text style={styles.buttonIcon}>⌨️</Text>
              <Text style={styles.manualButtonText}>Ingreso Manual</Text>
            </TouchableOpacity>
          </View>

          {/* Botón de restablecimiento rápido para laboratorio */}
          <TouchableOpacity
            style={styles.resetLabButton}
            onPress={() => applyNewSecret(DEFAULT_LAB_SECRET, 'estudiante@unisabana.edu.co', 'Unisabana')}
          >
            <Text style={styles.resetLabButtonText}>Cargar Semilla Demo Docente (JBSWY3DPEHPK3PXP)</Text>
          </TouchableOpacity>
        </View>

        {/* Detalles Técnicos de la Implementación */}
        <View style={styles.techDetailsBox}>
          <Text style={styles.techTitle}>Cumplimiento Estricto de Regla Inviolable:</Text>
          <Text style={styles.techText}>• Algoritmo de Hashing: HMAC-SHA1 implementado desde cero</Text>
          <Text style={styles.techText}>• Decodificación: Base32 RFC 4648 pura en TypeScript</Text>
          <Text style={styles.techText}>• Ventana de Rotación: X = 30 segundos, T0 = 0</Text>
          <Text style={styles.techText}>• Truncamiento: Dynamic Truncation RFC 4226 sección 5.4</Text>
          <Text style={styles.techText}>• Dependencias externas TOTP: 0 (Cero)</Text>
        </View>
      </ScrollView>

      {/* Modal de Entrada Manual Base32 */}
      <Modal visible={showManualModal} transparent animationType="slide">
        <View style={styles.modalOverlay}>
          <View style={styles.modalContent}>
            <Text style={styles.modalTitle}>Ingreso Manual de Semilla</Text>
            <Text style={styles.modalSubtitle}>
              Introduzca la clave alfanumérica Base32 (alfabeto A-Z, 2-7).
            </Text>

            <Text style={styles.fieldLabel}>Nombre de Cuenta:</Text>
            <TextInput
              style={styles.textInput}
              placeholder="estudiante@unisabana.edu.co"
              placeholderTextColor="#64748b"
              value={manualAccountInput}
              onChangeText={setManualAccountInput}
            />

            <Text style={styles.fieldLabel}>Semilla Base32:</Text>
            <TextInput
              style={[styles.textInput, styles.fontMono]}
              placeholder="EJ: JBSWY3DPEHPK3PXP"
              placeholderTextColor="#64748b"
              value={manualSecretInput}
              onChangeText={setManualSecretInput}
              autoCapitalize="characters"
              autoCorrect={false}
            />

            <View style={styles.modalActions}>
              <TouchableOpacity
                style={styles.modalCancel}
                onPress={() => setShowManualModal(false)}
              >
                <Text style={styles.modalCancelText}>Cancelar</Text>
              </TouchableOpacity>
              <TouchableOpacity
                style={styles.modalSubmit}
                onPress={() => {
                  if (!manualSecretInput) {
                    Alert.alert('Error', 'Ingrese una semilla Base32.');
                    return;
                  }
                  applyNewSecret(manualSecretInput, manualAccountInput || 'Usuario Unisabana', 'Unisabana');
                  setShowManualModal(false);
                  setManualSecretInput('');
                  setManualAccountInput('');
                }}
              >
                <Text style={styles.modalSubmitText}>Guardar Semilla</Text>
              </TouchableOpacity>
            </View>
          </View>
        </View>
      </Modal>

      {/* Modal de Escáner QR de Cámara */}
      <Modal visible={showCameraModal} animationType="slide">
        <SafeAreaView style={styles.cameraContainer}>
          <View style={styles.cameraHeader}>
            <Text style={styles.cameraHeaderTitle}>Escanear Código QR 2FA</Text>
            <TouchableOpacity
              style={styles.closeCameraBtn}
              onPress={() => setShowCameraModal(false)}
            >
              <Text style={styles.closeCameraBtnText}>Cerrar</Text>
            </TouchableOpacity>
          </View>

          <View style={styles.cameraWrapper}>
            <CameraView
              style={StyleSheet.absoluteFillObject}
              onBarcodeScanned={scanned ? undefined : handleBarCodeScanned}
              barcodeScannerSettings={{
                barcodeTypes: ['qr'],
              }}
            />
            {/* Marco visual para guiar el enfoque */}
            <View style={styles.targetFrame} />
          </View>

          <View style={styles.cameraFooter}>
            <Text style={styles.cameraFooterText}>
              Apunte la cámara al código QR provisto por el servidor Unisabana (URI otpauth://totp/...).
            </Text>
          </View>
        </SafeAreaView>
      </Modal>
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
  header: {
    alignItems: 'center',
    marginBottom: 20,
  },
  offlineBadge: {
    backgroundColor: 'rgba(16, 185, 129, 0.15)',
    paddingHorizontal: 12,
    paddingVertical: 4,
    borderRadius: 20,
    borderWidth: 1,
    borderColor: '#10b981',
    marginBottom: 8,
  },
  offlineBadgeText: {
    color: '#10b981',
    fontSize: 11,
    fontWeight: '700',
    letterSpacing: 0.5,
  },
  headerTitle: {
    fontSize: 22,
    fontWeight: 'bold',
    color: '#ffffff',
  },
  headerSubtitle: {
    fontSize: 13,
    color: '#94a3b8',
    marginTop: 2,
  },
  tokenCard: {
    backgroundColor: '#0a2540',
    borderRadius: 18,
    padding: 20,
    borderWidth: 1.5,
    borderColor: '#1e3a5f',
    marginBottom: 20,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 6 },
    shadowOpacity: 0.4,
    shadowRadius: 10,
    elevation: 8,
  },
  accountRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 12,
  },
  issuerText: {
    fontSize: 12,
    fontWeight: 'bold',
    color: '#e5a823',
    letterSpacing: 1,
  },
  accountText: {
    fontSize: 14,
    color: '#cbd5e1',
    fontWeight: '500',
    marginTop: 2,
  },
  timerBadge: {
    width: 44,
    height: 44,
    borderRadius: 22,
    borderWidth: 2.5,
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: 'rgba(0,0,0,0.2)',
  },
  timerText: {
    fontSize: 14,
    fontWeight: 'bold',
    fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
  },
  progressTrack: {
    height: 4,
    backgroundColor: '#163354',
    borderRadius: 2,
    overflow: 'hidden',
    marginBottom: 20,
  },
  progressBar: {
    height: '100%',
    borderRadius: 2,
  },
  codeContainer: {
    backgroundColor: '#051829',
    borderRadius: 12,
    paddingVertical: 18,
    alignItems: 'center',
    borderWidth: 1,
    borderColor: '#0284c7',
    marginBottom: 16,
  },
  totpText: {
    fontSize: 42,
    fontWeight: 'bold',
    color: '#38bdf8',
    fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
    letterSpacing: 6,
  },
  secretInfoRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    paddingVertical: 6,
    borderTopWidth: 1,
    borderTopColor: '#163354',
    marginBottom: 14,
  },
  secretInfoLabel: {
    fontSize: 11,
    color: '#64748b',
  },
  secretInfoValue: {
    fontSize: 11,
    fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
    color: '#94a3b8',
  },
  copyButton: {
    backgroundColor: '#0284c7',
    borderRadius: 8,
    paddingVertical: 10,
    alignItems: 'center',
  },
  copyButtonText: {
    color: '#ffffff',
    fontSize: 13,
    fontWeight: '600',
  },
  configCard: {
    backgroundColor: '#0a2540',
    borderRadius: 16,
    padding: 18,
    borderWidth: 1,
    borderColor: '#1e3a5f',
    marginBottom: 20,
  },
  configTitle: {
    fontSize: 15,
    fontWeight: '700',
    color: '#ffffff',
    marginBottom: 6,
  },
  configDesc: {
    fontSize: 12,
    color: '#94a3b8',
    lineHeight: 16,
    marginBottom: 16,
  },
  actionButtonsRow: {
    flexDirection: 'row',
    gap: 12,
    marginBottom: 12,
  },
  qrButton: {
    flex: 1,
    backgroundColor: '#0369a1',
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    paddingVertical: 12,
    borderRadius: 8,
    gap: 8,
  },
  qrButtonText: {
    color: '#ffffff',
    fontSize: 13,
    fontWeight: '600',
  },
  manualButton: {
    flex: 1,
    backgroundColor: '#1e293b',
    borderWidth: 1,
    borderColor: '#334155',
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    paddingVertical: 12,
    borderRadius: 8,
    gap: 8,
  },
  manualButtonText: {
    color: '#cbd5e1',
    fontSize: 13,
    fontWeight: '600',
  },
  buttonIcon: {
    fontSize: 16,
  },
  resetLabButton: {
    backgroundColor: 'rgba(229, 168, 35, 0.1)',
    borderWidth: 1,
    borderColor: 'rgba(229, 168, 35, 0.4)',
    borderRadius: 8,
    paddingVertical: 10,
    alignItems: 'center',
  },
  resetLabButtonText: {
    color: '#e5a823',
    fontSize: 11.5,
    fontWeight: '600',
  },
  techDetailsBox: {
    backgroundColor: '#051829',
    borderRadius: 12,
    padding: 14,
    borderWidth: 1,
    borderColor: '#163354',
  },
  techTitle: {
    fontSize: 12,
    fontWeight: 'bold',
    color: '#38bdf8',
    marginBottom: 6,
  },
  techText: {
    fontSize: 11,
    color: '#94a3b8',
    lineHeight: 16,
  },
  modalOverlay: {
    flex: 1,
    backgroundColor: 'rgba(0,0,0,0.8)',
    justifyContent: 'center',
    padding: 20,
  },
  modalContent: {
    backgroundColor: '#0a2540',
    borderRadius: 16,
    padding: 20,
    borderWidth: 1.5,
    borderColor: '#1e3a5f',
  },
  modalTitle: {
    fontSize: 18,
    fontWeight: 'bold',
    color: '#ffffff',
    marginBottom: 6,
  },
  modalSubtitle: {
    fontSize: 12,
    color: '#94a3b8',
    marginBottom: 16,
    lineHeight: 16,
  },
  fieldLabel: {
    fontSize: 12,
    color: '#cbd5e1',
    marginBottom: 4,
  },
  textInput: {
    backgroundColor: '#051829',
    borderWidth: 1,
    borderColor: '#334155',
    borderRadius: 8,
    paddingHorizontal: 12,
    paddingVertical: 10,
    color: '#ffffff',
    fontSize: 14,
    marginBottom: 14,
  },
  fontMono: {
    fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
    letterSpacing: 1,
  },
  modalActions: {
    flexDirection: 'row',
    gap: 12,
    marginTop: 6,
  },
  modalCancel: {
    flex: 1,
    backgroundColor: '#1e293b',
    paddingVertical: 12,
    borderRadius: 8,
    alignItems: 'center',
  },
  modalCancelText: {
    color: '#94a3b8',
    fontWeight: '600',
  },
  modalSubmit: {
    flex: 1.5,
    backgroundColor: '#0284c7',
    paddingVertical: 12,
    borderRadius: 8,
    alignItems: 'center',
  },
  modalSubmitText: {
    color: '#ffffff',
    fontWeight: 'bold',
  },
  cameraContainer: {
    flex: 1,
    backgroundColor: '#000000',
  },
  cameraHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: 20,
    backgroundColor: 'rgba(0,0,0,0.6)',
  },
  cameraHeaderTitle: {
    color: '#ffffff',
    fontSize: 16,
    fontWeight: 'bold',
  },
  closeCameraBtn: {
    backgroundColor: '#ef4444',
    paddingHorizontal: 14,
    paddingVertical: 6,
    borderRadius: 6,
  },
  closeCameraBtnText: {
    color: '#ffffff',
    fontWeight: 'bold',
  },
  cameraWrapper: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
  },
  targetFrame: {
    width: 250,
    height: 250,
    borderWidth: 2,
    borderColor: '#38bdf8',
    borderRadius: 16,
    backgroundColor: 'transparent',
  },
  cameraFooter: {
    padding: 20,
    backgroundColor: 'rgba(0,0,0,0.6)',
    alignItems: 'center',
  },
  cameraFooterText: {
    color: '#cbd5e1',
    fontSize: 13,
    textAlign: 'center',
  },
});

