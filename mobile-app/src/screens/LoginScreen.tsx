/**
 * LoginScreen.tsx
 * 
 * Pantalla de Inicio de Sesión OAuth 2.0 con PKCE (RFC 7636)
 * Abre el navegador del sistema mediante ASWebAuthenticationSession / Custom Tabs
 * para prevenir ataques de interceptación y robo de credenciales en WebViews embebidas.
 */

import React from 'react';
import {
  StyleSheet,
  Text,
  View,
  TouchableOpacity,
  ActivityIndicator,
  ScrollView,
  SafeAreaView,
  StatusBar,
} from 'react-native';
import { useAuth } from '../context/AuthContext';

export const LoginScreen: React.FC = () => {
  const { loginWithPKCE, isLoading } = useAuth();

  return (
    <SafeAreaView style={styles.container}>
      <StatusBar barStyle="light-content" backgroundColor="#001a33" />
      <ScrollView contentContainerStyle={styles.scrollContent}>
        {/* Encabezado Institucional */}
        <View style={styles.header}>
          <View style={styles.badgeContainer}>
            <Text style={styles.badgeText}>SEGURIDAD MÓVIL AVANZADA</Text>
          </View>
          <Text style={styles.title}>Universidad de La Sabana</Text>
          <Text style={styles.subtitle}>Portal de Identidad Criptográfica Móvil</Text>
        </View>

        {/* Tarjeta de Arquitectura y Especificación */}
        <View style={styles.card}>
          <Text style={styles.cardTitle}>Arquitectura RFC 7636 (PKCE)</Text>
          <Text style={styles.cardDescription}>
            Esta aplicación implementa el flujo de Código de Autorización con clave de prueba
            para intercambio de código (Proof Key for Code Exchange).
          </Text>

          <View style={styles.specBox}>
            <View style={styles.specRow}>
              <Text style={styles.specLabel}>Algoritmo Challenge:</Text>
              <Text style={styles.specValue}>SHA-256 (S256)</Text>
            </View>
            <View style={styles.specRow}>
              <Text style={styles.specLabel}>Entropía Verifier:</Text>
              <Text style={styles.specValue}>64 caracteres Base64URL</Text>
            </View>
            <View style={styles.specRow}>
              <Text style={styles.specLabel}>Protección CSRF:</Text>
              <Text style={styles.specValue}>Nonce criptográfico (State)</Text>
            </View>
            <View style={styles.specRow}>
              <Text style={styles.specLabel}>Almacenamiento Access:</Text>
              <Text style={styles.specValue}>Solo Memoria RAM (Volátil)</Text>
            </View>
            <View style={styles.specRow}>
              <Text style={styles.specLabel}>Almacenamiento Refresh:</Text>
              <Text style={styles.specValue}>Hardware Enclave (SecureStore)</Text>
            </View>
          </View>

          {/* Advertencia BCP RFC 8252 */}
          <View style={styles.warningBox}>
            <Text style={styles.warningTitle}>Seguridad Operativa (RFC 8252):</Text>
            <Text style={styles.warningText}>
              El inicio de sesión se delega al navegador del sistema seguro (WebBrowser). Queda
              estrictamente prohibido el uso de WebViews embebidas para proteger al usuario de
              scripts maliciosos y robo de credenciales en memoria.
            </Text>
          </View>

          {/* Botón de Inicio de Sesión */}
          <TouchableOpacity
            style={[styles.loginButton, isLoading && styles.buttonDisabled]}
            onPress={loginWithPKCE}
            disabled={isLoading}
            activeOpacity={0.8}
          >
            {isLoading ? (
              <ActivityIndicator color="#ffffff" />
            ) : (
              <Text style={styles.loginButtonText}>Iniciar Sesión Institucional (PKCE)</Text>
            )}
          </TouchableOpacity>
        </View>

        {/* Pie de página con créditos de laboratorio */}
        <View style={styles.footer}>
          <Text style={styles.footerText}>Laboratorio: OAuth 2.0 PKCE + TOTP RFC 6238</Text>
          <Text style={styles.footerSubText}>Facultad de Ingeniería — Ciberseguridad</Text>
        </View>
      </ScrollView>
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
    justifyContent: 'center',
    minHeight: '100%',
  },
  header: {
    alignItems: 'center',
    marginBottom: 24,
  },
  badgeContainer: {
    backgroundColor: 'rgba(229, 168, 35, 0.2)',
    paddingHorizontal: 12,
    paddingVertical: 4,
    borderRadius: 20,
    borderWidth: 1,
    borderColor: '#e5a823',
    marginBottom: 10,
  },
  badgeText: {
    color: '#e5a823',
    fontSize: 11,
    fontWeight: '700',
    letterSpacing: 1,
  },
  title: {
    fontSize: 24,
    fontWeight: 'bold',
    color: '#ffffff',
    textAlign: 'center',
  },
  subtitle: {
    fontSize: 14,
    color: '#94a3b8',
    marginTop: 4,
    textAlign: 'center',
  },
  card: {
    backgroundColor: '#0a2540',
    borderRadius: 16,
    padding: 20,
    borderWidth: 1,
    borderColor: '#1e3a5f',
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 6 },
    shadowOpacity: 0.3,
    shadowRadius: 10,
    elevation: 8,
  },
  cardTitle: {
    fontSize: 18,
    fontWeight: '700',
    color: '#38bdf8',
    marginBottom: 8,
  },
  cardDescription: {
    fontSize: 13,
    color: '#cbd5e1',
    lineHeight: 18,
    marginBottom: 16,
  },
  specBox: {
    backgroundColor: '#051829',
    borderRadius: 10,
    padding: 14,
    marginBottom: 16,
    borderWidth: 1,
    borderColor: '#163354',
  },
  specRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    paddingVertical: 5,
    borderBottomWidth: 1,
    borderBottomColor: '#0e243d',
  },
  specLabel: {
    fontSize: 12,
    color: '#94a3b8',
  },
  specValue: {
    fontSize: 12,
    fontWeight: '600',
    color: '#f8fafc',
  },
  warningBox: {
    backgroundColor: 'rgba(239, 68, 68, 0.1)',
    borderLeftWidth: 3,
    borderLeftColor: '#ef4444',
    padding: 12,
    borderRadius: 6,
    marginBottom: 20,
  },
  warningTitle: {
    fontSize: 12,
    fontWeight: 'bold',
    color: '#f87171',
    marginBottom: 2,
  },
  warningText: {
    fontSize: 11.5,
    color: '#fca5a5',
    lineHeight: 16,
  },
  loginButton: {
    backgroundColor: '#0284c7',
    paddingVertical: 14,
    borderRadius: 10,
    alignItems: 'center',
    shadowColor: '#0284c7',
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.4,
    shadowRadius: 6,
    elevation: 4,
  },
  buttonDisabled: {
    backgroundColor: '#475569',
  },
  loginButtonText: {
    color: '#ffffff',
    fontSize: 15,
    fontWeight: 'bold',
    letterSpacing: 0.5,
  },
  footer: {
    marginTop: 24,
    alignItems: 'center',
  },
  footerText: {
    color: '#64748b',
    fontSize: 12,
  },
  footerSubText: {
    color: '#475569',
    fontSize: 11,
    marginTop: 2,
  },
});

