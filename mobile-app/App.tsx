/**
 * App.tsx
 * 
 * Punto de Entrada Principal de la Aplicación Móvil
 * Configuración del AuthProvider y Navegación entre Pantallas:
 * - LoginScreen (OAuth 2.0 con PKCE en WebBrowser)
 * - VaultScreen (Bóveda Crítica con Step-Up 2FA)
 * - AuthenticatorScreen (Motor TOTP RFC 6238 100% Offline)
 */

import React, { useState } from 'react';
import {
  StyleSheet,
  View,
  Text,
  TouchableOpacity,
  ActivityIndicator,
  SafeAreaView,
  StatusBar,
  Platform,
} from 'react-native';
import { StatusBar as ExpoStatusBar } from 'expo-status-bar';
import { AuthProvider, useAuth } from './src/context/AuthContext';
import { LoginScreen } from './src/screens/LoginScreen';
import { VaultScreen } from './src/screens/VaultScreen';
import { AuthenticatorScreen } from './src/screens/AuthenticatorScreen';

type Tab = 'vault' | 'authenticator';

const NavigationContainer: React.FC = () => {
  const { isAuthenticated, isLoading } = useAuth();
  const [activeTab, setActiveTab] = useState<Tab>('vault');

  if (isLoading) {
    return (
      <View style={styles.loadingContainer}>
        <ActivityIndicator size="large" color="#38bdf8" />
        <Text style={styles.loadingText}>Iniciando Enclave Criptográfico...</Text>
      </View>
    );
  }

  if (!isAuthenticated) {
    return <LoginScreen />;
  }

  return (
    <SafeAreaView style={styles.mainContainer}>
      <ExpoStatusBar style="light" />

      {/* Contenido de la Pantalla Activa */}
      <View style={styles.screenContent}>
        {activeTab === 'vault' ? <VaultScreen /> : <AuthenticatorScreen />}
      </View>

      {/* Barra de Navegación Inferior (Tabs) */}
      <View style={styles.tabBar}>
        <TouchableOpacity
          style={[styles.tabButton, activeTab === 'vault' && styles.tabButtonActive]}
          onPress={() => setActiveTab('vault')}
          activeOpacity={0.7}
        >
          <Text style={styles.tabIcon}>🏛️</Text>
          <Text style={[styles.tabLabel, activeTab === 'vault' && styles.tabLabelActive]}>
            Bóveda Crítica
          </Text>
        </TouchableOpacity>

        <TouchableOpacity
          style={[styles.tabButton, activeTab === 'authenticator' && styles.tabButtonActive]}
          onPress={() => setActiveTab('authenticator')}
          activeOpacity={0.7}
        >
          <Text style={styles.tabIcon}>⏱️</Text>
          <Text style={[styles.tabLabel, activeTab === 'authenticator' && styles.tabLabelActive]}>
            Authenticator (TOTP)
          </Text>
        </TouchableOpacity>
      </View>
    </SafeAreaView>
  );
};

export default function App() {
  return (
    <AuthProvider>
      <NavigationContainer />
    </AuthProvider>
  );
}

const styles = StyleSheet.create({
  mainContainer: {
    flex: 1,
    backgroundColor: '#001a33',
  },
  loadingContainer: {
    flex: 1,
    backgroundColor: '#001a33',
    justifyContent: 'center',
    alignItems: 'center',
  },
  loadingText: {
    color: '#94a3b8',
    fontSize: 14,
    marginTop: 12,
  },
  screenContent: {
    flex: 1,
  },
  tabBar: {
    flexDirection: 'row',
    backgroundColor: '#051829',
    borderTopWidth: 1.5,
    borderTopColor: '#163354',
    paddingVertical: 10,
    paddingBottom: Platform.OS === 'ios' ? 24 : 10,
    justifyContent: 'space-around',
  },
  tabButton: {
    alignItems: 'center',
    paddingVertical: 4,
    paddingHorizontal: 20,
    borderRadius: 8,
  },
  tabButtonActive: {
    backgroundColor: 'rgba(56, 189, 248, 0.12)',
  },
  tabIcon: {
    fontSize: 22,
    marginBottom: 2,
  },
  tabLabel: {
    fontSize: 11.5,
    color: '#64748b',
    fontWeight: '600',
  },
  tabLabelActive: {
    color: '#38bdf8',
    fontWeight: 'bold',
  },
});

