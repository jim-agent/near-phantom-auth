/**
 * React Hook for Anonymous Authentication
 */

import {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  type ReactNode,
} from 'react';
import { createApiClient, type ApiClient, type SessionInfo } from '../api.js';
import {
  createPasskey,
  authenticateWithPasskey,
  isWebAuthnSupported,
  isPlatformAuthenticatorAvailable,
  isLikelyCloudSynced,
} from '../passkey.js';

export interface AnonAuthState {
  /** Whether initial session check is in progress */
  isLoading: boolean;
  /** Whether user is authenticated */
  isAuthenticated: boolean;
  /** User's codename (e.g., "ALPHA-7") */
  codename: string | null;
  /** User's chosen username (if custom username enabled) */
  username: string | null;
  /** User's NEAR account ID */
  nearAccountId: string | null;
  /** Session expiration time */
  expiresAt: Date | null;
  /** Authentication method used */
  authMethod: 'passkey' | 'oauth' | 'email' | null;
  /** User's email (if authenticated via OAuth or magic link) */
  email: string | null;
  /** Whether WebAuthn is supported */
  webAuthnSupported: boolean;
  /** Whether platform authenticator (biometric) is available */
  platformAuthAvailable: boolean;
  /** Error from last operation */
  error: string | null;
  /** Whether the last registered credential appears cloud-synced (privacy warning) */
  credentialCloudSynced: boolean | null;
  /** Available OAuth providers */
  oauthProviders: Array<{ name: string; authUrl: string }>;
}

export interface AnonAuthActions {
  /** Register a new identity with passkey (optional custom username) */
  register(username?: string): Promise<void>;
  /** Sign in with existing passkey */
  login(codename?: string): Promise<void>;
  /** Sign out */
  logout(): Promise<void>;
  /** Refresh session info */
  refreshSession(): Promise<void>;
  /** Clear error */
  clearError(): void;
  /** Check if username is available */
  checkUsername(username: string): Promise<{ available: boolean; suggestion?: string }>;
  /** Start OAuth flow */
  startOAuth(provider: string): Promise<void>;
  /** Send magic link email */
  sendMagicLink(email: string): Promise<void>;
  /** Verify magic link token */
  verifyMagicLink(token: string): Promise<void>;
}

export interface RecoveryActions {
  /** Link a NEAR wallet for recovery */
  linkWallet(signMessage: (message: string) => Promise<{ signature: string; publicKey: string }>, walletAccountId: string): Promise<void>;
  /** Recover account using wallet */
  recoverWithWallet(signMessage: (message: string) => Promise<{ signature: string; publicKey: string }>, nearAccountId: string): Promise<void>;
  /** Set up IPFS password recovery */
  setupPasswordRecovery(password: string): Promise<{ cid: string }>;
  /** Recover using IPFS password */
  recoverWithPassword(cid: string, password: string): Promise<void>;
}

export type AnonAuthContextValue = AnonAuthState & AnonAuthActions & {
  recovery: RecoveryActions;
};

const AnonAuthContext = createContext<AnonAuthContextValue | null>(null);

export interface AnonAuthProviderProps {
  /** API URL (e.g., '/auth') */
  apiUrl: string;
  /** Children */
  children: ReactNode;
}

export function AnonAuthProvider({ apiUrl, children }: AnonAuthProviderProps) {
  const [api] = useState(() => createApiClient({ baseUrl: apiUrl }));
  const [state, setState] = useState<AnonAuthState>({
    isLoading: true,
    isAuthenticated: false,
    codename: null,
    username: null,
    nearAccountId: null,
    expiresAt: null,
    authMethod: null,
    email: null,
    webAuthnSupported: false,
    platformAuthAvailable: false,
    error: null,
    credentialCloudSynced: null,
    oauthProviders: [],
  });

  // Check WebAuthn support on mount
  useEffect(() => {
    const checkSupport = async () => {
      const webAuthnSupported = isWebAuthnSupported();
      const platformAuthAvailable = await isPlatformAuthenticatorAvailable();
      
      setState((prev) => ({
        ...prev,
        webAuthnSupported,
        platformAuthAvailable,
      }));
    };
    
    checkSupport();
  }, []);

  // Check session and fetch OAuth providers on mount
  useEffect(() => {
    const initialize = async () => {
      try {
        // Check session
        const session = await api.getSession();
        
        // Fetch OAuth providers (non-blocking)
        let oauthProviders: Array<{ name: string; authUrl: string }> = [];
        try {
          const providers = await api.getOAuthProviders();
          oauthProviders = providers.providers || [];
        } catch {
          // OAuth not configured, ignore
        }
        
        setState((prev) => ({
          ...prev,
          isLoading: false,
          isAuthenticated: session.authenticated,
          codename: session.codename || null,
          username: session.username || null,
          nearAccountId: session.nearAccountId || null,
          expiresAt: session.expiresAt ? new Date(session.expiresAt) : null,
          authMethod: session.authMethod || null,
          email: session.email || null,
          oauthProviders,
        }));
      } catch (error) {
        setState((prev) => ({
          ...prev,
          isLoading: false,
          error: error instanceof Error ? error.message : 'Session check failed',
        }));
      }
    };
    
    initialize();
  }, [api]);

  const register = useCallback(async (username?: string) => {
    try {
      setState((prev) => ({ ...prev, isLoading: true, error: null, credentialCloudSynced: null }));
      
      // Start registration with optional username
      const { challengeId, options, tempUserId, codename } = await api.startRegistration(username);
      
      // Create passkey
      const credential = await createPasskey(options);
      
      // Check if credential appears cloud-synced (privacy warning)
      const cloudSynced = isLikelyCloudSynced(credential);
      
      // Finish registration
      const result = await api.finishRegistration(
        challengeId,
        credential,
        tempUserId,
        codename,
        username
      );
      
      if (result.success) {
        setState((prev) => ({
          ...prev,
          isLoading: false,
          isAuthenticated: true,
          codename: result.codename,
          username: result.username || username || null,
          nearAccountId: result.nearAccountId,
          authMethod: 'passkey',
          credentialCloudSynced: cloudSynced,
        }));
      } else {
        throw new Error('Registration failed');
      }
    } catch (error) {
      setState((prev) => ({
        ...prev,
        isLoading: false,
        error: error instanceof Error ? error.message : 'Registration failed',
      }));
    }
  }, [api]);

  const login = useCallback(async (codename?: string) => {
    try {
      setState((prev) => ({ ...prev, isLoading: true, error: null }));
      
      // Start authentication
      const { challengeId, options } = await api.startAuthentication(codename);
      
      // Authenticate with passkey
      const credential = await authenticateWithPasskey(options);
      
      // Finish authentication
      const result = await api.finishAuthentication(challengeId, credential);
      
      if (result.success) {
        // Refresh session to get full info
        const session = await api.getSession();
        
        setState((prev) => ({
          ...prev,
          isLoading: false,
          isAuthenticated: true,
          codename: session.codename || result.codename,
          nearAccountId: session.nearAccountId || null,
          expiresAt: session.expiresAt ? new Date(session.expiresAt) : null,
        }));
      } else {
        throw new Error('Authentication failed');
      }
    } catch (error) {
      setState((prev) => ({
        ...prev,
        isLoading: false,
        error: error instanceof Error ? error.message : 'Login failed',
      }));
    }
  }, [api]);

  const logout = useCallback(async () => {
    try {
      await api.logout();
      
      setState((prev) => ({
        ...prev,
        isAuthenticated: false,
        codename: null,
        nearAccountId: null,
        expiresAt: null,
      }));
    } catch (error) {
      setState((prev) => ({
        ...prev,
        error: error instanceof Error ? error.message : 'Logout failed',
      }));
    }
  }, [api]);

  const refreshSession = useCallback(async () => {
    try {
      const session = await api.getSession();
      
      setState((prev) => ({
        ...prev,
        isAuthenticated: session.authenticated,
        codename: session.codename || null,
        nearAccountId: session.nearAccountId || null,
        expiresAt: session.expiresAt ? new Date(session.expiresAt) : null,
      }));
    } catch (error) {
      console.error('Session refresh failed:', error);
    }
  }, [api]);

  const clearError = useCallback(() => {
    setState((prev) => ({ ...prev, error: null }));
  }, []);

  const checkUsername = useCallback(async (username: string) => {
    try {
      return await api.checkUsername(username);
    } catch (error) {
      return { available: false, suggestion: undefined };
    }
  }, [api]);

  const startOAuth = useCallback(async (provider: string) => {
    try {
      setState((prev) => ({ ...prev, isLoading: true, error: null }));
      const { authUrl } = await api.startOAuth(provider);
      // Redirect to OAuth provider
      window.location.href = authUrl;
    } catch (error) {
      setState((prev) => ({
        ...prev,
        isLoading: false,
        error: error instanceof Error ? error.message : 'OAuth failed',
      }));
    }
  }, [api]);

  const sendMagicLink = useCallback(async (email: string) => {
    try {
      setState((prev) => ({ ...prev, isLoading: true, error: null }));
      const result = await api.sendMagicLink(email);
      setState((prev) => ({
        ...prev,
        isLoading: false,
        error: result.success ? null : 'Failed to send magic link',
      }));
    } catch (error) {
      setState((prev) => ({
        ...prev,
        isLoading: false,
        error: error instanceof Error ? error.message : 'Failed to send magic link',
      }));
    }
  }, [api]);

  const verifyMagicLink = useCallback(async (token: string) => {
    try {
      setState((prev) => ({ ...prev, isLoading: true, error: null }));
      const result = await api.verifyMagicLink(token);
      
      if (result.success) {
        setState((prev) => ({
          ...prev,
          isLoading: false,
          isAuthenticated: true,
          codename: result.codename || null,
          nearAccountId: result.nearAccountId || null,
          authMethod: 'email',
        }));
      } else {
        throw new Error('Invalid or expired magic link');
      }
    } catch (error) {
      setState((prev) => ({
        ...prev,
        isLoading: false,
        error: error instanceof Error ? error.message : 'Magic link verification failed',
      }));
    }
  }, [api]);

  // Recovery actions
  const recovery: RecoveryActions = {
    async linkWallet(signMessage, walletAccountId) {
      const { challenge } = await api.startWalletLink();
      const signature = await signMessage(challenge);
      await api.finishWalletLink(signature, challenge, walletAccountId);
    },

    async recoverWithWallet(signMessage, nearAccountId) {
      const { challenge } = await api.startWalletRecovery();
      const signature = await signMessage(challenge);
      const result = await api.finishWalletRecovery(signature, challenge, nearAccountId);
      
      if (result.success) {
        setState((prev) => ({
          ...prev,
          isAuthenticated: true,
          codename: result.codename,
        }));
      }
    },

    async setupPasswordRecovery(password) {
      const result = await api.setupIPFSRecovery(password);
      return { cid: result.cid };
    },

    async recoverWithPassword(cid, password) {
      const result = await api.recoverFromIPFS(cid, password);
      
      if (result.success) {
        setState((prev) => ({
          ...prev,
          isAuthenticated: true,
          codename: result.codename,
        }));
      }
    },
  };

  const value: AnonAuthContextValue = {
    ...state,
    register,
    login,
    logout,
    refreshSession,
    clearError,
    checkUsername,
    startOAuth,
    sendMagicLink,
    verifyMagicLink,
    recovery,
  };

  return (
    <AnonAuthContext.Provider value={value}>
      {children}
    </AnonAuthContext.Provider>
  );
}

/**
 * Hook to access anonymous auth state and actions
 */
export function useAnonAuth(): AnonAuthContextValue {
  const context = useContext(AnonAuthContext);
  
  if (!context) {
    throw new Error('useAnonAuth must be used within AnonAuthProvider');
  }
  
  return context;
}
