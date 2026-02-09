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
} from '../passkey.js';

export interface AnonAuthState {
  /** Whether initial session check is in progress */
  isLoading: boolean;
  /** Whether user is authenticated */
  isAuthenticated: boolean;
  /** User's codename (e.g., "ALPHA-7") */
  codename: string | null;
  /** User's NEAR account ID */
  nearAccountId: string | null;
  /** Session expiration time */
  expiresAt: Date | null;
  /** Whether WebAuthn is supported */
  webAuthnSupported: boolean;
  /** Whether platform authenticator (biometric) is available */
  platformAuthAvailable: boolean;
  /** Error from last operation */
  error: string | null;
}

export interface AnonAuthActions {
  /** Register a new anonymous identity */
  register(): Promise<void>;
  /** Sign in with existing passkey */
  login(codename?: string): Promise<void>;
  /** Sign out */
  logout(): Promise<void>;
  /** Refresh session info */
  refreshSession(): Promise<void>;
  /** Clear error */
  clearError(): void;
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
    nearAccountId: null,
    expiresAt: null,
    webAuthnSupported: false,
    platformAuthAvailable: false,
    error: null,
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

  // Check session on mount
  useEffect(() => {
    const checkSession = async () => {
      try {
        const session = await api.getSession();
        
        setState((prev) => ({
          ...prev,
          isLoading: false,
          isAuthenticated: session.authenticated,
          codename: session.codename || null,
          nearAccountId: session.nearAccountId || null,
          expiresAt: session.expiresAt ? new Date(session.expiresAt) : null,
        }));
      } catch (error) {
        setState((prev) => ({
          ...prev,
          isLoading: false,
          error: error instanceof Error ? error.message : 'Session check failed',
        }));
      }
    };
    
    checkSession();
  }, [api]);

  const register = useCallback(async () => {
    try {
      setState((prev) => ({ ...prev, isLoading: true, error: null }));
      
      // Start registration
      const { challengeId, options, tempUserId, codename } = await api.startRegistration();
      
      // Create passkey
      const credential = await createPasskey(options);
      
      // Finish registration
      const result = await api.finishRegistration(
        challengeId,
        credential,
        tempUserId,
        codename
      );
      
      if (result.success) {
        setState((prev) => ({
          ...prev,
          isLoading: false,
          isAuthenticated: true,
          codename: result.codename,
          nearAccountId: result.nearAccountId,
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
