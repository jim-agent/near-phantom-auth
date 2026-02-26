import * as react_jsx_runtime from 'react/jsx-runtime';
import { ReactNode } from 'react';
import { R as RegistrationStartResponse, a as RegistrationResponseJSON, b as RegistrationFinishResponse, A as AuthenticationStartResponse, c as AuthenticationResponseJSON, d as AuthenticationFinishResponse, P as PublicKeyCredentialRequestOptionsJSON, e as PublicKeyCredentialCreationOptionsJSON } from '../index-Bywvf8De.cjs';

interface AnonAuthState {
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
    oauthProviders: Array<{
        name: string;
        authUrl: string;
    }>;
}
interface AnonAuthActions {
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
    checkUsername(username: string): Promise<{
        available: boolean;
        suggestion?: string;
    }>;
    /** Start OAuth flow */
    startOAuth(provider: string): Promise<void>;
    /** Send magic link email */
    sendMagicLink(email: string): Promise<void>;
    /** Verify magic link token */
    verifyMagicLink(token: string): Promise<void>;
}
interface RecoveryActions {
    /** Link a NEAR wallet for recovery */
    linkWallet(signMessage: (message: string) => Promise<{
        signature: string;
        publicKey: string;
    }>, walletAccountId: string): Promise<void>;
    /** Recover account using wallet */
    recoverWithWallet(signMessage: (message: string) => Promise<{
        signature: string;
        publicKey: string;
    }>, nearAccountId: string): Promise<void>;
    /** Set up IPFS password recovery */
    setupPasswordRecovery(password: string): Promise<{
        cid: string;
    }>;
    /** Recover using IPFS password */
    recoverWithPassword(cid: string, password: string): Promise<void>;
}
type AnonAuthContextValue = AnonAuthState & AnonAuthActions & {
    recovery: RecoveryActions;
};
interface AnonAuthProviderProps {
    /** API URL (e.g., '/auth') */
    apiUrl: string;
    /** Children */
    children: ReactNode;
}
declare function AnonAuthProvider({ apiUrl, children }: AnonAuthProviderProps): react_jsx_runtime.JSX.Element;
/**
 * Hook to access anonymous auth state and actions
 */
declare function useAnonAuth(): AnonAuthContextValue;

interface OAuthProviders {
    google: boolean;
    github: boolean;
    twitter: boolean;
}
interface OAuthUser {
    id: string;
    email: string;
    name?: string;
    avatarUrl?: string;
    nearAccountId: string;
    type: 'standard';
}
interface OAuthState {
    isLoading: boolean;
    error: string | null;
    providers: OAuthProviders;
    user: OAuthUser | null;
    isAuthenticated: boolean;
}
interface OAuthActions {
    /** Initiate Google OAuth login */
    loginWithGoogle: () => Promise<void>;
    /** Initiate GitHub OAuth login */
    loginWithGithub: () => Promise<void>;
    /** Initiate Twitter (X) OAuth login */
    loginWithTwitter: () => Promise<void>;
    /** Handle OAuth callback */
    handleCallback: (provider: string, code: string, state: string) => Promise<OAuthUser>;
    /** Link additional OAuth provider */
    linkProvider: (provider: 'google' | 'github' | 'twitter') => Promise<void>;
    /** Clear error */
    clearError: () => void;
    /** Refresh session */
    refreshSession: () => Promise<void>;
    /** Logout */
    logout: () => Promise<void>;
}
interface OAuthContextValue extends OAuthState, OAuthActions {
}
interface OAuthProviderProps {
    children: ReactNode;
    apiUrl: string;
    onLoginSuccess?: (user: OAuthUser, isNewUser: boolean) => void;
    onLoginError?: (error: Error) => void;
}
declare function OAuthProvider$1({ children, apiUrl, onLoginSuccess, onLoginError, }: OAuthProviderProps): react_jsx_runtime.JSX.Element;
declare function useOAuth(): OAuthContextValue;
/**
 * Hook to handle OAuth callback from URL parameters
 */
declare function useOAuthCallback(): {
    processCallback: () => Promise<void>;
    isProcessing: boolean;
    result: {
        user?: OAuthUser;
        error?: string;
    };
};

/**
 * API Client for near-anon-auth server
 */

interface ApiClientConfig {
    /** Base URL for auth API (e.g., '/auth' or 'https://api.example.com/auth') */
    baseUrl: string;
    /** Custom fetch function (optional) */
    fetch?: typeof fetch;
}
interface SessionInfo {
    authenticated: boolean;
    codename?: string;
    username?: string;
    nearAccountId?: string;
    expiresAt?: string;
    authMethod?: 'passkey' | 'oauth' | 'email';
    email?: string;
}
interface OAuthProvider {
    name: string;
    authUrl: string;
}
interface ApiClient {
    startRegistration(username?: string): Promise<RegistrationStartResponse & {
        codename: string;
        tempUserId: string;
        username?: string;
    }>;
    finishRegistration(challengeId: string, response: RegistrationResponseJSON, tempUserId: string, codename: string, username?: string): Promise<RegistrationFinishResponse & {
        username?: string;
    }>;
    checkUsername(username: string): Promise<{
        available: boolean;
        suggestion?: string;
    }>;
    startAuthentication(codename?: string): Promise<AuthenticationStartResponse>;
    finishAuthentication(challengeId: string, response: AuthenticationResponseJSON): Promise<AuthenticationFinishResponse>;
    getOAuthProviders(): Promise<{
        providers: OAuthProvider[];
    }>;
    startOAuth(provider: string): Promise<{
        authUrl: string;
    }>;
    sendMagicLink(email: string): Promise<{
        success: boolean;
        message: string;
    }>;
    verifyMagicLink(token: string): Promise<{
        success: boolean;
        codename?: string;
        nearAccountId?: string;
    }>;
    getSession(): Promise<SessionInfo>;
    logout(): Promise<void>;
    startWalletLink(): Promise<{
        challenge: string;
        expiresAt: string;
    }>;
    finishWalletLink(signature: unknown, challenge: string, walletAccountId: string): Promise<{
        success: boolean;
        message: string;
    }>;
    startWalletRecovery(): Promise<{
        challenge: string;
        expiresAt: string;
    }>;
    finishWalletRecovery(signature: unknown, challenge: string, nearAccountId: string): Promise<{
        success: boolean;
        codename: string;
        message: string;
    }>;
    setupIPFSRecovery(password: string): Promise<{
        success: boolean;
        cid: string;
        message: string;
    }>;
    recoverFromIPFS(cid: string, password: string): Promise<{
        success: boolean;
        codename: string;
        message: string;
    }>;
}
/**
 * Create API client
 */
declare function createApiClient(config: ApiClientConfig): ApiClient;

/**
 * Client-side Passkey (WebAuthn) operations
 */

/**
 * Check if WebAuthn is supported
 */
declare function isWebAuthnSupported(): boolean;
/**
 * Check if platform authenticator is available
 */
declare function isPlatformAuthenticatorAvailable(): Promise<boolean>;
/**
 * Create a new passkey (registration)
 */
declare function createPasskey(options: PublicKeyCredentialCreationOptionsJSON): Promise<RegistrationResponseJSON>;
/**
 * Check if credential appears to use cloud-synced storage
 * Returns true if likely synced (platform authenticator), false if likely safe (hardware key)
 */
declare function isLikelyCloudSynced(credential: RegistrationResponseJSON): boolean;
/**
 * Authenticate with existing passkey
 */
declare function authenticateWithPasskey(options: PublicKeyCredentialRequestOptionsJSON): Promise<AuthenticationResponseJSON>;

export { type AnonAuthActions, type AnonAuthContextValue, AnonAuthProvider, type AnonAuthProviderProps, type AnonAuthState, type ApiClient, type ApiClientConfig, type OAuthActions, type OAuthContextValue, OAuthProvider$1 as OAuthProvider, type OAuthProviderProps, type OAuthProviders, type OAuthState, type OAuthUser, type RecoveryActions, type SessionInfo, authenticateWithPasskey, createApiClient, createPasskey, isLikelyCloudSynced, isPlatformAuthenticatorAvailable, isWebAuthnSupported, useAnonAuth, useOAuth, useOAuthCallback };
