import { Response, Request, Router, RequestHandler } from 'express';
import { S as Session, e as PublicKeyCredentialCreationOptionsJSON, a as RegistrationResponseJSON, f as AuthenticatorTransport, P as PublicKeyCredentialRequestOptionsJSON, c as AuthenticationResponseJSON, g as Passkey, D as DatabaseAdapter, O as OAuthConfig, h as AnonAuthConfig } from '../index-Bywvf8De.cjs';
export { i as AnonUser, j as OAuthProvider, k as OAuthUser, U as User, l as UserType } from '../index-Bywvf8De.cjs';

/**
 * Session Management
 *
 * HttpOnly cookie-based sessions for XSS protection.
 * Sessions are stored server-side (database) with secure cookie reference.
 */

interface SessionConfig {
    /** Secret for signing session cookies */
    secret: string;
    /** Cookie name (default: anon_session) */
    cookieName?: string;
    /** Session duration in ms (default: 7 days) */
    durationMs?: number;
    /** Cookie domain (optional) */
    domain?: string;
    /** Cookie path (default: /) */
    path?: string;
    /** Secure flag (default: true in production) */
    secure?: boolean;
    /** SameSite setting (default: strict) */
    sameSite?: 'strict' | 'lax' | 'none';
}
interface SessionManager {
    createSession(userId: string, res: Response, options?: {
        ipAddress?: string;
        userAgent?: string;
    }): Promise<Session>;
    getSession(req: Request): Promise<Session | null>;
    destroySession(req: Request, res: Response): Promise<void>;
    refreshSession(req: Request, res: Response): Promise<Session | null>;
}

/**
 * Passkey (WebAuthn) Authentication
 *
 * Handles passkey registration and authentication using @simplewebauthn/server
 */

interface PasskeyConfig {
    /** Relying Party name (shown to users) */
    rpName: string;
    /** Relying Party ID (your domain, e.g., 'example.com') */
    rpId: string;
    /** Origin for WebAuthn (e.g., 'https://example.com') */
    origin: string;
    /** Challenge timeout in ms (default: 60000) */
    challengeTimeoutMs?: number;
}
interface PasskeyManager {
    startRegistration(userId: string, userDisplayName: string): Promise<{
        challengeId: string;
        options: PublicKeyCredentialCreationOptionsJSON;
    }>;
    finishRegistration(challengeId: string, response: RegistrationResponseJSON): Promise<{
        verified: boolean;
        passkeyData?: {
            credentialId: string;
            publicKey: Uint8Array;
            counter: number;
            deviceType: 'singleDevice' | 'multiDevice';
            backedUp: boolean;
            transports?: AuthenticatorTransport[];
        };
        tempUserId?: string;
    }>;
    startAuthentication(userId?: string): Promise<{
        challengeId: string;
        options: PublicKeyCredentialRequestOptionsJSON;
    }>;
    finishAuthentication(challengeId: string, response: AuthenticationResponseJSON): Promise<{
        verified: boolean;
        userId?: string;
        passkey?: Passkey;
    }>;
}

/**
 * NEAR MPC Account Manager
 *
 * Creates NEAR accounts using Chain Signatures MPC network.
 * No private keys are stored - all key management is decentralized.
 */
interface MPCAccount {
    nearAccountId: string;
    derivationPath: string;
    mpcPublicKey: string;
    onChain: boolean;
}
interface MPCConfig {
    networkId: 'testnet' | 'mainnet';
    accountPrefix?: string;
    treasuryAccount?: string;
    treasuryPrivateKey?: string;
    fundingAmount?: string;
}
/**
 * MPC Account Manager
 */
declare class MPCAccountManager {
    private networkId;
    private mpcContractId;
    private accountPrefix;
    private treasuryAccount?;
    private treasuryPrivateKey?;
    private fundingAmount;
    constructor(config: MPCConfig);
    /**
     * Create a new NEAR account for an anonymous user
     */
    createAccount(userId: string): Promise<MPCAccount>;
    /**
     * Add a recovery wallet as an access key to the MPC account
     *
     * This creates an on-chain link without storing it in our database.
     * The recovery wallet can be used to prove ownership and create new passkeys.
     */
    addRecoveryWallet(nearAccountId: string, recoveryWalletId: string): Promise<{
        success: boolean;
        txHash?: string;
    }>;
    /**
     * Verify that a wallet has recovery access to an account
     */
    verifyRecoveryWallet(nearAccountId: string, recoveryWalletId: string): Promise<boolean>;
    /**
     * Get MPC contract ID
     */
    getMPCContractId(): string;
    /**
     * Get network ID
     */
    getNetworkId(): string;
}

interface WalletSignature {
    signature: string;
    publicKey: string;
    message: string;
}
/**
 * Wallet Recovery Manager
 */
interface WalletRecoveryManager {
    /**
     * Generate challenge for linking a wallet
     */
    generateLinkChallenge(): {
        challenge: string;
        expiresAt: Date;
    };
    /**
     * Verify wallet signature and prepare for linking
     */
    verifyLinkSignature(signature: WalletSignature, challenge: string): {
        verified: boolean;
        walletId?: string;
    };
    /**
     * Generate challenge for recovery
     */
    generateRecoveryChallenge(): {
        challenge: string;
        expiresAt: Date;
    };
    /**
     * Verify recovery signature
     */
    verifyRecoverySignature(signature: WalletSignature, challenge: string, nearAccountId: string): Promise<{
        verified: boolean;
    }>;
}

/**
 * IPFS + Password Recovery
 *
 * Encrypts recovery data with user's password and stores on IPFS.
 * User needs password + CID to recover.
 *
 * Supported pinning services:
 * - Pinata (https://pinata.cloud)
 * - web3.storage (https://web3.storage)
 * - Infura (https://infura.io)
 */
interface IPFSRecoveryConfig {
    pinningService: 'pinata' | 'web3storage' | 'infura' | 'custom';
    /** API key (required for pinata, web3storage, infura) */
    apiKey?: string;
    /** API secret (required for pinata, infura) */
    apiSecret?: string;
    /** Project ID (required for infura) */
    projectId?: string;
    /** Custom pinning function */
    customPin?: (data: Uint8Array) => Promise<string>;
    /** Custom fetch function */
    customFetch?: (cid: string) => Promise<Uint8Array>;
}
interface RecoveryPayload {
    userId: string;
    nearAccountId: string;
    derivationPath: string;
    createdAt: number;
}
/**
 * IPFS Recovery Manager
 */
interface IPFSRecoveryManager {
    /**
     * Create and pin encrypted recovery data
     */
    createRecoveryBackup(payload: RecoveryPayload, password: string): Promise<{
        cid: string;
    }>;
    /**
     * Recover data from IPFS
     */
    recoverFromBackup(cid: string, password: string): Promise<RecoveryPayload>;
    /**
     * Validate password strength
     */
    validatePassword(password: string): {
        valid: boolean;
        errors: string[];
        strength: 'weak' | 'medium' | 'strong';
    };
}

/**
 * OAuth Provider Manager
 *
 * Manages OAuth authentication alongside passkey auth.
 * Supports Google, GitHub, and X (Twitter) OAuth providers.
 */

interface OAuthProviderConfig {
    google?: {
        clientId: string;
        clientSecret: string;
    };
    github?: {
        clientId: string;
        clientSecret: string;
    };
    twitter?: {
        clientId: string;
        clientSecret: string;
    };
}
interface OAuthState {
    provider: 'google' | 'github' | 'twitter';
    state: string;
    codeVerifier?: string;
    redirectUri: string;
    expiresAt: Date;
}
interface OAuthTokens {
    accessToken: string;
    refreshToken?: string;
    expiresIn: number;
    tokenType: string;
}
interface OAuthProfile {
    provider: 'google' | 'github' | 'twitter';
    providerId: string;
    email?: string;
    name?: string;
    avatarUrl?: string;
    raw: Record<string, unknown>;
}
interface OAuthManager {
    getAuthUrl(provider: 'google' | 'github' | 'twitter', redirectUri: string): Promise<{
        url: string;
        state: string;
        codeVerifier?: string;
    }>;
    exchangeCode(provider: 'google' | 'github' | 'twitter', code: string, redirectUri: string, codeVerifier?: string): Promise<OAuthTokens>;
    getProfile(provider: 'google' | 'github' | 'twitter', accessToken: string): Promise<OAuthProfile>;
    validateState(state: string): Promise<OAuthState | null>;
    isConfigured(provider: 'google' | 'github' | 'twitter'): boolean;
}
/**
 * Create OAuth Manager
 */
declare function createOAuthManager(config: OAuthProviderConfig, db: DatabaseAdapter): OAuthManager;

/**
 * Codename Generator
 *
 * Generates anonymous codenames for HUMINT sources
 */
type CodenameStyle = 'nato-phonetic' | 'animals' | 'custom';
/**
 * Generate codename based on style
 */
declare function generateCodename(style?: CodenameStyle): string;
/**
 * Check if a codename format is valid
 */
declare function isValidCodename(codename: string): boolean;

/**
 * PostgreSQL Database Adapter
 */

interface PostgresConfig {
    connectionString: string;
}
/**
 * SQL schema for near-anon-auth tables
 */
declare const POSTGRES_SCHEMA = "\n-- Anonymous users (HUMINT sources - passkey only)\nCREATE TABLE IF NOT EXISTS anon_users (\n  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),\n  codename TEXT UNIQUE NOT NULL,\n  near_account_id TEXT UNIQUE NOT NULL,\n  mpc_public_key TEXT NOT NULL,\n  derivation_path TEXT NOT NULL,\n  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),\n  last_active_at TIMESTAMPTZ NOT NULL DEFAULT NOW()\n);\n\n-- OAuth users (standard users - OAuth providers)\nCREATE TABLE IF NOT EXISTS oauth_users (\n  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),\n  email TEXT UNIQUE NOT NULL,\n  name TEXT,\n  avatar_url TEXT,\n  near_account_id TEXT UNIQUE NOT NULL,\n  mpc_public_key TEXT NOT NULL,\n  derivation_path TEXT NOT NULL,\n  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),\n  last_active_at TIMESTAMPTZ NOT NULL DEFAULT NOW()\n);\n\n-- OAuth provider connections\nCREATE TABLE IF NOT EXISTS oauth_providers (\n  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),\n  user_id UUID NOT NULL REFERENCES oauth_users(id) ON DELETE CASCADE,\n  provider TEXT NOT NULL,\n  provider_id TEXT NOT NULL,\n  email TEXT,\n  name TEXT,\n  avatar_url TEXT,\n  connected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),\n  UNIQUE(provider, provider_id)\n);\n\n-- Passkeys (WebAuthn credentials) - for anonymous users\nCREATE TABLE IF NOT EXISTS anon_passkeys (\n  credential_id TEXT PRIMARY KEY,\n  user_id UUID NOT NULL REFERENCES anon_users(id) ON DELETE CASCADE,\n  public_key BYTEA NOT NULL,\n  counter BIGINT NOT NULL DEFAULT 0,\n  device_type TEXT NOT NULL,\n  backed_up BOOLEAN NOT NULL DEFAULT false,\n  transports TEXT[],\n  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()\n);\n\n-- Sessions (works for both user types)\nCREATE TABLE IF NOT EXISTS anon_sessions (\n  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),\n  user_id UUID NOT NULL,\n  user_type TEXT NOT NULL DEFAULT 'anonymous',\n  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),\n  expires_at TIMESTAMPTZ NOT NULL,\n  last_activity_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),\n  ip_address TEXT,\n  user_agent TEXT\n);\n\n-- WebAuthn challenges (temporary)\nCREATE TABLE IF NOT EXISTS anon_challenges (\n  id UUID PRIMARY KEY,\n  challenge TEXT NOT NULL,\n  type TEXT NOT NULL,\n  user_id UUID,\n  expires_at TIMESTAMPTZ NOT NULL,\n  metadata JSONB\n);\n\n-- Recovery data references (works for both user types)\nCREATE TABLE IF NOT EXISTS anon_recovery (\n  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),\n  user_id UUID NOT NULL,\n  user_type TEXT NOT NULL DEFAULT 'anonymous',\n  type TEXT NOT NULL,\n  reference TEXT NOT NULL,\n  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),\n  UNIQUE(user_id, type)\n);\n\n-- Indexes\nCREATE INDEX IF NOT EXISTS idx_anon_sessions_user ON anon_sessions(user_id);\nCREATE INDEX IF NOT EXISTS idx_anon_sessions_expires ON anon_sessions(expires_at);\nCREATE INDEX IF NOT EXISTS idx_anon_passkeys_user ON anon_passkeys(user_id);\nCREATE INDEX IF NOT EXISTS idx_anon_challenges_expires ON anon_challenges(expires_at);\nCREATE INDEX IF NOT EXISTS idx_oauth_users_email ON oauth_users(email);\nCREATE INDEX IF NOT EXISTS idx_oauth_providers_user ON oauth_providers(user_id);\nCREATE INDEX IF NOT EXISTS idx_oauth_providers_lookup ON oauth_providers(provider, provider_id);\n";
/**
 * Create PostgreSQL adapter
 *
 * Note: Requires 'pg' package to be installed by the consuming application
 */
declare function createPostgresAdapter(config: PostgresConfig): DatabaseAdapter;

/**
 * OAuth Router
 *
 * API routes for OAuth authentication.
 */

interface OAuthRouterConfig {
    db: DatabaseAdapter;
    sessionManager: SessionManager;
    mpcManager: MPCAccountManager;
    oauthConfig: OAuthConfig;
    ipfsRecovery?: IPFSRecoveryManager;
}
declare function createOAuthRouter(config: OAuthRouterConfig): Router;

/**
 * Server SDK Entry Point
 *
 * @example
 * ```typescript
 * import { createAnonAuth } from '@vitalpoint/near-phantom-auth/server';
 *
 * const anonAuth = createAnonAuth({
 *   nearNetwork: 'testnet',
 *   sessionSecret: process.env.SESSION_SECRET,
 *   database: {
 *     type: 'postgres',
 *     connectionString: process.env.DATABASE_URL,
 *   },
 *   rp: {
 *     name: 'My App',
 *     id: 'myapp.com',
 *     origin: 'https://myapp.com',
 *   },
 *   oauth: {
 *     callbackBaseUrl: 'https://myapp.com/auth/callback',
 *     google: { clientId: '...', clientSecret: '...' },
 *     github: { clientId: '...', clientSecret: '...' },
 *     twitter: { clientId: '...', clientSecret: '...' },
 *   },
 * });
 *
 * app.use('/auth', anonAuth.router);
 * app.use('/auth/oauth', anonAuth.oauthRouter);
 * app.get('/protected', anonAuth.requireAuth, handler);
 * ```
 */

interface AnonAuthInstance {
    /** Express router with all auth endpoints (passkey) */
    router: Router;
    /** OAuth router for OAuth providers */
    oauthRouter?: Router;
    /** Middleware that attaches user to request if authenticated */
    middleware: RequestHandler;
    /** Middleware that requires authentication (401 if not) */
    requireAuth: RequestHandler;
    /** Initialize database schema */
    initialize(): Promise<void>;
    /** Database adapter */
    db: DatabaseAdapter;
    /** Session manager */
    sessionManager: SessionManager;
    /** Passkey manager */
    passkeyManager: PasskeyManager;
    /** MPC account manager */
    mpcManager: MPCAccountManager;
    /** Wallet recovery manager (if enabled) */
    walletRecovery?: WalletRecoveryManager;
    /** IPFS recovery manager (if enabled) */
    ipfsRecovery?: IPFSRecoveryManager;
    /** OAuth manager (if enabled) */
    oauthManager?: OAuthManager;
}
/**
 * Create anonymous authentication instance
 */
declare function createAnonAuth(config: AnonAuthConfig): AnonAuthInstance;

export { AnonAuthConfig, type AnonAuthInstance, DatabaseAdapter, type IPFSRecoveryConfig, type IPFSRecoveryManager, type MPCAccount, MPCAccountManager, type MPCConfig, OAuthConfig, type OAuthManager, type OAuthProfile, type OAuthProviderConfig, type OAuthTokens, POSTGRES_SCHEMA, type PasskeyConfig, type PasskeyManager, Session, type SessionConfig, type SessionManager, type WalletRecoveryManager, createAnonAuth, createOAuthManager, createOAuthRouter, createPostgresAdapter, generateCodename, isValidCodename };
