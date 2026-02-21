/**
 * Core types for near-anon-auth
 */
interface AnonAuthConfig {
    /** NEAR network: 'testnet' | 'mainnet' */
    nearNetwork: 'testnet' | 'mainnet';
    /** Secret for signing session cookies */
    sessionSecret: string;
    /** Session duration in milliseconds (default: 7 days) */
    sessionDurationMs?: number;
    /** Database configuration */
    database: DatabaseConfig;
    /** Codename generation style */
    codename?: CodenameConfig;
    /** Recovery options */
    recovery?: RecoveryConfig;
    /** WebAuthn relying party configuration */
    rp?: {
        /** Relying party name (shown to users) */
        name: string;
        /** Relying party ID (usually your domain) */
        id: string;
        /** Origin for WebAuthn (e.g., https://example.com) */
        origin: string;
    };
    /** OAuth provider configuration */
    oauth?: OAuthConfig;
    /** MPC account configuration */
    mpc?: MPCAccountConfig;
}
interface MPCAccountConfig {
    /** Treasury account for auto-funding new accounts */
    treasuryAccount?: string;
    /** Treasury account private key (ed25519:...) */
    treasuryPrivateKey?: string;
    /** Amount of NEAR to fund new accounts (default: 0.01) */
    fundingAmount?: string;
    /** Account name prefix (default: 'anon') */
    accountPrefix?: string;
}
interface OAuthConfig {
    /** OAuth callback base URL (e.g., https://myapp.com/auth/callback) */
    callbackBaseUrl: string;
    /** Google OAuth */
    google?: {
        clientId: string;
        clientSecret: string;
    };
    /** GitHub OAuth */
    github?: {
        clientId: string;
        clientSecret: string;
    };
    /** X (Twitter) OAuth */
    twitter?: {
        clientId: string;
        clientSecret: string;
    };
}
interface DatabaseConfig {
    type: 'postgres' | 'sqlite' | 'custom';
    connectionString?: string;
    /** Custom adapter for database operations */
    adapter?: DatabaseAdapter;
}
interface CodenameConfig {
    /** Style of codename generation */
    style?: 'nato-phonetic' | 'animals' | 'custom';
    /** Custom codename generator function */
    generator?: (userId: string) => string;
}
interface RecoveryConfig {
    /** Enable wallet-based recovery (on-chain access key) */
    wallet?: boolean;
    /** Enable IPFS + password recovery */
    ipfs?: {
        pinningService: 'pinata' | 'web3storage' | 'infura' | 'custom';
        apiKey?: string;
        apiSecret?: string;
        /** Custom pinning function */
        customPin?: (data: Uint8Array) => Promise<string>;
        customFetch?: (cid: string) => Promise<Uint8Array>;
    };
}
interface DatabaseAdapter {
    /** Initialize database schema */
    initialize(): Promise<void>;
    createUser(user: CreateUserInput): Promise<AnonUser>;
    getUserById(id: string): Promise<AnonUser | null>;
    getUserByCodename(codename: string): Promise<AnonUser | null>;
    getUserByNearAccount(nearAccountId: string): Promise<AnonUser | null>;
    createOAuthUser(user: CreateOAuthUserInput): Promise<OAuthUser>;
    getOAuthUserById(id: string): Promise<OAuthUser | null>;
    getOAuthUserByEmail(email: string): Promise<OAuthUser | null>;
    getOAuthUserByProvider(provider: string, providerId: string): Promise<OAuthUser | null>;
    linkOAuthProvider(userId: string, provider: OAuthProvider): Promise<void>;
    createPasskey(passkey: CreatePasskeyInput): Promise<Passkey>;
    getPasskeyById(credentialId: string): Promise<Passkey | null>;
    getPasskeysByUserId(userId: string): Promise<Passkey[]>;
    updatePasskeyCounter(credentialId: string, counter: number): Promise<void>;
    deletePasskey(credentialId: string): Promise<void>;
    createSession(session: CreateSessionInput): Promise<Session>;
    getSession(sessionId: string): Promise<Session | null>;
    deleteSession(sessionId: string): Promise<void>;
    deleteUserSessions(userId: string): Promise<void>;
    cleanExpiredSessions(): Promise<number>;
    storeChallenge(challenge: Challenge): Promise<void>;
    getChallenge(challengeId: string): Promise<Challenge | null>;
    deleteChallenge(challengeId: string): Promise<void>;
    storeRecoveryData(data: RecoveryData): Promise<void>;
    getRecoveryData(userId: string, type: RecoveryType): Promise<RecoveryData | null>;
}
/**
 * User type enumeration
 */
type UserType = 'anonymous' | 'standard';
/**
 * Anonymous user (HUMINT sources) - passkey only, no PII
 */
interface AnonUser {
    id: string;
    type: 'anonymous';
    codename: string;
    nearAccountId: string;
    mpcPublicKey: string;
    derivationPath: string;
    createdAt: Date;
    lastActiveAt: Date;
}
interface CreateUserInput {
    codename: string;
    nearAccountId: string;
    mpcPublicKey: string;
    derivationPath: string;
}
/**
 * OAuth provider connection
 */
interface OAuthProvider {
    provider: 'google' | 'github' | 'twitter';
    providerId: string;
    email?: string;
    name?: string;
    avatarUrl?: string;
    connectedAt: Date;
}
/**
 * Standard user (OAuth/email) - full access, has PII
 */
interface OAuthUser {
    id: string;
    type: 'standard';
    email: string;
    name?: string;
    avatarUrl?: string;
    nearAccountId: string;
    mpcPublicKey: string;
    derivationPath: string;
    providers: OAuthProvider[];
    createdAt: Date;
    lastActiveAt: Date;
}
interface CreateOAuthUserInput {
    email: string;
    name?: string;
    avatarUrl?: string;
    nearAccountId: string;
    mpcPublicKey: string;
    derivationPath: string;
    provider: OAuthProvider;
}
/**
 * Union type for any user
 */
type User = AnonUser | OAuthUser;
interface Session {
    id: string;
    userId: string;
    createdAt: Date;
    expiresAt: Date;
    lastActivityAt: Date;
    ipAddress?: string;
    userAgent?: string;
}
interface CreateSessionInput {
    userId: string;
    expiresAt: Date;
    ipAddress?: string;
    userAgent?: string;
}
interface Passkey {
    credentialId: string;
    userId: string;
    publicKey: Uint8Array;
    counter: number;
    deviceType: 'singleDevice' | 'multiDevice';
    backedUp: boolean;
    transports?: AuthenticatorTransport[];
    createdAt: Date;
}
type AuthenticatorTransport = 'usb' | 'ble' | 'nfc' | 'internal' | 'hybrid';
interface CreatePasskeyInput {
    credentialId: string;
    userId: string;
    publicKey: Uint8Array;
    counter: number;
    deviceType: 'singleDevice' | 'multiDevice';
    backedUp: boolean;
    transports?: AuthenticatorTransport[];
}
interface Challenge {
    id: string;
    challenge: string;
    type: 'registration' | 'authentication' | 'recovery';
    userId?: string;
    expiresAt: Date;
    metadata?: Record<string, unknown>;
}
type RecoveryType = 'wallet' | 'ipfs';
interface RecoveryData {
    userId: string;
    type: RecoveryType;
    /** For wallet: NEAR account ID. For IPFS: CID */
    reference: string;
    createdAt: Date;
}
interface RegistrationStartResponse {
    challengeId: string;
    options: PublicKeyCredentialCreationOptionsJSON;
}
interface RegistrationFinishResponse {
    success: boolean;
    codename: string;
    nearAccountId: string;
}
interface AuthenticationStartResponse {
    challengeId: string;
    options: PublicKeyCredentialRequestOptionsJSON;
}
interface AuthenticationFinishResponse {
    success: boolean;
    codename: string;
}
interface PublicKeyCredentialCreationOptionsJSON {
    challenge: string;
    rp: {
        name: string;
        id: string;
    };
    user: {
        id: string;
        name: string;
        displayName: string;
    };
    pubKeyCredParams: Array<{
        type: 'public-key';
        alg: number;
    }>;
    timeout?: number;
    excludeCredentials?: Array<{
        id: string;
        type: 'public-key';
        transports?: AuthenticatorTransport[];
    }>;
    authenticatorSelection?: {
        authenticatorAttachment?: 'platform' | 'cross-platform';
        residentKey?: 'discouraged' | 'preferred' | 'required';
        requireResidentKey?: boolean;
        userVerification?: 'discouraged' | 'preferred' | 'required';
    };
    attestation?: 'none' | 'indirect' | 'direct' | 'enterprise';
}
interface PublicKeyCredentialRequestOptionsJSON {
    challenge: string;
    timeout?: number;
    rpId?: string;
    allowCredentials?: Array<{
        id: string;
        type: 'public-key';
        transports?: AuthenticatorTransport[];
    }>;
    userVerification?: 'discouraged' | 'preferred' | 'required';
}
interface RegistrationResponseJSON {
    id: string;
    rawId: string;
    type: 'public-key';
    response: {
        clientDataJSON: string;
        attestationObject: string;
        transports?: AuthenticatorTransport[];
    };
    clientExtensionResults: Record<string, unknown>;
    /** Authenticator attachment type (platform = device built-in, cross-platform = hardware key) */
    authenticatorAttachment?: 'platform' | 'cross-platform';
    /** Transport methods (for privacy detection) */
    transports?: AuthenticatorTransport[];
}
interface AuthenticationResponseJSON {
    id: string;
    rawId: string;
    type: 'public-key';
    response: {
        clientDataJSON: string;
        authenticatorData: string;
        signature: string;
        userHandle?: string;
    };
    clientExtensionResults: Record<string, unknown>;
}
interface AnonAuthRequest {
    anonUser?: AnonUser;
    anonSession?: Session;
}
declare global {
    namespace Express {
        interface Request extends AnonAuthRequest {
        }
    }
}

export type { AuthenticationStartResponse as A, CodenameConfig as C, DatabaseAdapter as D, OAuthConfig as O, PublicKeyCredentialRequestOptionsJSON as P, RegistrationStartResponse as R, Session as S, User as U, RegistrationResponseJSON as a, RegistrationFinishResponse as b, AuthenticationResponseJSON as c, AuthenticationFinishResponse as d, PublicKeyCredentialCreationOptionsJSON as e, AuthenticatorTransport as f, Passkey as g, AnonAuthConfig as h, AnonUser as i, OAuthProvider as j, OAuthUser as k, UserType as l, RecoveryConfig as m, RecoveryData as n, RecoveryType as o };
