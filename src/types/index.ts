/**
 * Core types for near-anon-auth
 */

// ============================================
// Configuration
// ============================================

export interface AnonAuthConfig {
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
}

export interface DatabaseConfig {
  type: 'postgres' | 'sqlite' | 'custom';
  connectionString?: string;
  /** Custom adapter for database operations */
  adapter?: DatabaseAdapter;
}

export interface CodenameConfig {
  /** Style of codename generation */
  style?: 'nato-phonetic' | 'animals' | 'custom';
  /** Custom codename generator function */
  generator?: (userId: string) => string;
}

export interface RecoveryConfig {
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

// ============================================
// Database Adapter
// ============================================

export interface DatabaseAdapter {
  /** Initialize database schema */
  initialize(): Promise<void>;
  
  // Users
  createUser(user: CreateUserInput): Promise<AnonUser>;
  getUserById(id: string): Promise<AnonUser | null>;
  getUserByCodename(codename: string): Promise<AnonUser | null>;
  getUserByNearAccount(nearAccountId: string): Promise<AnonUser | null>;
  
  // Passkeys
  createPasskey(passkey: CreatePasskeyInput): Promise<Passkey>;
  getPasskeyById(credentialId: string): Promise<Passkey | null>;
  getPasskeysByUserId(userId: string): Promise<Passkey[]>;
  updatePasskeyCounter(credentialId: string, counter: number): Promise<void>;
  deletePasskey(credentialId: string): Promise<void>;
  
  // Sessions
  createSession(session: CreateSessionInput): Promise<Session>;
  getSession(sessionId: string): Promise<Session | null>;
  deleteSession(sessionId: string): Promise<void>;
  deleteUserSessions(userId: string): Promise<void>;
  cleanExpiredSessions(): Promise<number>;
  
  // Challenges (for WebAuthn)
  storeChallenge(challenge: Challenge): Promise<void>;
  getChallenge(challengeId: string): Promise<Challenge | null>;
  deleteChallenge(challengeId: string): Promise<void>;
  
  // Recovery
  storeRecoveryData(data: RecoveryData): Promise<void>;
  getRecoveryData(userId: string, type: RecoveryType): Promise<RecoveryData | null>;
}

// ============================================
// User & Session
// ============================================

export interface AnonUser {
  id: string;
  codename: string;
  nearAccountId: string;
  mpcPublicKey: string;
  derivationPath: string;
  createdAt: Date;
  lastActiveAt: Date;
}

export interface CreateUserInput {
  codename: string;
  nearAccountId: string;
  mpcPublicKey: string;
  derivationPath: string;
}

export interface Session {
  id: string;
  userId: string;
  createdAt: Date;
  expiresAt: Date;
  lastActivityAt: Date;
  ipAddress?: string;
  userAgent?: string;
}

export interface CreateSessionInput {
  userId: string;
  expiresAt: Date;
  ipAddress?: string;
  userAgent?: string;
}

// ============================================
// Passkeys (WebAuthn)
// ============================================

export interface Passkey {
  credentialId: string;
  userId: string;
  publicKey: Uint8Array;
  counter: number;
  deviceType: 'singleDevice' | 'multiDevice';
  backedUp: boolean;
  transports?: AuthenticatorTransport[];
  createdAt: Date;
}

export type AuthenticatorTransport = 'usb' | 'ble' | 'nfc' | 'internal' | 'hybrid';

export interface CreatePasskeyInput {
  credentialId: string;
  userId: string;
  publicKey: Uint8Array;
  counter: number;
  deviceType: 'singleDevice' | 'multiDevice';
  backedUp: boolean;
  transports?: AuthenticatorTransport[];
}

// ============================================
// Challenges
// ============================================

export interface Challenge {
  id: string;
  challenge: string;
  type: 'registration' | 'authentication' | 'recovery';
  userId?: string;
  expiresAt: Date;
  metadata?: Record<string, unknown>;
}

// ============================================
// Recovery
// ============================================

export type RecoveryType = 'wallet' | 'ipfs';

export interface RecoveryData {
  userId: string;
  type: RecoveryType;
  /** For wallet: NEAR account ID. For IPFS: CID */
  reference: string;
  createdAt: Date;
}

// ============================================
// API Responses
// ============================================

export interface RegistrationStartResponse {
  challengeId: string;
  options: PublicKeyCredentialCreationOptionsJSON;
}

export interface RegistrationFinishResponse {
  success: boolean;
  codename: string;
  nearAccountId: string;
}

export interface AuthenticationStartResponse {
  challengeId: string;
  options: PublicKeyCredentialRequestOptionsJSON;
}

export interface AuthenticationFinishResponse {
  success: boolean;
  codename: string;
}

export interface RecoveryWalletLinkResponse {
  success: boolean;
  nearAccountId: string;
  message: string;
}

export interface RecoveryIPFSSetupResponse {
  success: boolean;
  cid: string;
  message: string;
}

// ============================================
// WebAuthn JSON Types (for API transport)
// ============================================

export interface PublicKeyCredentialCreationOptionsJSON {
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

export interface PublicKeyCredentialRequestOptionsJSON {
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

export interface RegistrationResponseJSON {
  id: string;
  rawId: string;
  type: 'public-key';
  response: {
    clientDataJSON: string;
    attestationObject: string;
    transports?: AuthenticatorTransport[];
  };
  clientExtensionResults: Record<string, unknown>;
}

export interface AuthenticationResponseJSON {
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

// ============================================
// Express Integration
// ============================================

export interface AnonAuthRequest {
  anonUser?: AnonUser;
  anonSession?: Session;
}

declare global {
  namespace Express {
    interface Request extends AnonAuthRequest {}
  }
}
