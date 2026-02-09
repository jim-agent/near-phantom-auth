/**
 * PostgreSQL Database Adapter
 */

import type {
  DatabaseAdapter,
  AnonUser,
  CreateUserInput,
  Session,
  CreateSessionInput,
  Passkey,
  CreatePasskeyInput,
  Challenge,
  RecoveryData,
  RecoveryType,
  AuthenticatorTransport,
} from '../../../types/index.js';

export interface PostgresConfig {
  connectionString: string;
}

/**
 * SQL schema for near-anon-auth tables
 */
export const POSTGRES_SCHEMA = `
-- Anonymous users
CREATE TABLE IF NOT EXISTS anon_users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  codename TEXT UNIQUE NOT NULL,
  near_account_id TEXT UNIQUE NOT NULL,
  mpc_public_key TEXT NOT NULL,
  derivation_path TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_active_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Passkeys (WebAuthn credentials)
CREATE TABLE IF NOT EXISTS anon_passkeys (
  credential_id TEXT PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES anon_users(id) ON DELETE CASCADE,
  public_key BYTEA NOT NULL,
  counter BIGINT NOT NULL DEFAULT 0,
  device_type TEXT NOT NULL,
  backed_up BOOLEAN NOT NULL DEFAULT false,
  transports TEXT[],
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Sessions
CREATE TABLE IF NOT EXISTS anon_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES anon_users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  last_activity_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ip_address TEXT,
  user_agent TEXT
);

-- WebAuthn challenges (temporary)
CREATE TABLE IF NOT EXISTS anon_challenges (
  id UUID PRIMARY KEY,
  challenge TEXT NOT NULL,
  type TEXT NOT NULL,
  user_id UUID REFERENCES anon_users(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL,
  metadata JSONB
);

-- Recovery data references
CREATE TABLE IF NOT EXISTS anon_recovery (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES anon_users(id) ON DELETE CASCADE,
  type TEXT NOT NULL,
  reference TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(user_id, type)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_anon_sessions_user ON anon_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_anon_sessions_expires ON anon_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_anon_passkeys_user ON anon_passkeys(user_id);
CREATE INDEX IF NOT EXISTS idx_anon_challenges_expires ON anon_challenges(expires_at);
`;

/**
 * Create PostgreSQL adapter
 * 
 * Note: Requires 'pg' package to be installed by the consuming application
 */
export function createPostgresAdapter(config: PostgresConfig): DatabaseAdapter {
  // Dynamic import of pg to make it optional
  let pool: import('pg').Pool | null = null;
  
  async function getPool(): Promise<import('pg').Pool> {
    if (!pool) {
      const { Pool } = await import('pg');
      pool = new Pool({ connectionString: config.connectionString });
    }
    return pool;
  }

  return {
    async initialize() {
      const p = await getPool();
      await p.query(POSTGRES_SCHEMA);
    },

    async createUser(input: CreateUserInput): Promise<AnonUser> {
      const p = await getPool();
      const result = await p.query(
        `INSERT INTO anon_users (codename, near_account_id, mpc_public_key, derivation_path)
         VALUES ($1, $2, $3, $4)
         RETURNING id, codename, near_account_id, mpc_public_key, derivation_path, created_at, last_active_at`,
        [input.codename, input.nearAccountId, input.mpcPublicKey, input.derivationPath]
      );
      
      const row = result.rows[0];
      return {
        id: row.id,
        codename: row.codename,
        nearAccountId: row.near_account_id,
        mpcPublicKey: row.mpc_public_key,
        derivationPath: row.derivation_path,
        createdAt: row.created_at,
        lastActiveAt: row.last_active_at,
      };
    },

    async getUserById(id: string): Promise<AnonUser | null> {
      const p = await getPool();
      const result = await p.query(
        'SELECT * FROM anon_users WHERE id = $1',
        [id]
      );
      
      if (result.rows.length === 0) return null;
      
      const row = result.rows[0];
      return {
        id: row.id,
        codename: row.codename,
        nearAccountId: row.near_account_id,
        mpcPublicKey: row.mpc_public_key,
        derivationPath: row.derivation_path,
        createdAt: row.created_at,
        lastActiveAt: row.last_active_at,
      };
    },

    async getUserByCodename(codename: string): Promise<AnonUser | null> {
      const p = await getPool();
      const result = await p.query(
        'SELECT * FROM anon_users WHERE codename = $1',
        [codename]
      );
      
      if (result.rows.length === 0) return null;
      
      const row = result.rows[0];
      return {
        id: row.id,
        codename: row.codename,
        nearAccountId: row.near_account_id,
        mpcPublicKey: row.mpc_public_key,
        derivationPath: row.derivation_path,
        createdAt: row.created_at,
        lastActiveAt: row.last_active_at,
      };
    },

    async getUserByNearAccount(nearAccountId: string): Promise<AnonUser | null> {
      const p = await getPool();
      const result = await p.query(
        'SELECT * FROM anon_users WHERE near_account_id = $1',
        [nearAccountId]
      );
      
      if (result.rows.length === 0) return null;
      
      const row = result.rows[0];
      return {
        id: row.id,
        codename: row.codename,
        nearAccountId: row.near_account_id,
        mpcPublicKey: row.mpc_public_key,
        derivationPath: row.derivation_path,
        createdAt: row.created_at,
        lastActiveAt: row.last_active_at,
      };
    },

    async createPasskey(input: CreatePasskeyInput): Promise<Passkey> {
      const p = await getPool();
      await p.query(
        `INSERT INTO anon_passkeys (credential_id, user_id, public_key, counter, device_type, backed_up, transports)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [
          input.credentialId,
          input.userId,
          input.publicKey,
          input.counter,
          input.deviceType,
          input.backedUp,
          input.transports || null,
        ]
      );
      
      return {
        ...input,
        createdAt: new Date(),
      };
    },

    async getPasskeyById(credentialId: string): Promise<Passkey | null> {
      const p = await getPool();
      const result = await p.query(
        'SELECT * FROM anon_passkeys WHERE credential_id = $1',
        [credentialId]
      );
      
      if (result.rows.length === 0) return null;
      
      const row = result.rows[0];
      return {
        credentialId: row.credential_id,
        userId: row.user_id,
        publicKey: row.public_key,
        counter: row.counter,
        deviceType: row.device_type,
        backedUp: row.backed_up,
        transports: row.transports,
        createdAt: row.created_at,
      };
    },

    async getPasskeysByUserId(userId: string): Promise<Passkey[]> {
      const p = await getPool();
      const result = await p.query(
        'SELECT * FROM anon_passkeys WHERE user_id = $1',
        [userId]
      );
      
      return result.rows.map((row: Record<string, unknown>) => ({
        credentialId: row.credential_id as string,
        userId: row.user_id as string,
        publicKey: row.public_key as Uint8Array,
        counter: row.counter as number,
        deviceType: row.device_type as 'singleDevice' | 'multiDevice',
        backedUp: row.backed_up as boolean,
        transports: row.transports as AuthenticatorTransport[] | undefined,
        createdAt: row.created_at as Date,
      }));
    },

    async updatePasskeyCounter(credentialId: string, counter: number): Promise<void> {
      const p = await getPool();
      await p.query(
        'UPDATE anon_passkeys SET counter = $1 WHERE credential_id = $2',
        [counter, credentialId]
      );
    },

    async deletePasskey(credentialId: string): Promise<void> {
      const p = await getPool();
      await p.query('DELETE FROM anon_passkeys WHERE credential_id = $1', [credentialId]);
    },

    async createSession(input: CreateSessionInput & { id?: string }): Promise<Session> {
      const p = await getPool();
      const result = await p.query(
        `INSERT INTO anon_sessions (id, user_id, expires_at, ip_address, user_agent)
         VALUES (COALESCE($1, gen_random_uuid()), $2, $3, $4, $5)
         RETURNING id, user_id, created_at, expires_at, last_activity_at, ip_address, user_agent`,
        [input.id || null, input.userId, input.expiresAt, input.ipAddress || null, input.userAgent || null]
      );
      
      const row = result.rows[0];
      return {
        id: row.id,
        userId: row.user_id,
        createdAt: row.created_at,
        expiresAt: row.expires_at,
        lastActivityAt: row.last_activity_at,
        ipAddress: row.ip_address,
        userAgent: row.user_agent,
      };
    },

    async getSession(sessionId: string): Promise<Session | null> {
      const p = await getPool();
      const result = await p.query(
        'SELECT * FROM anon_sessions WHERE id = $1 AND expires_at > NOW()',
        [sessionId]
      );
      
      if (result.rows.length === 0) return null;
      
      const row = result.rows[0];
      return {
        id: row.id,
        userId: row.user_id,
        createdAt: row.created_at,
        expiresAt: row.expires_at,
        lastActivityAt: row.last_activity_at,
        ipAddress: row.ip_address,
        userAgent: row.user_agent,
      };
    },

    async deleteSession(sessionId: string): Promise<void> {
      const p = await getPool();
      await p.query('DELETE FROM anon_sessions WHERE id = $1', [sessionId]);
    },

    async deleteUserSessions(userId: string): Promise<void> {
      const p = await getPool();
      await p.query('DELETE FROM anon_sessions WHERE user_id = $1', [userId]);
    },

    async cleanExpiredSessions(): Promise<number> {
      const p = await getPool();
      const result = await p.query('DELETE FROM anon_sessions WHERE expires_at < NOW()');
      return result.rowCount || 0;
    },

    async storeChallenge(challenge: Challenge): Promise<void> {
      const p = await getPool();
      await p.query(
        `INSERT INTO anon_challenges (id, challenge, type, user_id, expires_at, metadata)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [
          challenge.id,
          challenge.challenge,
          challenge.type,
          challenge.userId || null,
          challenge.expiresAt,
          challenge.metadata ? JSON.stringify(challenge.metadata) : null,
        ]
      );
    },

    async getChallenge(challengeId: string): Promise<Challenge | null> {
      const p = await getPool();
      const result = await p.query(
        'SELECT * FROM anon_challenges WHERE id = $1',
        [challengeId]
      );
      
      if (result.rows.length === 0) return null;
      
      const row = result.rows[0];
      return {
        id: row.id,
        challenge: row.challenge,
        type: row.type,
        userId: row.user_id,
        expiresAt: row.expires_at,
        metadata: row.metadata,
      };
    },

    async deleteChallenge(challengeId: string): Promise<void> {
      const p = await getPool();
      await p.query('DELETE FROM anon_challenges WHERE id = $1', [challengeId]);
    },

    async storeRecoveryData(data: RecoveryData): Promise<void> {
      const p = await getPool();
      await p.query(
        `INSERT INTO anon_recovery (user_id, type, reference)
         VALUES ($1, $2, $3)
         ON CONFLICT (user_id, type) DO UPDATE SET reference = $3, created_at = NOW()`,
        [data.userId, data.type, data.reference]
      );
    },

    async getRecoveryData(userId: string, type: RecoveryType): Promise<RecoveryData | null> {
      const p = await getPool();
      const result = await p.query(
        'SELECT * FROM anon_recovery WHERE user_id = $1 AND type = $2',
        [userId, type]
      );
      
      if (result.rows.length === 0) return null;
      
      const row = result.rows[0];
      return {
        userId: row.user_id,
        type: row.type,
        reference: row.reference,
        createdAt: row.created_at,
      };
    },
  };
}
