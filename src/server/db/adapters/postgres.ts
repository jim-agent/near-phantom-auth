/**
 * PostgreSQL Database Adapter
 */

import type {
  DatabaseAdapter,
  AnonUser,
  CreateUserInput,
  OAuthUser,
  CreateOAuthUserInput,
  OAuthProvider,
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
-- Anonymous users (HUMINT sources - passkey only)
CREATE TABLE IF NOT EXISTS anon_users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  codename TEXT UNIQUE NOT NULL,
  near_account_id TEXT UNIQUE NOT NULL,
  mpc_public_key TEXT NOT NULL,
  derivation_path TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_active_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- OAuth users (standard users - OAuth providers)
CREATE TABLE IF NOT EXISTS oauth_users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT UNIQUE NOT NULL,
  name TEXT,
  avatar_url TEXT,
  near_account_id TEXT UNIQUE NOT NULL,
  mpc_public_key TEXT NOT NULL,
  derivation_path TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_active_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- OAuth provider connections
CREATE TABLE IF NOT EXISTS oauth_providers (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES oauth_users(id) ON DELETE CASCADE,
  provider TEXT NOT NULL,
  provider_id TEXT NOT NULL,
  email TEXT,
  name TEXT,
  avatar_url TEXT,
  connected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(provider, provider_id)
);

-- Passkeys (WebAuthn credentials) - for anonymous users
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

-- Sessions (works for both user types)
CREATE TABLE IF NOT EXISTS anon_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,
  user_type TEXT NOT NULL DEFAULT 'anonymous',
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
  user_id UUID,
  expires_at TIMESTAMPTZ NOT NULL,
  metadata JSONB
);

-- Recovery data references (works for both user types)
CREATE TABLE IF NOT EXISTS anon_recovery (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,
  user_type TEXT NOT NULL DEFAULT 'anonymous',
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
CREATE INDEX IF NOT EXISTS idx_oauth_users_email ON oauth_users(email);
CREATE INDEX IF NOT EXISTS idx_oauth_providers_user ON oauth_providers(user_id);
CREATE INDEX IF NOT EXISTS idx_oauth_providers_lookup ON oauth_providers(provider, provider_id);
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
        type: 'anonymous' as const,
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
        type: 'anonymous',
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
        type: 'anonymous',
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
        type: 'anonymous',
        codename: row.codename,
        nearAccountId: row.near_account_id,
        mpcPublicKey: row.mpc_public_key,
        derivationPath: row.derivation_path,
        createdAt: row.created_at,
        lastActiveAt: row.last_active_at,
      };
    },

    // ============================================
    // OAuth Users
    // ============================================

    async createOAuthUser(input: CreateOAuthUserInput): Promise<OAuthUser> {
      const p = await getPool();
      const client = await p.connect();
      
      try {
        await client.query('BEGIN');
        
        // Create user
        const userResult = await client.query(
          `INSERT INTO oauth_users (email, name, avatar_url, near_account_id, mpc_public_key, derivation_path)
           VALUES ($1, $2, $3, $4, $5, $6)
           RETURNING *`,
          [input.email, input.name, input.avatarUrl, input.nearAccountId, input.mpcPublicKey, input.derivationPath]
        );
        
        const userRow = userResult.rows[0];
        
        // Create provider connection
        await client.query(
          `INSERT INTO oauth_providers (user_id, provider, provider_id, email, name, avatar_url)
           VALUES ($1, $2, $3, $4, $5, $6)`,
          [
            userRow.id,
            input.provider.provider,
            input.provider.providerId,
            input.provider.email,
            input.provider.name,
            input.provider.avatarUrl,
          ]
        );
        
        await client.query('COMMIT');
        
        return {
          id: userRow.id,
          type: 'standard',
          email: userRow.email,
          name: userRow.name,
          avatarUrl: userRow.avatar_url,
          nearAccountId: userRow.near_account_id,
          mpcPublicKey: userRow.mpc_public_key,
          derivationPath: userRow.derivation_path,
          providers: [input.provider],
          createdAt: userRow.created_at,
          lastActiveAt: userRow.last_active_at,
        };
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      } finally {
        client.release();
      }
    },

    async getOAuthUserById(id: string): Promise<OAuthUser | null> {
      const p = await getPool();
      const userResult = await p.query(
        'SELECT * FROM oauth_users WHERE id = $1',
        [id]
      );
      
      if (userResult.rows.length === 0) return null;
      
      const userRow = userResult.rows[0];
      
      // Get providers
      const providersResult = await p.query(
        'SELECT * FROM oauth_providers WHERE user_id = $1',
        [id]
      );
      
      const providers: OAuthProvider[] = providersResult.rows.map((row: Record<string, unknown>) => ({
        provider: row.provider as 'google' | 'github' | 'twitter',
        providerId: row.provider_id as string,
        email: row.email as string | undefined,
        name: row.name as string | undefined,
        avatarUrl: row.avatar_url as string | undefined,
        connectedAt: row.connected_at as Date,
      }));
      
      return {
        id: userRow.id,
        type: 'standard',
        email: userRow.email,
        name: userRow.name,
        avatarUrl: userRow.avatar_url,
        nearAccountId: userRow.near_account_id,
        mpcPublicKey: userRow.mpc_public_key,
        derivationPath: userRow.derivation_path,
        providers,
        createdAt: userRow.created_at,
        lastActiveAt: userRow.last_active_at,
      };
    },

    async getOAuthUserByEmail(email: string): Promise<OAuthUser | null> {
      const p = await getPool();
      const userResult = await p.query(
        'SELECT * FROM oauth_users WHERE email = $1',
        [email]
      );
      
      if (userResult.rows.length === 0) return null;
      
      const userRow = userResult.rows[0];
      
      // Get providers
      const providersResult = await p.query(
        'SELECT * FROM oauth_providers WHERE user_id = $1',
        [userRow.id]
      );
      
      const providers: OAuthProvider[] = providersResult.rows.map((row: Record<string, unknown>) => ({
        provider: row.provider as 'google' | 'github' | 'twitter',
        providerId: row.provider_id as string,
        email: row.email as string | undefined,
        name: row.name as string | undefined,
        avatarUrl: row.avatar_url as string | undefined,
        connectedAt: row.connected_at as Date,
      }));
      
      return {
        id: userRow.id,
        type: 'standard',
        email: userRow.email,
        name: userRow.name,
        avatarUrl: userRow.avatar_url,
        nearAccountId: userRow.near_account_id,
        mpcPublicKey: userRow.mpc_public_key,
        derivationPath: userRow.derivation_path,
        providers,
        createdAt: userRow.created_at,
        lastActiveAt: userRow.last_active_at,
      };
    },

    async getOAuthUserByProvider(provider: string, providerId: string): Promise<OAuthUser | null> {
      const p = await getPool();
      const providerResult = await p.query(
        'SELECT user_id FROM oauth_providers WHERE provider = $1 AND provider_id = $2',
        [provider, providerId]
      );
      
      if (providerResult.rows.length === 0) return null;
      
      const userId = providerResult.rows[0].user_id;
      return this.getOAuthUserById(userId);
    },

    async linkOAuthProvider(userId: string, provider: OAuthProvider): Promise<void> {
      const p = await getPool();
      await p.query(
        `INSERT INTO oauth_providers (user_id, provider, provider_id, email, name, avatar_url)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (provider, provider_id) DO UPDATE SET
           email = EXCLUDED.email,
           name = EXCLUDED.name,
           avatar_url = EXCLUDED.avatar_url`,
        [
          userId,
          provider.provider,
          provider.providerId,
          provider.email,
          provider.name,
          provider.avatarUrl,
        ]
      );
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
