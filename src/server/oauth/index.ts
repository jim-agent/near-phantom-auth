/**
 * OAuth Provider Manager
 * 
 * Manages OAuth authentication alongside passkey auth.
 * Supports Google, GitHub, and X (Twitter) OAuth providers.
 */

import type { DatabaseAdapter, OAuthUser, CreateOAuthUserInput } from '../../types/index.js';
import { createHash, randomBytes } from 'crypto';

export interface OAuthProviderConfig {
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

export interface OAuthState {
  provider: 'google' | 'github' | 'twitter';
  state: string;
  codeVerifier?: string;
  redirectUri: string;
  expiresAt: Date;
}

export interface OAuthTokens {
  accessToken: string;
  refreshToken?: string;
  expiresIn: number;
  tokenType: string;
}

export interface OAuthProfile {
  provider: 'google' | 'github' | 'twitter';
  providerId: string;
  email?: string;
  name?: string;
  avatarUrl?: string;
  raw: Record<string, unknown>;
}

export interface OAuthManager {
  getAuthUrl(provider: 'google' | 'github' | 'twitter', redirectUri: string): Promise<{
    url: string;
    state: string;
    codeVerifier?: string;
  }>;
  
  exchangeCode(
    provider: 'google' | 'github' | 'twitter',
    code: string,
    redirectUri: string,
    codeVerifier?: string
  ): Promise<OAuthTokens>;
  
  getProfile(provider: 'google' | 'github' | 'twitter', accessToken: string): Promise<OAuthProfile>;
  
  validateState(state: string): Promise<OAuthState | null>;
  
  isConfigured(provider: 'google' | 'github' | 'twitter'): boolean;
}

/**
 * Generate PKCE code verifier and challenge
 */
function generatePKCE(): { codeVerifier: string; codeChallenge: string } {
  const codeVerifier = randomBytes(32).toString('base64url');
  const codeChallenge = createHash('sha256')
    .update(codeVerifier)
    .digest('base64url');
  return { codeVerifier, codeChallenge };
}

/**
 * Generate state parameter for OAuth
 */
function generateState(): string {
  return randomBytes(32).toString('base64url');
}

/**
 * Create OAuth Manager
 */
export function createOAuthManager(
  config: OAuthProviderConfig,
  db: DatabaseAdapter
): OAuthManager {
  const stateStore = new Map<string, OAuthState>();

  return {
    isConfigured(provider) {
      return !!config[provider]?.clientId;
    },

    async getAuthUrl(provider, redirectUri) {
      const providerConfig = config[provider];
      if (!providerConfig) {
        throw new Error(`Provider ${provider} not configured`);
      }

      const state = generateState();
      const { codeVerifier, codeChallenge } = generatePKCE();

      let url: string;
      const { clientId } = providerConfig;

      switch (provider) {
        case 'google': {
          const params = new URLSearchParams({
            client_id: clientId,
            redirect_uri: redirectUri,
            response_type: 'code',
            scope: 'openid email profile',
            state,
            code_challenge: codeChallenge,
            code_challenge_method: 'S256',
            access_type: 'offline',
            prompt: 'consent',
          });
          url = `https://accounts.google.com/o/oauth2/v2/auth?${params}`;
          break;
        }

        case 'github': {
          const params = new URLSearchParams({
            client_id: clientId,
            redirect_uri: redirectUri,
            scope: 'read:user user:email',
            state,
          });
          url = `https://github.com/login/oauth/authorize?${params}`;
          break;
        }

        case 'twitter': {
          const params = new URLSearchParams({
            client_id: clientId,
            redirect_uri: redirectUri,
            response_type: 'code',
            scope: 'tweet.read users.read offline.access',
            state,
            code_challenge: codeChallenge,
            code_challenge_method: 'S256',
          });
          url = `https://twitter.com/i/oauth2/authorize?${params}`;
          break;
        }

        default:
          throw new Error(`Unknown provider: ${provider}`);
      }

      // Store state for validation
      const oauthState: OAuthState = {
        provider,
        state,
        codeVerifier,
        redirectUri,
        expiresAt: new Date(Date.now() + 10 * 60 * 1000), // 10 minutes
      };
      stateStore.set(state, oauthState);

      // Clean up old states
      for (const [key, value] of stateStore.entries()) {
        if (value.expiresAt < new Date()) {
          stateStore.delete(key);
        }
      }

      return { url, state, codeVerifier };
    },

    async exchangeCode(provider, code, redirectUri, codeVerifier) {
      const providerConfig = config[provider];
      if (!providerConfig) {
        throw new Error(`Provider ${provider} not configured`);
      }

      const { clientId, clientSecret } = providerConfig;
      let tokenUrl: string;
      let body: URLSearchParams;

      switch (provider) {
        case 'google': {
          tokenUrl = 'https://oauth2.googleapis.com/token';
          body = new URLSearchParams({
            client_id: clientId,
            client_secret: clientSecret,
            code,
            redirect_uri: redirectUri,
            grant_type: 'authorization_code',
            code_verifier: codeVerifier || '',
          });
          break;
        }

        case 'github': {
          tokenUrl = 'https://github.com/login/oauth/access_token';
          body = new URLSearchParams({
            client_id: clientId,
            client_secret: clientSecret,
            code,
            redirect_uri: redirectUri,
          });
          break;
        }

        case 'twitter': {
          tokenUrl = 'https://api.twitter.com/2/oauth2/token';
          body = new URLSearchParams({
            client_id: clientId,
            code,
            redirect_uri: redirectUri,
            grant_type: 'authorization_code',
            code_verifier: codeVerifier || '',
          });
          break;
        }

        default:
          throw new Error(`Unknown provider: ${provider}`);
      }

      const headers: Record<string, string> = {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
      };

      // Twitter requires Basic auth
      if (provider === 'twitter') {
        const credentials = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
        headers['Authorization'] = `Basic ${credentials}`;
      }

      const response = await fetch(tokenUrl, {
        method: 'POST',
        headers,
        body,
      });

      if (!response.ok) {
        const error = await response.text();
        throw new Error(`Token exchange failed: ${error}`);
      }

      const data = await response.json() as {
        access_token: string;
        refresh_token?: string;
        expires_in?: number;
        token_type?: string;
      };

      return {
        accessToken: data.access_token,
        refreshToken: data.refresh_token,
        expiresIn: data.expires_in || 3600,
        tokenType: data.token_type || 'Bearer',
      };
    },

    async getProfile(provider, accessToken) {
      let profileUrl: string;
      const headers: Record<string, string> = {
        Authorization: `Bearer ${accessToken}`,
        Accept: 'application/json',
      };

      switch (provider) {
        case 'google':
          profileUrl = 'https://www.googleapis.com/oauth2/v2/userinfo';
          break;

        case 'github':
          profileUrl = 'https://api.github.com/user';
          break;

        case 'twitter':
          profileUrl = 'https://api.twitter.com/2/users/me?user.fields=profile_image_url';
          break;

        default:
          throw new Error(`Unknown provider: ${provider}`);
      }

      const response = await fetch(profileUrl, { headers });

      if (!response.ok) {
        const error = await response.text();
        throw new Error(`Profile fetch failed: ${error}`);
      }

      const data = await response.json() as Record<string, unknown>;

      // Normalize profile data
      switch (provider) {
        case 'google':
          return {
            provider,
            providerId: String(data.id),
            email: data.email as string | undefined,
            name: data.name as string | undefined,
            avatarUrl: data.picture as string | undefined,
            raw: data,
          };

        case 'github': {
          // GitHub requires separate call for email if private
          let email = data.email as string | undefined;
          if (!email) {
            try {
              const emailResponse = await fetch('https://api.github.com/user/emails', { headers });
              if (emailResponse.ok) {
                const emails = await emailResponse.json() as Array<{
                  email: string;
                  primary: boolean;
                  verified: boolean;
                }>;
                const primary = emails.find(e => e.primary && e.verified);
                email = primary?.email;
              }
            } catch {
              // Email fetch failed, continue without
            }
          }
          return {
            provider,
            providerId: String(data.id),
            email,
            name: (data.name || data.login) as string | undefined,
            avatarUrl: data.avatar_url as string | undefined,
            raw: data,
          };
        }

        case 'twitter': {
          const twitterData = data.data as Record<string, unknown>;
          return {
            provider,
            providerId: String(twitterData.id),
            email: undefined, // Twitter doesn't provide email
            name: twitterData.name as string | undefined,
            avatarUrl: twitterData.profile_image_url as string | undefined,
            raw: data,
          };
        }

        default:
          throw new Error(`Unknown provider: ${provider}`);
      }
    },

    async validateState(state) {
      const oauthState = stateStore.get(state);
      if (!oauthState) {
        return null;
      }
      if (oauthState.expiresAt < new Date()) {
        stateStore.delete(state);
        return null;
      }
      stateStore.delete(state);
      return oauthState;
    },
  };
}

export type { OAuthProviderConfig, OAuthProfile, OAuthTokens };
