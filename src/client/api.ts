/**
 * API Client for near-anon-auth server
 */

import type {
  RegistrationStartResponse,
  RegistrationFinishResponse,
  AuthenticationStartResponse,
  AuthenticationFinishResponse,
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
} from '../types/index.js';

export interface ApiClientConfig {
  /** Base URL for auth API (e.g., '/auth' or 'https://api.example.com/auth') */
  baseUrl: string;
  /** Custom fetch function (optional) */
  fetch?: typeof fetch;
}

export interface SessionInfo {
  authenticated: boolean;
  codename?: string;
  username?: string;
  nearAccountId?: string;
  expiresAt?: string;
  authMethod?: 'passkey' | 'oauth' | 'email';
  email?: string;
}

export interface OAuthProvider {
  name: string;
  authUrl: string;
}

export interface ApiClient {
  // Registration with optional username
  startRegistration(username?: string): Promise<RegistrationStartResponse & { codename: string; tempUserId: string; username?: string }>;
  finishRegistration(
    challengeId: string,
    response: RegistrationResponseJSON,
    tempUserId: string,
    codename: string,
    username?: string
  ): Promise<RegistrationFinishResponse & { username?: string }>;
  
  // Check username availability
  checkUsername(username: string): Promise<{ available: boolean; suggestion?: string }>;
  
  // Authentication
  startAuthentication(codename?: string): Promise<AuthenticationStartResponse>;
  finishAuthentication(
    challengeId: string,
    response: AuthenticationResponseJSON
  ): Promise<AuthenticationFinishResponse>;
  
  // OAuth
  getOAuthProviders(): Promise<{ providers: OAuthProvider[] }>;
  startOAuth(provider: string): Promise<{ authUrl: string }>;
  
  // Email Magic Link
  sendMagicLink(email: string): Promise<{ success: boolean; message: string }>;
  verifyMagicLink(token: string): Promise<{ success: boolean; codename?: string; nearAccountId?: string }>;
  
  // Session
  getSession(): Promise<SessionInfo>;
  logout(): Promise<void>;
  
  // Wallet Recovery
  startWalletLink(): Promise<{ challenge: string; expiresAt: string }>;
  finishWalletLink(
    signature: unknown,
    challenge: string,
    walletAccountId: string
  ): Promise<{ success: boolean; message: string }>;
  startWalletRecovery(): Promise<{ challenge: string; expiresAt: string }>;
  finishWalletRecovery(
    signature: unknown,
    challenge: string,
    nearAccountId: string
  ): Promise<{ success: boolean; codename: string; message: string }>;
  
  // IPFS Recovery
  setupIPFSRecovery(password: string): Promise<{ success: boolean; cid: string; message: string }>;
  recoverFromIPFS(cid: string, password: string): Promise<{ success: boolean; codename: string; message: string }>;
}

/**
 * Create API client
 */
export function createApiClient(config: ApiClientConfig): ApiClient {
  const fetchFn = config.fetch || fetch;
  const baseUrl = config.baseUrl.replace(/\/$/, ''); // Remove trailing slash

  async function request<T>(
    method: string,
    path: string,
    body?: unknown
  ): Promise<T> {
    const response = await fetchFn(`${baseUrl}${path}`, {
      method,
      headers: {
        'Content-Type': 'application/json',
      },
      credentials: 'include', // Include cookies
      body: body ? JSON.stringify(body) : undefined,
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: 'Request failed' }));
      throw new Error(error.error || `Request failed: ${response.status}`);
    }

    return response.json();
  }

  return {
    // Registration with optional username
    async startRegistration(username?: string) {
      return request('POST', '/register/start', username ? { username } : undefined);
    },

    async finishRegistration(challengeId, response, tempUserId, codename, username?: string) {
      return request('POST', '/register/finish', {
        challengeId,
        response,
        tempUserId,
        codename,
        username,
      });
    },

    // Check username availability
    async checkUsername(username: string) {
      return request('POST', '/username/check', { username });
    },

    // Authentication
    async startAuthentication(codename) {
      return request('POST', '/login/start', { codename });
    },

    async finishAuthentication(challengeId, response) {
      return request('POST', '/login/finish', {
        challengeId,
        response,
      });
    },

    // OAuth
    async getOAuthProviders() {
      return request('GET', '/oauth/providers');
    },

    async startOAuth(provider: string) {
      return request('POST', '/oauth/start', { provider });
    },

    // Email Magic Link
    async sendMagicLink(email: string) {
      return request('POST', '/email/send', { email });
    },

    async verifyMagicLink(token: string) {
      return request('POST', '/email/verify', { token });
    },

    // Session
    async getSession() {
      try {
        return await request('GET', '/session');
      } catch {
        return { authenticated: false };
      }
    },

    async logout() {
      await request('POST', '/logout');
    },

    // Wallet Recovery
    async startWalletLink() {
      return request('POST', '/recovery/wallet/link');
    },

    async finishWalletLink(signature, challenge, walletAccountId) {
      return request('POST', '/recovery/wallet/verify', {
        signature,
        challenge,
        walletAccountId,
      });
    },

    async startWalletRecovery() {
      return request('POST', '/recovery/wallet/start');
    },

    async finishWalletRecovery(signature, challenge, nearAccountId) {
      return request('POST', '/recovery/wallet/finish', {
        signature,
        challenge,
        nearAccountId,
      });
    },

    // IPFS Recovery
    async setupIPFSRecovery(password) {
      return request('POST', '/recovery/ipfs/setup', { password });
    },

    async recoverFromIPFS(cid, password) {
      return request('POST', '/recovery/ipfs/recover', { cid, password });
    },
  };
}
