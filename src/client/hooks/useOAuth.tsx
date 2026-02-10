'use client';

import { createContext, useContext, useCallback, useState, useEffect, type ReactNode } from 'react';

export interface OAuthProviders {
  google: boolean;
  github: boolean;
  twitter: boolean;
}

export interface OAuthUser {
  id: string;
  email: string;
  name?: string;
  avatarUrl?: string;
  nearAccountId: string;
  type: 'standard';
}

export interface OAuthState {
  isLoading: boolean;
  error: string | null;
  providers: OAuthProviders;
  user: OAuthUser | null;
  isAuthenticated: boolean;
}

export interface OAuthActions {
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

export interface OAuthContextValue extends OAuthState, OAuthActions {}

export interface OAuthProviderProps {
  children: ReactNode;
  apiUrl: string;
  onLoginSuccess?: (user: OAuthUser, isNewUser: boolean) => void;
  onLoginError?: (error: Error) => void;
}

const OAuthContext = createContext<OAuthContextValue | null>(null);

export function OAuthProvider({
  children,
  apiUrl,
  onLoginSuccess,
  onLoginError,
}: OAuthProviderProps) {
  const [state, setState] = useState<OAuthState>({
    isLoading: true,
    error: null,
    providers: { google: false, github: false, twitter: false },
    user: null,
    isAuthenticated: false,
  });

  // Fetch available providers on mount
  useEffect(() => {
    async function fetchProviders() {
      try {
        const response = await fetch(`${apiUrl}/oauth/providers`);
        if (response.ok) {
          const data = await response.json();
          setState(prev => ({
            ...prev,
            providers: data.providers,
            isLoading: false,
          }));
        }
      } catch {
        setState(prev => ({ ...prev, isLoading: false }));
      }
    }

    async function checkSession() {
      try {
        const response = await fetch(`${apiUrl}/session`, {
          credentials: 'include',
        });
        if (response.ok) {
          const data = await response.json();
          if (data.authenticated && data.type === 'standard') {
            setState(prev => ({
              ...prev,
              user: {
                id: data.id,
                email: data.email,
                name: data.name,
                avatarUrl: data.avatarUrl,
                nearAccountId: data.nearAccountId,
                type: 'standard',
              },
              isAuthenticated: true,
            }));
          }
        }
      } catch {
        // Session check failed, user not authenticated
      }
    }

    fetchProviders();
    checkSession();
  }, [apiUrl]);

  const initiateOAuth = useCallback(async (provider: 'google' | 'github' | 'twitter') => {
    setState(prev => ({ ...prev, isLoading: true, error: null }));

    try {
      const response = await fetch(`${apiUrl}/oauth/${provider}/start`, {
        credentials: 'include',
      });

      if (!response.ok) {
        throw new Error(`Failed to start ${provider} OAuth`);
      }

      const data = await response.json();
      
      // Store state for verification after redirect
      sessionStorage.setItem('oauth_state', data.state);
      sessionStorage.setItem('oauth_provider', provider);
      
      // Redirect to provider
      window.location.href = data.url;
    } catch (error) {
      const err = error instanceof Error ? error : new Error('OAuth failed');
      setState(prev => ({ ...prev, isLoading: false, error: err.message }));
      onLoginError?.(err);
      throw err;
    }
  }, [apiUrl, onLoginError]);

  const handleCallback = useCallback(async (
    provider: string,
    code: string,
    state: string
  ): Promise<OAuthUser> => {
    setState(prev => ({ ...prev, isLoading: true, error: null }));

    try {
      const response = await fetch(`${apiUrl}/oauth/${provider}/callback`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ code, state }),
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'OAuth callback failed');
      }

      const data = await response.json();
      const user = data.user as OAuthUser;

      setState(prev => ({
        ...prev,
        isLoading: false,
        user,
        isAuthenticated: true,
      }));

      onLoginSuccess?.(user, data.isNewUser);
      
      // Clean up stored state
      sessionStorage.removeItem('oauth_state');
      sessionStorage.removeItem('oauth_provider');

      return user;
    } catch (error) {
      const err = error instanceof Error ? error : new Error('OAuth callback failed');
      setState(prev => ({ ...prev, isLoading: false, error: err.message }));
      onLoginError?.(err);
      throw err;
    }
  }, [apiUrl, onLoginSuccess, onLoginError]);

  const linkProvider = useCallback(async (provider: 'google' | 'github' | 'twitter') => {
    if (!state.isAuthenticated) {
      throw new Error('Must be authenticated to link providers');
    }

    // Start OAuth flow for linking
    setState(prev => ({ ...prev, isLoading: true }));

    try {
      const response = await fetch(`${apiUrl}/oauth/${provider}/start`, {
        credentials: 'include',
      });

      if (!response.ok) {
        throw new Error(`Failed to start ${provider} OAuth`);
      }

      const data = await response.json();
      
      // Store state for verification after redirect
      sessionStorage.setItem('oauth_state', data.state);
      sessionStorage.setItem('oauth_provider', provider);
      sessionStorage.setItem('oauth_action', 'link');
      
      // Redirect to provider
      window.location.href = data.url;
    } catch (error) {
      const err = error instanceof Error ? error : new Error('Link failed');
      setState(prev => ({ ...prev, isLoading: false, error: err.message }));
      throw err;
    }
  }, [apiUrl, state.isAuthenticated]);

  const refreshSession = useCallback(async () => {
    try {
      const response = await fetch(`${apiUrl}/session`, {
        credentials: 'include',
      });

      if (response.ok) {
        const data = await response.json();
        if (data.authenticated && data.type === 'standard') {
          setState(prev => ({
            ...prev,
            user: {
              id: data.id,
              email: data.email,
              name: data.name,
              avatarUrl: data.avatarUrl,
              nearAccountId: data.nearAccountId,
              type: 'standard',
            },
            isAuthenticated: true,
          }));
        } else {
          setState(prev => ({
            ...prev,
            user: null,
            isAuthenticated: false,
          }));
        }
      }
    } catch {
      setState(prev => ({
        ...prev,
        user: null,
        isAuthenticated: false,
      }));
    }
  }, [apiUrl]);

  const logout = useCallback(async () => {
    try {
      await fetch(`${apiUrl}/logout`, {
        method: 'POST',
        credentials: 'include',
      });
    } finally {
      setState(prev => ({
        ...prev,
        user: null,
        isAuthenticated: false,
      }));
    }
  }, [apiUrl]);

  const clearError = useCallback(() => {
    setState(prev => ({ ...prev, error: null }));
  }, []);

  const value: OAuthContextValue = {
    ...state,
    loginWithGoogle: () => initiateOAuth('google'),
    loginWithGithub: () => initiateOAuth('github'),
    loginWithTwitter: () => initiateOAuth('twitter'),
    handleCallback,
    linkProvider,
    clearError,
    refreshSession,
    logout,
  };

  return (
    <OAuthContext.Provider value={value}>
      {children}
    </OAuthContext.Provider>
  );
}

export function useOAuth(): OAuthContextValue {
  const context = useContext(OAuthContext);
  if (!context) {
    throw new Error('useOAuth must be used within an OAuthProvider');
  }
  return context;
}

/**
 * Hook to handle OAuth callback from URL parameters
 */
export function useOAuthCallback() {
  const oauth = useOAuth();
  const [isProcessing, setIsProcessing] = useState(false);
  const [result, setResult] = useState<{ user?: OAuthUser; error?: string } | null>(null);

  const processCallback = useCallback(async () => {
    // Check if we have OAuth params in URL
    const params = new URLSearchParams(window.location.search);
    const code = params.get('code');
    const state = params.get('state');
    const error = params.get('error');

    if (error) {
      setResult({ error: params.get('error_description') || error });
      return;
    }

    if (!code || !state) {
      return;
    }

    // Verify state matches
    const storedState = sessionStorage.getItem('oauth_state');
    const storedProvider = sessionStorage.getItem('oauth_provider');

    if (state !== storedState || !storedProvider) {
      setResult({ error: 'Invalid OAuth state' });
      return;
    }

    setIsProcessing(true);

    try {
      const user = await oauth.handleCallback(storedProvider, code, state);
      setResult({ user });
      
      // Clean up URL
      const url = new URL(window.location.href);
      url.searchParams.delete('code');
      url.searchParams.delete('state');
      window.history.replaceState({}, '', url.toString());
    } catch (err) {
      setResult({ error: err instanceof Error ? err.message : 'OAuth failed' });
    } finally {
      setIsProcessing(false);
    }
  }, [oauth]);

  return {
    processCallback,
    isProcessing,
    result,
  };
}
