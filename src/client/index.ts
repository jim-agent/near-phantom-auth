/**
 * Client SDK Entry Point
 * 
 * @example
 * ```tsx
 * import { AnonAuthProvider, useAnonAuth, OAuthProvider, useOAuth } from '@vitalpoint/near-phantom-auth/client';
 * 
 * function App() {
 *   return (
 *     <OAuthProvider apiUrl="/auth">
 *       <AnonAuthProvider apiUrl="/auth">
 *         <MyComponent />
 *       </AnonAuthProvider>
 *     </OAuthProvider>
 *   );
 * }
 * 
 * function MyComponent() {
 *   const { isAuthenticated, codename, register, login, logout } = useAnonAuth();
 *   const { loginWithGoogle, loginWithGithub, loginWithTwitter } = useOAuth();
 *   
 *   if (!isAuthenticated) {
 *     return (
 *       <div>
 *         <h3>Anonymous (HUMINT)</h3>
 *         <button onClick={register}>Register as Source</button>
 *         <button onClick={() => login()}>Sign In with Passkey</button>
 *         
 *         <h3>Standard User</h3>
 *         <button onClick={loginWithGoogle}>Sign in with Google</button>
 *         <button onClick={loginWithGithub}>Sign in with GitHub</button>
 *         <button onClick={loginWithTwitter}>Sign in with X</button>
 *       </div>
 *     );
 *   }
 *   
 *   return (
 *     <div>
 *       <p>Welcome, {codename}</p>
 *       <button onClick={logout}>Sign Out</button>
 *     </div>
 *   );
 * }
 * ```
 */

// React hooks - Anonymous (passkey) auth
export {
  AnonAuthProvider,
  useAnonAuth,
  type AnonAuthProviderProps,
  type AnonAuthState,
  type AnonAuthActions,
  type AnonAuthContextValue,
  type RecoveryActions,
} from './hooks/useAnonAuth.js';

// React hooks - OAuth auth
export {
  OAuthProvider,
  useOAuth,
  useOAuthCallback,
  type OAuthProviderProps,
  type OAuthState,
  type OAuthActions,
  type OAuthContextValue,
  type OAuthProviders,
  type OAuthUser,
} from './hooks/useOAuth.js';

// API client (for non-React usage)
export {
  createApiClient,
  type ApiClient,
  type ApiClientConfig,
  type SessionInfo,
} from './api.js';

// Passkey utilities
export {
  isWebAuthnSupported,
  isPlatformAuthenticatorAvailable,
  createPasskey,
  authenticateWithPasskey,
} from './passkey.js';
