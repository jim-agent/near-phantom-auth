/**
 * Client SDK Entry Point
 * 
 * @example
 * ```tsx
 * import { AnonAuthProvider, useAnonAuth } from '@vitalpoint/near-anon-auth/client';
 * 
 * function App() {
 *   return (
 *     <AnonAuthProvider apiUrl="/auth">
 *       <MyComponent />
 *     </AnonAuthProvider>
 *   );
 * }
 * 
 * function MyComponent() {
 *   const { isAuthenticated, codename, register, login, logout } = useAnonAuth();
 *   
 *   if (!isAuthenticated) {
 *     return (
 *       <div>
 *         <button onClick={register}>Register</button>
 *         <button onClick={() => login()}>Sign In</button>
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

// React hooks
export {
  AnonAuthProvider,
  useAnonAuth,
  type AnonAuthProviderProps,
  type AnonAuthState,
  type AnonAuthActions,
  type AnonAuthContextValue,
  type RecoveryActions,
} from './hooks/useAnonAuth.js';

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
