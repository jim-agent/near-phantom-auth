'use strict';

var react = require('react');
var jsxRuntime = require('react/jsx-runtime');

// src/client/hooks/useAnonAuth.tsx

// src/client/api.ts
function createApiClient(config) {
  const fetchFn = config.fetch || fetch;
  const baseUrl = config.baseUrl.replace(/\/$/, "");
  async function request(method, path, body) {
    const response = await fetchFn(`${baseUrl}${path}`, {
      method,
      headers: {
        "Content-Type": "application/json"
      },
      credentials: "include",
      // Include cookies
      body: body ? JSON.stringify(body) : void 0
    });
    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: "Request failed" }));
      throw new Error(error.error || `Request failed: ${response.status}`);
    }
    return response.json();
  }
  return {
    // Registration
    async startRegistration() {
      return request("POST", "/register/start");
    },
    async finishRegistration(challengeId, response, tempUserId, codename) {
      return request("POST", "/register/finish", {
        challengeId,
        response,
        tempUserId,
        codename
      });
    },
    // Authentication
    async startAuthentication(codename) {
      return request("POST", "/login/start", { codename });
    },
    async finishAuthentication(challengeId, response) {
      return request("POST", "/login/finish", {
        challengeId,
        response
      });
    },
    // Session
    async getSession() {
      try {
        return await request("GET", "/session");
      } catch {
        return { authenticated: false };
      }
    },
    async logout() {
      await request("POST", "/logout");
    },
    // Wallet Recovery
    async startWalletLink() {
      return request("POST", "/recovery/wallet/link");
    },
    async finishWalletLink(signature, challenge, walletAccountId) {
      return request("POST", "/recovery/wallet/verify", {
        signature,
        challenge,
        walletAccountId
      });
    },
    async startWalletRecovery() {
      return request("POST", "/recovery/wallet/start");
    },
    async finishWalletRecovery(signature, challenge, nearAccountId) {
      return request("POST", "/recovery/wallet/finish", {
        signature,
        challenge,
        nearAccountId
      });
    },
    // IPFS Recovery
    async setupIPFSRecovery(password) {
      return request("POST", "/recovery/ipfs/setup", { password });
    },
    async recoverFromIPFS(cid, password) {
      return request("POST", "/recovery/ipfs/recover", { cid, password });
    }
  };
}

// src/client/passkey.ts
function isWebAuthnSupported() {
  return typeof window !== "undefined" && typeof window.PublicKeyCredential !== "undefined" && typeof window.navigator.credentials !== "undefined";
}
async function isPlatformAuthenticatorAvailable() {
  if (!isWebAuthnSupported()) return false;
  try {
    return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch {
    return false;
  }
}
function base64urlToBuffer(base64url) {
  const base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
  const padLen = (4 - base64.length % 4) % 4;
  const padded = base64 + "=".repeat(padLen);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}
function bufferToBase64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  const base64 = btoa(binary);
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}
async function createPasskey(options) {
  if (!isWebAuthnSupported()) {
    throw new Error("WebAuthn is not supported in this browser");
  }
  const publicKeyOptions = {
    challenge: base64urlToBuffer(options.challenge),
    rp: options.rp,
    user: {
      id: base64urlToBuffer(options.user.id),
      name: options.user.name,
      displayName: options.user.displayName
    },
    pubKeyCredParams: options.pubKeyCredParams,
    timeout: options.timeout,
    authenticatorSelection: options.authenticatorSelection,
    attestation: options.attestation || "none",
    excludeCredentials: options.excludeCredentials?.map((cred) => ({
      id: base64urlToBuffer(cred.id),
      type: cred.type,
      transports: cred.transports
    }))
  };
  const credential = await navigator.credentials.create({
    publicKey: publicKeyOptions
  });
  if (!credential) {
    throw new Error("Credential creation failed");
  }
  const response = credential.response;
  return {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: "public-key",
    response: {
      clientDataJSON: bufferToBase64url(response.clientDataJSON),
      attestationObject: bufferToBase64url(response.attestationObject),
      transports: response.getTransports?.()
    },
    clientExtensionResults: credential.getClientExtensionResults()
  };
}
async function authenticateWithPasskey(options) {
  if (!isWebAuthnSupported()) {
    throw new Error("WebAuthn is not supported in this browser");
  }
  const publicKeyOptions = {
    challenge: base64urlToBuffer(options.challenge),
    timeout: options.timeout,
    rpId: options.rpId,
    userVerification: options.userVerification,
    allowCredentials: options.allowCredentials?.map((cred) => ({
      id: base64urlToBuffer(cred.id),
      type: cred.type,
      transports: cred.transports
    }))
  };
  const credential = await navigator.credentials.get({
    publicKey: publicKeyOptions
  });
  if (!credential) {
    throw new Error("Authentication failed");
  }
  const response = credential.response;
  return {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: "public-key",
    response: {
      clientDataJSON: bufferToBase64url(response.clientDataJSON),
      authenticatorData: bufferToBase64url(response.authenticatorData),
      signature: bufferToBase64url(response.signature),
      userHandle: response.userHandle ? bufferToBase64url(response.userHandle) : void 0
    },
    clientExtensionResults: credential.getClientExtensionResults()
  };
}
var AnonAuthContext = react.createContext(null);
function AnonAuthProvider({ apiUrl, children }) {
  const [api] = react.useState(() => createApiClient({ baseUrl: apiUrl }));
  const [state, setState] = react.useState({
    isLoading: true,
    isAuthenticated: false,
    codename: null,
    nearAccountId: null,
    expiresAt: null,
    webAuthnSupported: false,
    platformAuthAvailable: false,
    error: null
  });
  react.useEffect(() => {
    const checkSupport = async () => {
      const webAuthnSupported = isWebAuthnSupported();
      const platformAuthAvailable = await isPlatformAuthenticatorAvailable();
      setState((prev) => ({
        ...prev,
        webAuthnSupported,
        platformAuthAvailable
      }));
    };
    checkSupport();
  }, []);
  react.useEffect(() => {
    const checkSession = async () => {
      try {
        const session = await api.getSession();
        setState((prev) => ({
          ...prev,
          isLoading: false,
          isAuthenticated: session.authenticated,
          codename: session.codename || null,
          nearAccountId: session.nearAccountId || null,
          expiresAt: session.expiresAt ? new Date(session.expiresAt) : null
        }));
      } catch (error) {
        setState((prev) => ({
          ...prev,
          isLoading: false,
          error: error instanceof Error ? error.message : "Session check failed"
        }));
      }
    };
    checkSession();
  }, [api]);
  const register = react.useCallback(async () => {
    try {
      setState((prev) => ({ ...prev, isLoading: true, error: null }));
      const { challengeId, options, tempUserId, codename } = await api.startRegistration();
      const credential = await createPasskey(options);
      const result = await api.finishRegistration(
        challengeId,
        credential,
        tempUserId,
        codename
      );
      if (result.success) {
        setState((prev) => ({
          ...prev,
          isLoading: false,
          isAuthenticated: true,
          codename: result.codename,
          nearAccountId: result.nearAccountId
        }));
      } else {
        throw new Error("Registration failed");
      }
    } catch (error) {
      setState((prev) => ({
        ...prev,
        isLoading: false,
        error: error instanceof Error ? error.message : "Registration failed"
      }));
    }
  }, [api]);
  const login = react.useCallback(async (codename) => {
    try {
      setState((prev) => ({ ...prev, isLoading: true, error: null }));
      const { challengeId, options } = await api.startAuthentication(codename);
      const credential = await authenticateWithPasskey(options);
      const result = await api.finishAuthentication(challengeId, credential);
      if (result.success) {
        const session = await api.getSession();
        setState((prev) => ({
          ...prev,
          isLoading: false,
          isAuthenticated: true,
          codename: session.codename || result.codename,
          nearAccountId: session.nearAccountId || null,
          expiresAt: session.expiresAt ? new Date(session.expiresAt) : null
        }));
      } else {
        throw new Error("Authentication failed");
      }
    } catch (error) {
      setState((prev) => ({
        ...prev,
        isLoading: false,
        error: error instanceof Error ? error.message : "Login failed"
      }));
    }
  }, [api]);
  const logout = react.useCallback(async () => {
    try {
      await api.logout();
      setState((prev) => ({
        ...prev,
        isAuthenticated: false,
        codename: null,
        nearAccountId: null,
        expiresAt: null
      }));
    } catch (error) {
      setState((prev) => ({
        ...prev,
        error: error instanceof Error ? error.message : "Logout failed"
      }));
    }
  }, [api]);
  const refreshSession = react.useCallback(async () => {
    try {
      const session = await api.getSession();
      setState((prev) => ({
        ...prev,
        isAuthenticated: session.authenticated,
        codename: session.codename || null,
        nearAccountId: session.nearAccountId || null,
        expiresAt: session.expiresAt ? new Date(session.expiresAt) : null
      }));
    } catch (error) {
      console.error("Session refresh failed:", error);
    }
  }, [api]);
  const clearError = react.useCallback(() => {
    setState((prev) => ({ ...prev, error: null }));
  }, []);
  const recovery = {
    async linkWallet(signMessage, walletAccountId) {
      const { challenge } = await api.startWalletLink();
      const signature = await signMessage(challenge);
      await api.finishWalletLink(signature, challenge, walletAccountId);
    },
    async recoverWithWallet(signMessage, nearAccountId) {
      const { challenge } = await api.startWalletRecovery();
      const signature = await signMessage(challenge);
      const result = await api.finishWalletRecovery(signature, challenge, nearAccountId);
      if (result.success) {
        setState((prev) => ({
          ...prev,
          isAuthenticated: true,
          codename: result.codename
        }));
      }
    },
    async setupPasswordRecovery(password) {
      const result = await api.setupIPFSRecovery(password);
      return { cid: result.cid };
    },
    async recoverWithPassword(cid, password) {
      const result = await api.recoverFromIPFS(cid, password);
      if (result.success) {
        setState((prev) => ({
          ...prev,
          isAuthenticated: true,
          codename: result.codename
        }));
      }
    }
  };
  const value = {
    ...state,
    register,
    login,
    logout,
    refreshSession,
    clearError,
    recovery
  };
  return /* @__PURE__ */ jsxRuntime.jsx(AnonAuthContext.Provider, { value, children });
}
function useAnonAuth() {
  const context = react.useContext(AnonAuthContext);
  if (!context) {
    throw new Error("useAnonAuth must be used within AnonAuthProvider");
  }
  return context;
}
var OAuthContext = react.createContext(null);
function OAuthProvider({
  children,
  apiUrl,
  onLoginSuccess,
  onLoginError
}) {
  const [state, setState] = react.useState({
    isLoading: true,
    error: null,
    providers: { google: false, github: false, twitter: false },
    user: null,
    isAuthenticated: false
  });
  react.useEffect(() => {
    async function fetchProviders() {
      try {
        const response = await fetch(`${apiUrl}/oauth/providers`);
        if (response.ok) {
          const data = await response.json();
          setState((prev) => ({
            ...prev,
            providers: data.providers,
            isLoading: false
          }));
        }
      } catch {
        setState((prev) => ({ ...prev, isLoading: false }));
      }
    }
    async function checkSession() {
      try {
        const response = await fetch(`${apiUrl}/session`, {
          credentials: "include"
        });
        if (response.ok) {
          const data = await response.json();
          if (data.authenticated && data.type === "standard") {
            setState((prev) => ({
              ...prev,
              user: {
                id: data.id,
                email: data.email,
                name: data.name,
                avatarUrl: data.avatarUrl,
                nearAccountId: data.nearAccountId,
                type: "standard"
              },
              isAuthenticated: true
            }));
          }
        }
      } catch {
      }
    }
    fetchProviders();
    checkSession();
  }, [apiUrl]);
  const initiateOAuth = react.useCallback(async (provider) => {
    setState((prev) => ({ ...prev, isLoading: true, error: null }));
    try {
      const response = await fetch(`${apiUrl}/oauth/${provider}/start`, {
        credentials: "include"
      });
      if (!response.ok) {
        throw new Error(`Failed to start ${provider} OAuth`);
      }
      const data = await response.json();
      sessionStorage.setItem("oauth_state", data.state);
      sessionStorage.setItem("oauth_provider", provider);
      window.location.href = data.url;
    } catch (error) {
      const err = error instanceof Error ? error : new Error("OAuth failed");
      setState((prev) => ({ ...prev, isLoading: false, error: err.message }));
      onLoginError?.(err);
      throw err;
    }
  }, [apiUrl, onLoginError]);
  const handleCallback = react.useCallback(async (provider, code, state2) => {
    setState((prev) => ({ ...prev, isLoading: true, error: null }));
    try {
      const response = await fetch(`${apiUrl}/oauth/${provider}/callback`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ code, state: state2 })
      });
      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || "OAuth callback failed");
      }
      const data = await response.json();
      const user = data.user;
      setState((prev) => ({
        ...prev,
        isLoading: false,
        user,
        isAuthenticated: true
      }));
      onLoginSuccess?.(user, data.isNewUser);
      sessionStorage.removeItem("oauth_state");
      sessionStorage.removeItem("oauth_provider");
      return user;
    } catch (error) {
      const err = error instanceof Error ? error : new Error("OAuth callback failed");
      setState((prev) => ({ ...prev, isLoading: false, error: err.message }));
      onLoginError?.(err);
      throw err;
    }
  }, [apiUrl, onLoginSuccess, onLoginError]);
  const linkProvider = react.useCallback(async (provider) => {
    if (!state.isAuthenticated) {
      throw new Error("Must be authenticated to link providers");
    }
    setState((prev) => ({ ...prev, isLoading: true }));
    try {
      const response = await fetch(`${apiUrl}/oauth/${provider}/start`, {
        credentials: "include"
      });
      if (!response.ok) {
        throw new Error(`Failed to start ${provider} OAuth`);
      }
      const data = await response.json();
      sessionStorage.setItem("oauth_state", data.state);
      sessionStorage.setItem("oauth_provider", provider);
      sessionStorage.setItem("oauth_action", "link");
      window.location.href = data.url;
    } catch (error) {
      const err = error instanceof Error ? error : new Error("Link failed");
      setState((prev) => ({ ...prev, isLoading: false, error: err.message }));
      throw err;
    }
  }, [apiUrl, state.isAuthenticated]);
  const refreshSession = react.useCallback(async () => {
    try {
      const response = await fetch(`${apiUrl}/session`, {
        credentials: "include"
      });
      if (response.ok) {
        const data = await response.json();
        if (data.authenticated && data.type === "standard") {
          setState((prev) => ({
            ...prev,
            user: {
              id: data.id,
              email: data.email,
              name: data.name,
              avatarUrl: data.avatarUrl,
              nearAccountId: data.nearAccountId,
              type: "standard"
            },
            isAuthenticated: true
          }));
        } else {
          setState((prev) => ({
            ...prev,
            user: null,
            isAuthenticated: false
          }));
        }
      }
    } catch {
      setState((prev) => ({
        ...prev,
        user: null,
        isAuthenticated: false
      }));
    }
  }, [apiUrl]);
  const logout = react.useCallback(async () => {
    try {
      await fetch(`${apiUrl}/logout`, {
        method: "POST",
        credentials: "include"
      });
    } finally {
      setState((prev) => ({
        ...prev,
        user: null,
        isAuthenticated: false
      }));
    }
  }, [apiUrl]);
  const clearError = react.useCallback(() => {
    setState((prev) => ({ ...prev, error: null }));
  }, []);
  const value = {
    ...state,
    loginWithGoogle: () => initiateOAuth("google"),
    loginWithGithub: () => initiateOAuth("github"),
    loginWithTwitter: () => initiateOAuth("twitter"),
    handleCallback,
    linkProvider,
    clearError,
    refreshSession,
    logout
  };
  return /* @__PURE__ */ jsxRuntime.jsx(OAuthContext.Provider, { value, children });
}
function useOAuth() {
  const context = react.useContext(OAuthContext);
  if (!context) {
    throw new Error("useOAuth must be used within an OAuthProvider");
  }
  return context;
}
function useOAuthCallback() {
  const oauth = useOAuth();
  const [isProcessing, setIsProcessing] = react.useState(false);
  const [result, setResult] = react.useState(null);
  const processCallback = react.useCallback(async () => {
    const params = new URLSearchParams(window.location.search);
    const code = params.get("code");
    const state = params.get("state");
    const error = params.get("error");
    if (error) {
      setResult({ error: params.get("error_description") || error });
      return;
    }
    if (!code || !state) {
      return;
    }
    const storedState = sessionStorage.getItem("oauth_state");
    const storedProvider = sessionStorage.getItem("oauth_provider");
    if (state !== storedState || !storedProvider) {
      setResult({ error: "Invalid OAuth state" });
      return;
    }
    setIsProcessing(true);
    try {
      const user = await oauth.handleCallback(storedProvider, code, state);
      setResult({ user });
      const url = new URL(window.location.href);
      url.searchParams.delete("code");
      url.searchParams.delete("state");
      window.history.replaceState({}, "", url.toString());
    } catch (err) {
      setResult({ error: err instanceof Error ? err.message : "OAuth failed" });
    } finally {
      setIsProcessing(false);
    }
  }, [oauth]);
  return {
    processCallback,
    isProcessing,
    result
  };
}

exports.AnonAuthProvider = AnonAuthProvider;
exports.OAuthProvider = OAuthProvider;
exports.authenticateWithPasskey = authenticateWithPasskey;
exports.createApiClient = createApiClient;
exports.createPasskey = createPasskey;
exports.isPlatformAuthenticatorAvailable = isPlatformAuthenticatorAvailable;
exports.isWebAuthnSupported = isWebAuthnSupported;
exports.useAnonAuth = useAnonAuth;
exports.useOAuth = useOAuth;
exports.useOAuthCallback = useOAuthCallback;
//# sourceMappingURL=index.cjs.map
//# sourceMappingURL=index.cjs.map