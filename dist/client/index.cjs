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

exports.AnonAuthProvider = AnonAuthProvider;
exports.authenticateWithPasskey = authenticateWithPasskey;
exports.createApiClient = createApiClient;
exports.createPasskey = createPasskey;
exports.isPlatformAuthenticatorAvailable = isPlatformAuthenticatorAvailable;
exports.isWebAuthnSupported = isWebAuthnSupported;
exports.useAnonAuth = useAnonAuth;
//# sourceMappingURL=index.cjs.map
//# sourceMappingURL=index.cjs.map