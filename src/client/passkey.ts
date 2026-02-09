/**
 * Client-side Passkey (WebAuthn) operations
 */

import type {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
} from '../types/index.js';

/**
 * Check if WebAuthn is supported
 */
export function isWebAuthnSupported(): boolean {
  return (
    typeof window !== 'undefined' &&
    typeof window.PublicKeyCredential !== 'undefined' &&
    typeof window.navigator.credentials !== 'undefined'
  );
}

/**
 * Check if platform authenticator is available
 */
export async function isPlatformAuthenticatorAvailable(): Promise<boolean> {
  if (!isWebAuthnSupported()) return false;
  
  try {
    return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch {
    return false;
  }
}

/**
 * Decode base64url string to ArrayBuffer
 */
function base64urlToBuffer(base64url: string): ArrayBuffer {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  const padLen = (4 - (base64.length % 4)) % 4;
  const padded = base64 + '='.repeat(padLen);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * Encode ArrayBuffer to base64url string
 */
function bufferToBase64url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  const base64 = btoa(binary);
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Create a new passkey (registration)
 */
export async function createPasskey(
  options: PublicKeyCredentialCreationOptionsJSON
): Promise<RegistrationResponseJSON> {
  if (!isWebAuthnSupported()) {
    throw new Error('WebAuthn is not supported in this browser');
  }

  // Convert JSON options to WebAuthn format
  const publicKeyOptions: PublicKeyCredentialCreationOptions = {
    challenge: base64urlToBuffer(options.challenge),
    rp: options.rp,
    user: {
      id: base64urlToBuffer(options.user.id),
      name: options.user.name,
      displayName: options.user.displayName,
    },
    pubKeyCredParams: options.pubKeyCredParams,
    timeout: options.timeout,
    authenticatorSelection: options.authenticatorSelection,
    attestation: options.attestation || 'none',
    excludeCredentials: options.excludeCredentials?.map((cred) => ({
      id: base64urlToBuffer(cred.id),
      type: cred.type,
      transports: cred.transports,
    })),
  };

  // Create credential
  const credential = await navigator.credentials.create({
    publicKey: publicKeyOptions,
  }) as PublicKeyCredential;

  if (!credential) {
    throw new Error('Credential creation failed');
  }

  const response = credential.response as AuthenticatorAttestationResponse;

  // Convert response to JSON format
  return {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: 'public-key',
    response: {
      clientDataJSON: bufferToBase64url(response.clientDataJSON),
      attestationObject: bufferToBase64url(response.attestationObject),
      transports: response.getTransports?.() as AuthenticationResponseJSON['response']['transports'],
    },
    clientExtensionResults: credential.getClientExtensionResults(),
  };
}

/**
 * Authenticate with existing passkey
 */
export async function authenticateWithPasskey(
  options: PublicKeyCredentialRequestOptionsJSON
): Promise<AuthenticationResponseJSON> {
  if (!isWebAuthnSupported()) {
    throw new Error('WebAuthn is not supported in this browser');
  }

  // Convert JSON options to WebAuthn format
  const publicKeyOptions: PublicKeyCredentialRequestOptions = {
    challenge: base64urlToBuffer(options.challenge),
    timeout: options.timeout,
    rpId: options.rpId,
    userVerification: options.userVerification,
    allowCredentials: options.allowCredentials?.map((cred) => ({
      id: base64urlToBuffer(cred.id),
      type: cred.type,
      transports: cred.transports,
    })),
  };

  // Get credential
  const credential = await navigator.credentials.get({
    publicKey: publicKeyOptions,
  }) as PublicKeyCredential;

  if (!credential) {
    throw new Error('Authentication failed');
  }

  const response = credential.response as AuthenticatorAssertionResponse;

  // Convert response to JSON format
  return {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: 'public-key',
    response: {
      clientDataJSON: bufferToBase64url(response.clientDataJSON),
      authenticatorData: bufferToBase64url(response.authenticatorData),
      signature: bufferToBase64url(response.signature),
      userHandle: response.userHandle ? bufferToBase64url(response.userHandle) : undefined,
    },
    clientExtensionResults: credential.getClientExtensionResults(),
  };
}
