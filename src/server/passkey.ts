/**
 * Passkey (WebAuthn) Authentication
 * 
 * Handles passkey registration and authentication using @simplewebauthn/server
 */

import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import type {
  GenerateRegistrationOptionsOpts,
  GenerateAuthenticationOptionsOpts,
  VerifyRegistrationResponseOpts,
  VerifyAuthenticationResponseOpts,
  VerifiedRegistrationResponse,
  VerifiedAuthenticationResponse,
} from '@simplewebauthn/server';
import { randomUUID } from 'crypto';
import type {
  DatabaseAdapter,
  Challenge,
  Passkey,
  CreatePasskeyInput,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
  AuthenticatorTransport,
} from '../types/index.js';

export interface PasskeyConfig {
  /** Relying Party name (shown to users) */
  rpName: string;
  /** Relying Party ID (your domain, e.g., 'example.com') */
  rpId: string;
  /** Origin for WebAuthn (e.g., 'https://example.com') */
  origin: string;
  /** Challenge timeout in ms (default: 60000) */
  challengeTimeoutMs?: number;
}

export interface PasskeyManager {
  startRegistration(
    userId: string,
    userDisplayName: string
  ): Promise<{
    challengeId: string;
    options: PublicKeyCredentialCreationOptionsJSON;
  }>;
  
  finishRegistration(
    challengeId: string,
    response: RegistrationResponseJSON
  ): Promise<{
    verified: boolean;
    passkey?: Passkey;
  }>;
  
  startAuthentication(
    userId?: string
  ): Promise<{
    challengeId: string;
    options: PublicKeyCredentialRequestOptionsJSON;
  }>;
  
  finishAuthentication(
    challengeId: string,
    response: AuthenticationResponseJSON
  ): Promise<{
    verified: boolean;
    userId?: string;
    passkey?: Passkey;
  }>;
}

/**
 * Create passkey manager
 */
export function createPasskeyManager(
  db: DatabaseAdapter,
  config: PasskeyConfig
): PasskeyManager {
  const challengeTimeoutMs = config.challengeTimeoutMs || 60000;

  return {
    async startRegistration(userId, userDisplayName) {
      // Get existing passkeys for this user
      const existingPasskeys = await db.getPasskeysByUserId(userId);
      
      const excludeCredentials = existingPasskeys.map((pk) => ({
        id: pk.credentialId,
        type: 'public-key' as const,
        transports: pk.transports,
      }));
      
      const options = await generateRegistrationOptions({
        rpName: config.rpName,
        rpID: config.rpId,
        userName: userDisplayName,
        userDisplayName: userDisplayName,
        userID: new TextEncoder().encode(userId),
        attestationType: 'none',
        excludeCredentials,
        authenticatorSelection: {
          residentKey: 'preferred',
          userVerification: 'preferred',
          authenticatorAttachment: 'platform',
        },
      } as GenerateRegistrationOptionsOpts);
      
      // Store challenge
      const challengeId = randomUUID();
      const challenge: Challenge = {
        id: challengeId,
        challenge: options.challenge,
        type: 'registration',
        userId,
        expiresAt: new Date(Date.now() + challengeTimeoutMs),
      };
      
      await db.storeChallenge(challenge);
      
      return {
        challengeId,
        options: options as unknown as PublicKeyCredentialCreationOptionsJSON,
      };
    },
    
    async finishRegistration(challengeId, response) {
      // Get and validate challenge
      const challenge = await db.getChallenge(challengeId);
      
      if (!challenge) {
        throw new Error('Challenge not found or expired');
      }
      
      if (challenge.type !== 'registration') {
        throw new Error('Invalid challenge type');
      }
      
      if (challenge.expiresAt < new Date()) {
        await db.deleteChallenge(challengeId);
        throw new Error('Challenge expired');
      }
      
      if (!challenge.userId) {
        throw new Error('Challenge missing user ID');
      }
      
      // Verify registration
      let verification: VerifiedRegistrationResponse;
      try {
        verification = await verifyRegistrationResponse({
          response: response as unknown as Parameters<typeof verifyRegistrationResponse>[0]['response'],
          expectedChallenge: challenge.challenge,
          expectedOrigin: config.origin,
          expectedRPID: config.rpId,
        } as VerifyRegistrationResponseOpts);
      } catch (error) {
        console.error('[Passkey] Registration verification failed:', error);
        await db.deleteChallenge(challengeId);
        return { verified: false };
      }
      
      if (!verification.verified || !verification.registrationInfo) {
        await db.deleteChallenge(challengeId);
        return { verified: false };
      }
      
      const { registrationInfo } = verification;
      
      // Create passkey record
      const passkeyInput: CreatePasskeyInput = {
        credentialId: registrationInfo.credential.id,
        userId: challenge.userId,
        publicKey: registrationInfo.credential.publicKey,
        counter: registrationInfo.credential.counter,
        deviceType: registrationInfo.credentialDeviceType,
        backedUp: registrationInfo.credentialBackedUp,
        transports: response.response.transports,
      };
      
      const passkey = await db.createPasskey(passkeyInput);
      
      // Clean up challenge
      await db.deleteChallenge(challengeId);
      
      return {
        verified: true,
        passkey,
      };
    },
    
    async startAuthentication(userId) {
      // Get user's passkeys if userId provided
      let allowCredentials: Array<{
        id: string;
        type: 'public-key';
        transports?: AuthenticatorTransport[];
      }> | undefined;
      
      if (userId) {
        const passkeys = await db.getPasskeysByUserId(userId);
        allowCredentials = passkeys.map((pk) => ({
          id: pk.credentialId,
          type: 'public-key' as const,
          transports: pk.transports,
        }));
      }
      
      const options = await generateAuthenticationOptions({
        rpID: config.rpId,
        userVerification: 'preferred',
        allowCredentials,
      } as GenerateAuthenticationOptionsOpts);
      
      // Store challenge
      const challengeId = randomUUID();
      const challenge: Challenge = {
        id: challengeId,
        challenge: options.challenge,
        type: 'authentication',
        userId,
        expiresAt: new Date(Date.now() + challengeTimeoutMs),
      };
      
      await db.storeChallenge(challenge);
      
      return {
        challengeId,
        options: options as unknown as PublicKeyCredentialRequestOptionsJSON,
      };
    },
    
    async finishAuthentication(challengeId, response) {
      // Get and validate challenge
      const challenge = await db.getChallenge(challengeId);
      
      if (!challenge) {
        throw new Error('Challenge not found or expired');
      }
      
      if (challenge.type !== 'authentication') {
        throw new Error('Invalid challenge type');
      }
      
      if (challenge.expiresAt < new Date()) {
        await db.deleteChallenge(challengeId);
        throw new Error('Challenge expired');
      }
      
      // Find passkey by credential ID
      const passkey = await db.getPasskeyById(response.id);
      
      if (!passkey) {
        await db.deleteChallenge(challengeId);
        throw new Error('Passkey not found');
      }
      
      // Verify authentication
      let verification: VerifiedAuthenticationResponse;
      try {
        verification = await verifyAuthenticationResponse({
          response: response as unknown as Parameters<typeof verifyAuthenticationResponse>[0]['response'],
          expectedChallenge: challenge.challenge,
          expectedOrigin: config.origin,
          expectedRPID: config.rpId,
          credential: {
            id: passkey.credentialId,
            publicKey: passkey.publicKey,
            counter: passkey.counter,
            transports: passkey.transports,
          },
        } as VerifyAuthenticationResponseOpts);
      } catch (error) {
        console.error('[Passkey] Authentication verification failed:', error);
        await db.deleteChallenge(challengeId);
        return { verified: false };
      }
      
      if (!verification.verified) {
        await db.deleteChallenge(challengeId);
        return { verified: false };
      }
      
      // Update counter
      await db.updatePasskeyCounter(
        passkey.credentialId,
        verification.authenticationInfo.newCounter
      );
      
      // Clean up challenge
      await db.deleteChallenge(challengeId);
      
      return {
        verified: true,
        userId: passkey.userId,
        passkey,
      };
    },
  };
}
