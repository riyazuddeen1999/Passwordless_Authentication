import express from 'express';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} from '@simplewebauthn/server';
import base64url from 'base64url';
import WebAuthnCredential from '../models/WebAuthnCredential.js';
import { randomBytes } from 'crypto';

const router = express.Router();
const challengeMemory = new Map();

const rpName = process.env.RP_NAME || 'My WebAuthn App';
const rpID = process.env.RP_ID || 'localhost';
const origin = process.env.ORIGIN || `http://localhost:3001`;

function toBase64url(buffer) {
  return base64url.encode(Buffer.from(buffer));
}

// Registration
router.post('/register-options', (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'Missing username' });

  const options = generateRegistrationOptions({
    rpName,
    rpID,
    userID: Buffer.from(username, 'utf-8'),
    userName: username,
    attestationType: 'none',
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      userVerification: 'required',
    },
    timeout: 60000,
  });

  challengeMemory.set(username, toBase64url(options.challenge));

  options.challenge = toBase64url(options.challenge);
  if (options.user && options.user.id) {
    options.user.id = toBase64url(options.user.id);
  }

  res.json(options);
});

router.post('/verify-registration', async (req, res) => {
  const { username, attestationResponse } = req.body;
  if (!username || !attestationResponse) return res.status(400).json({ error: 'Missing data' });

  const expectedChallenge = challengeMemory.get(username);
  if (!expectedChallenge) return res.status(400).json({ error: 'No challenge for username' });

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: attestationResponse,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
    });
  } catch (err) {
    console.error('verifyRegistrationResponse error:', err);
    return res.status(400).json({ verified: false, error: err.message });
  }

  const { verified, registrationInfo } = verification;
  if (verified && registrationInfo) {
    const { credentialID, credentialPublicKey, counter } = registrationInfo;
    try {
      await WebAuthnCredential.create({
        username,
        credentialID: Buffer.from(credentialID),
        credentialPublicKey: Buffer.from(credentialPublicKey),
        counter,
      });
    } catch (dbErr) {
      console.error('DB save error:', dbErr);
      return res.status(500).json({ verified: false, error: 'DB save failed' });
    }
  }

  res.json({ verified });
});

// Login
router.post('/authn-options', async (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'Missing username' });

  const creds = await WebAuthnCredential.find({ username });
  if (!creds || creds.length === 0) {
    return res.status(404).json({ error: 'No credentials for user' });
  }

  const allowCredentialsForGen = creds.map(c => ({
    id: base64url.encode(Buffer.from(c.credentialID)), 
    type: 'public-key',
    transports: c.transports || ['internal'],
  }));

  const options = generateAuthenticationOptions({
    allowCredentials: allowCredentialsForGen, 
    userVerification: 'required',
    rpID,
  });

  challengeMemory.set(username, toBase64url(options.challenge));

  options.challenge = toBase64url(options.challenge);
  options.allowCredentials = allowCredentialsForGen;

  /*options.allowCredentials = options.allowCredentials.map(c => ({
    ...c,
    id: toBase64url(c.id),
  })); */

  res.json(options);
});

router.post('/verify-authn', async (req, res) => {
  const { username, assertionResponse } = req.body;
  if (!username || !assertionResponse) return res.status(400).json({ error: 'Missing data' });

  const expectedChallenge = challengeMemory.get(username);
  if (!expectedChallenge) return res.status(400).json({ error: 'No challenge for username' });

  const cred = await WebAuthnCredential.findOne({ username });
  if (!cred) return res.status(404).json({ error: 'Credential not found' });

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response: assertionResponse,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      authenticator: {
        credentialID: cred.credentialID,
        credentialPublicKey: cred.credentialPublicKey,
        counter: cred.counter,
      },
    });
  } catch (err) {
    console.error('verifyAuthenticationResponse error:', err);
    return res.status(400).json({ verified: false, error: err.message });
  }

  if (verification.verified) {
    cred.counter = verification.authenticationInfo.newCounter;
    await cred.save();
  }

  res.json({ verified: verification.verified });
});

export default router;
