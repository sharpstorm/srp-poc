import { launchHandshake, launchWhoami } from './auth.js';
import { AUTH_OK } from './auth.js';
import { Hasher } from './hasher.js';
import { encodeString } from './utils.js';

document.addEventListener('DOMContentLoaded', () => {
  const userField = document.getElementById('username');
  const passwordField = document.getElementById('password');
  const loginBtn = document.getElementById('login-btn');
  const authStatus = document.getElementById('auth-status');
  const sessionId = document.getElementById('session-id');
  const sessionSecret = document.getElementById('session-secret');

  const whoamiBtn = document.getElementById('whoami-btn');
  const serverWhoamiProof = document.getElementById('server-whoami-proof');
  const clientWhoamiProof = document.getElementById('client-whoami-proof');

  let curUsername = '';
  let secret = null;
  let curSessionId = null;

  const toHexString = (arr) => arr.reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');

  loginBtn.addEventListener('click', async () => {
    curUsername = userField.value;
    const result = await launchHandshake(userField.value, passwordField.value);
    console.log(result);

    authStatus.textContent = result.status;
    if (result.status === AUTH_OK) {
      sessionId.textContent = result.sessionId;
      sessionSecret.textContent = toHexString(result.secret);
      secret = result.secret;
      curSessionId = result.sessionId;
    }
  });

  whoamiBtn.addEventListener('click', async () => {
    if (!secret || !curSessionId) {
      console.log('No secret');
      return;
    }

    const clientProof = await new Hasher('SHA-512')
      .update(encodeString(curUsername))
      .update(secret)
      .digest();

    const proof = await launchWhoami(curSessionId);
    serverWhoamiProof.textContent = toHexString(proof);
    clientWhoamiProof.textContent = toHexString(clientProof);
  });
});
