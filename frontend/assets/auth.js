import {
  genKey,
  Client,
  Params,
} from './srp.js';

import { encodeBase64, decodeBase64 } from './utils.js';

const params = Params['3072'];
const HANDSHAKE_ROUTE = '/api/auth/handshake';
const VERIFY_ROUTE = '/api/auth/verify';
const WHOAMI_ROUTE = '/api/auth/whoami';

export const AUTH_OK = 'ok';
export const AUTH_WRONG_USERNAME = 'wrong username';
export const AUTH_WRONG_PASSWORD = 'wrong password';
export const AUTH_INVALID_SERVER = 'wrong server';

async function request(url, body) {
  const resp = await fetch(url, {
    method: 'POST',
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });
  return await resp.json();
}

export async function launchHandshake(username, password) {
  const clientRandomPK = genKey();
  const client = await Client.new(params, clientRandomPK);
  let resp, resp2;
  try {
    resp = await request(HANDSHAKE_ROUTE, {
      username,
      clientpublic: encodeBase64(client.computeA()),
    });
  } catch (err) {
    return {
      status: AUTH_WRONG_USERNAME,
    };
  }

  const hid = resp.hid;
  const salt = decodeBase64(resp.salt);
  const publicKey = decodeBase64(resp.publickey);

  await client.setCredentials(username, password, salt);
  await client.setB(publicKey);

  try {
    resp2 = await request(VERIFY_ROUTE, {
      hid,
      username,
      clientproof: encodeBase64(client.computeM1()),
    });
  } catch (err) {
    return {
      status: AUTH_WRONG_PASSWORD,
    };
  }

  if (!resp2.result) {
    return {
      status: AUTH_WRONG_PASSWORD,
    };
  }

  if (!client.checkM2(decodeBase64(resp2.serverproof))) {
    return {
      status: AUTH_INVALID_SERVER,
    };
  }

  return {
    status: AUTH_OK,
    sessionId: resp2.sessionid,
    secret: client.getSecret(),
  };
}

export async function launchWhoami(sessionId) {
  const resp = await request(WHOAMI_ROUTE, {
    sessionid: sessionId,
  });

  return decodeBase64(resp.proof);
}

