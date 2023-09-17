import { Hasher } from './hasher.js';
import { modPow } from './bigint-ext.js';
import { Params } from './params.js';
import { bnToBuf, bufToBn, calculateXOR, encodeString } from './utils.js';

// Adapted from node-srp by Mozilla

const zero = BigInt(0);

/*
 * If a conversion is explicitly specified with the operator PAD(),
 * the integer will first be implicitly converted, then the resultant
 * byte-string will be left-padded with zeros (if necessary) until its
 * length equals the implicitly-converted length of N.
 *
 * params:
 *         n (buffer)       Number to pad
 *         len (int)        length of the resulting Buffer
 *
 * returns: buffer
 */
function padTo(n, len) {
  const padding = len - n.length;
  const result = new Uint8Array(len);
  result.fill(0, 0, padding);
  result.set(n, padding);
  
  return result;
};

function padToN(number, params) {
  if (typeof number === 'bigint') {
    number = bnToBuf(number);
  }
  return padTo(number, params.N_length_bits / 8);
}

/*
 * compute the intermediate value x as a hash of three buffers:
 * salt, identity, and password.  And a colon.  FOUR buffers.
 *
 *      x = H(s | H(I | ":" | P))
 *
 * params:
 *         salt (buffer)    salt
 *         I (buffer)       user identity
 *         P (buffer)       user password
 *
 * returns: x (bignum)      user secret
 */
async function getX(params, salt, I, P) {
  const xBuf = await new Hasher(params.hash)
    .update(salt)
    .update(encodeString(`${I}:${P}`))
    .digest();

  return bufToBn(xBuf);
};

/*
 * The verifier is calculated as described in Section 3 of [SRP-RFC].
 * We give the algorithm here for convenience.
 *
 * The verifier (v) is computed based on the salt (s), user name (I),
 * password (P), and group parameters (N, g).
 *
 *         x = H(s | H(I | ":" | P))
 *         v = g^x % N
 *
 * params:
 *         params (obj)     group parameters, with .N, .g, .hash
 *         salt (buffer)    salt
 *         I (buffer)       user identity
 *         P (buffer)       user password
 *
 * returns: buffer
 */
async function computeVerifier(params, salt, I, P) {
  const x = await getX(params, salt, I, P);
  const vNum = modPow(params.g, x, params.N);
  return padToN(vNum, params);
};

/*
 * calculate the SRP-6 multiplier
 *
 * params:
 *         params (obj)     group parameters, with .N, .g, .hash
 *
 * returns: bignum
 */
async function getk(params) {
  return await new Hasher(params.hash)
    .update(padToN(params.N, params))
    .update(padToN(params.g, params))
    .digest();
};

/*
 * Generate a random key
 *
 * params:
 *         length (int)      length of key (default=32)
 */
function genKey(length) {
  if (!length) {
    length = 32;
  }

  const result = new Uint8Array(length);
  crypto.getRandomValues(result);
  return result;
};

/*
 * The client key exchange message carries the client's public value
 * (A).  The client calculates this value as A = g^a % N, where a is a
 * random number that SHOULD be at least 256 bits in length.
 *
 * Note: for this implementation, we take that to mean 256/8 bytes.
 *
 * params:
 *         params (obj)     group parameters, with .N, .g, .hash
 *         a (bignum)       client secret exponent
 *
 * returns A (bignum)       the client public message
 */
function getA(params, a_num) {
  return padToN(modPow(params.g, a_num, params.N), params);
};

/*
 * getU() hashes the two public messages together, to obtain a scrambling
 * parameter "u" which cannot be predicted by either party ahead of time.
 * This makes it safe to use the message ordering defined in the SRP-6a
 * paper, in which the server reveals their "B" value before the client
 * commits to their "A" value.
 *
 * params:
 *         params (obj)     group parameters, with .N, .g, .hash
 *         A (Buffer)       client ephemeral public key
 *         B (Buffer)       server ephemeral public key
 *
 * returns: u (bignum)      shared scrambling parameter
 */
async function getU(params, A, B) {
  const uBuf = await new Hasher(params.hash)
    .update(padToN(A, params))
    .update(padToN(B, params))
    .digest();

  return bufToBn(uBuf);
};

/*
 * The TLS premaster secret as calculated by the client
 *
 * params:
 *         params (obj)     group parameters, with .N, .g, .hash
 *         salt (buffer)    salt (read from server)
 *         I (buffer)       user identity (read from user)
 *         P (buffer)       user password (read from user)
 *         a (bignum)       ephemeral private key (generated for session)
 *         B (bignum)       server ephemeral public key (read from server)
 *
 * returns: buffer
 */

function client_getS(params, k_num, x_num, a_num, B_num, u_num) {
  const g = params.g;
  const N = params.N;
  if (zero >= B_num || N <= B_num) {
    throw new Error("invalid server-supplied 'B', must be 1..N-1");
  }

  const a1 = B_num - (k_num * modPow(g, x_num, N));
  const S_num = modPow(a1, a_num + (u_num * x_num), N);

  return padToN(S_num, params);
};

/*
 * Compute the shared session key K from S
 *
 * params:
 *         params (obj)     group parameters, with .N, .g, .hash
 *         S (buffer)       Session key
 *
 * returns: buffer
 */
async function getK(params, S_buf) {
  return await new Hasher(params.hash)
      .update(S_buf)
      .digest();
};

async function getM1(params, A_buf, B_buf, S_buf, identity, salt_buf) {
  const paramsHash = calculateXOR(padToN(params.g, params), padToN(params.N, params));
  const iHash = await new Hasher(params.hash).update(encodeString(identity)).digest();

  return await new Hasher(params.hash)
    .update(paramsHash)
    .update(iHash)
    .update(salt_buf)
    .update(A_buf)
    .update(B_buf)
    .update(await getK(params, S_buf))
    .digest();
}

async function getM2(params, A_buf, M_buf, K_buf) {
  return await new Hasher(params.hash)
    .update(A_buf).update(M_buf).update(K_buf)
    .digest();
}

function equal(buf1, buf2) {
  // constant-time comparison. A drop in the ocean compared to our
  // non-constant-time modexp operations, but still good practice.
  var mismatch = buf1.length - buf2.length;
  if (mismatch) {
    return false;
  }
  for (var i = 0; i < buf1.length; i++) {
    mismatch |= buf1[i] ^ buf2[i];
  }
  return mismatch === 0;
}

class Client {
  params;
  a_num;
  A_buf;
  kNum;
  xNum;
  identity;
  salt_buf;

  K_buf;
  M1_buf;
  M2_buf;
  S_buf;

  constructor(params, secret1Buf, kBuf) {
    this.params = params;
    this.kNum = bufToBn(kBuf);
    this.a_num = bufToBn(secret1Buf);
    this.A_buf = getA(this.params, this.a_num);
  }

  computeA() {
    return this.A_buf;
  }

  async setCredentials(identity, password, salt_buf) {
    this.identity = identity;
    this.salt_buf = salt_buf;
    this.xNum = await getX(this.params, salt_buf, identity, password);
  }

  async setB(B_buf) {
    const B_num = bufToBn(new Uint8Array(B_buf));
    const u_num = await getU(this.params, this.A_buf, B_buf);
    const S_buf = client_getS(this.params, this.kNum, this.xNum, this.a_num, B_num, u_num);
    this.S_buf = S_buf;
    this.K_buf = await getK(this.params, S_buf);
    this.M1_buf = await getM1(this.params, this.A_buf, B_buf, S_buf, this.identity, this.salt_buf);
    this.M2_buf = await getM2(this.params, this.A_buf, this.M1_buf, this.K_buf);
  }

  computeM1() {
    if (this.M1_buf === undefined)
      throw new Error("incomplete protocol");
    return this.M1_buf;
  }

  checkM2(serverM2_buf) {
    return equal(this.M2_buf, serverM2_buf)
  }

  computeK() {
    if (this.K_buf === undefined)
      throw new Error("incomplete protocol");
    return this.K_buf;
  }

  getSecret() {
    return this.S_buf;
  }

  static async new(params, secret1Buf) {
    const k = await getk(params);
    return new Client(params, secret1Buf, k);
  }
}

export {
  genKey,
  computeVerifier,
  Client,
  Params,
};
