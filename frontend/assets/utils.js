export const encodeBase64 = (uint8array) => {
  const output = [];
  for (let i = 0, {length} = uint8array; i < length; i++)
    output.push(String.fromCharCode(uint8array[i]));
  return btoa(output.join(''));
}

const asCharCode = c => c.charCodeAt(0);
export const decodeBase64 = chars => Uint8Array.from(atob(chars), asCharCode);

export function bnToBuf(bn) {
  let hex = BigInt(bn).toString(16);
  if (hex.length % 2) {
    hex = '0' + hex;
  }

  const len = hex.length / 2;
  const u8 = new Uint8Array(len);

  let i = 0;
  let j = 0;
  while (i < len) {
    u8[i] = parseInt(hex.slice(j, j+2), 16);
    i += 1;
    j += 2;
  }

  return u8;
}

export function bufToBn(buf) {
  var hex = [];
  const u8 = Uint8Array.from(buf);

  u8.forEach(function (i) {
    var h = i.toString(16);
    if (h.length % 2) { h = '0' + h; }
    hex.push(h);
  });

  return BigInt('0x' + hex.join(''));
}

export function calculateXOR(arr1, arr2) {
  let result = new Uint8Array(arr1.length);
  for (let i = 0; i < result.length; i++) {
     result[i] = arr1[i] ^ arr2[i];
  }

  return result;
}

const encoder = new TextEncoder();
export function encodeString(inp) {
  return encoder.encode(inp);
}
