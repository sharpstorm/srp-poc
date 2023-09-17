export class Hasher {
  hash;

  buffer;

  constructor(hash) {
    this.hash = hash;
    this.buffer = [];
  }

  update(newInput) {
    this.buffer.push(newInput);
    return this;
  }

  async digest() {
    const finalInput = new Uint8Array(
      this.buffer.reduce(
        (prev, curBuffer) => prev + curBuffer.length,
        0
      ));
    
    let curOffset = 0;
    this.buffer.forEach((inp) => {
      finalInput.set(inp, curOffset);
      curOffset += inp.length;
    });

    const digest = await crypto.subtle.digest(this.hash, finalInput);
    return new Uint8Array(digest);
  }
};
