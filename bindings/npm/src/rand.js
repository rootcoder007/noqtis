// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
// emscripten library override: getentropy() (and so nqrand) reads
// crypto.getRandomValues on every runtime, Node included (on Node 18,
// which has no global WebCrypto, init() hands in node:crypto's webcrypto).
// A missing or failing source returns an error, which nqrand turns into
// NQERNG; there is no fallback.
addToLibrary({
  $initRandomFill: () => (view) => {
    try {
      // init() passes the WebCrypto object it found as Module.nqcrypto
      const c = Module['nqcrypto'] || globalThis.crypto;
      // getRandomValues takes at most 65536 bytes; getentropy asks <= 256
      for (let i = 0; i < view.length; i += 65536) {
        c.getRandomValues(view.subarray(i, Math.min(view.length, i + 65536)));
      }
      return 0;
    } catch (e) {
      return 52; // ENOSYS
    }
  },
});
