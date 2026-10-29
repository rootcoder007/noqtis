// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Compiled with `tsc -p test/tsconfig.json` (no output): the types cover
// the API as the tests use it.
import nq, { init, sign, kem, hash, capsule, algs, NoqtisError, codes }
  from 'noqtis';
import { checkDir } from 'noqtis/node';

async function main(): Promise<void> {
  await init();
  const k = sign.keygen('ML-DSA-65', { seed: new Uint8Array(32) });
  const s: Uint8Array = sign.sign('ML-DSA-65', k.secretKey, 'm',
    { ctx: 'c', deterministic: true, prehash: 'sha256' });
  const ok: boolean = sign.verify('ML-DSA-65', k.publicKey, 'm', s);
  const e = kem.encap('ML-KEM-768', kem.keygen('ML-KEM-768').publicKey);
  const ss: Uint8Array = e.sharedSecret;
  const d: Uint8Array = hash('shake256', ss, { length: 10 });
  const r = capsule.check(new Map([['a', 'x']]), { trust: k.publicKey });
  const r2 = checkDir('.', {});
  for (const a of algs()) {
    if (a.kind === 'kem') console.log(a.ciphertext);
  }
  try {
    nq.sign.keygen('x');
  } catch (err) {
    if (err instanceof NoqtisError && err.code === codes.ENOSUP) return;
  }
  console.log(ok, d, r.ok, r2.checks[0]?.detail);
}
void main();
