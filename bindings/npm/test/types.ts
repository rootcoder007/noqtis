// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Compiled with `tsc -p test/tsconfig.json` (no output): the types cover
// the API as the tests use it.
import nq, { init, sign, kem, hash, capsule, dsse, idcard, algs,
  NoqtisError, codes }
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
  const r2 = checkDir('.', { lineage: ['..'], only: ['a'] });
  const f2 = capsule.seal(new Map([['a', 'x']]), 'ML-DSA-65', k.secretKey,
    k.publicKey, { format: 2, inputs: [{ name: 'in', id: new Uint8Array(32) }] });
  const id: Uint8Array = capsule.id(new Map(Object.entries(f2)));
  const pr: Uint8Array = capsule.prove(new Map(), ['a']);
  const r3 = capsule.check(null, { proof: pr, keys: ['{}'], lineage: [] });
  const fl: string = capsule.files(new Map())[0]?.sha256 ?? '';
  const st: Uint8Array = capsule.revoke('ML-DSA-65', k.secretKey,
    k.publicKey, { at: new Date(), reason: 'r' });
  const env = dsse.sign('ML-DSA-65', k.secretKey, k.publicKey, 't', 'p');
  const v = dsse.verify('ML-DSA-65', k.publicKey, env);
  const card: Uint8Array = idcard.make('ML-DSA-65', k.secretKey,
    k.publicKey, { name: 'A', orcid: null, url: 'https://a' }, { at: 0 });
  const c = idcard.verify(card, { trust: k.publicKey });
  const who: string | null = c ? c.orcid : null;
  console.log(id, r3.ok, fl, st, v?.payloadType, who, c?.keySha256);
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
