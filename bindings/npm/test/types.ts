// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Compiled with `tsc -p test/tsconfig.json` (no output): the types cover
// the API as the tests use it.
import nq, { init, sign, kem, hash, capsule, dsse, idcard, algs,
  NoqtisError, codes, data, keyfile, hasher, blake2b, argon2id, cteq,
  armor, mail, pgp, keystore }
  from 'noqtis';
import { checkDir, packages } from 'noqtis/node';

async function main(): Promise<void> {
  await init();
  const sg = sign.signer('ML-DSA-44', new Uint8Array(2560)).update('m');
  const sb: Uint8Array = sg.sign({ deterministic: true });
  const vb: boolean = sign.verifier('ML-DSA-44', sb).update('m').verify(sb);
  const mu: Uint8Array = sign.mu('ML-DSA-44', sb, 'm');
  const sm: boolean = sign.verifymu('ML-DSA-44', sb, mu, sign.signmu('ML-DSA-44', sb, mu));
  const ks: Uint8Array = kem.open('ML-KEM-768', sb, kem.seal('ML-KEM-768', sb, 'm', { ctx: 'c' }));
  const se = kem.sealer('ML-KEM-768', sb, { chunk: 1024 });
  const hd: Uint8Array = se.header;
  const op: Uint8Array = kem.opener('ML-KEM-768', sb, hd).last(se.last('x'));
  for await (const p of kem.unbox('ML-KEM-768', sb, kem.box('ML-KEM-768', sb, ['a']))) {
    const q: Uint8Array = p;
  }
  const pw: Uint8Array = keyfile.pwdec('p', keyfile.pwenc('p', sb, { m: 8192 }));
  const kd = keyfile.decode(keyfile.encode('ML-DSA-44', 'sec', sb, { passphrase: 'p' }), { passphrase: 'p' });
  const hh: Uint8Array = hasher('sha256').update('x').digest();
  const bb: Uint8Array = blake2b('x', { key: 'k', length: 32 });
  const aa: Uint8Array = argon2id('pw', 'saltsalt', { t: 1, m: 8, p: 1 });
  const ce: boolean = cteq(bb, aa);
  const ar: string = armor.encode('NOQTIS TEST', sb);
  const ad: Uint8Array = armor.decode(ar).data;
  const cr: Uint8Array = mail.selfCert('ML-DSA-44', sb, sb, 'Ada', { email: 'a@example.org', notBefore: 0 });
  const kc: Uint8Array = mail.kemCert('ML-DSA-44', sb, cr, 'ML-KEM-768', sb);
  const ci: string = mail.readCert(cr).name;
  const cv = mail.cmsVerify(mail.cmsSign('ML-DSA-44', sb, cr, 'm', { detached: true }), [cr], { content: 'm' });
  const cn: string | undefined = cv?.signer.email;
  const cd: Uint8Array | null = mail.cmsDecrypt('ML-KEM-768', sb, mail.cmsEncrypt([kc], 'm'), { certificate: kc });
  const sv = mail.smimeVerify(mail.smimeSign('ML-DSA-44', sb, cr, 'e'), [cr]);
  const sn: string | undefined = sv?.entity;
  const sd: string | null = mail.smimeDecrypt('ML-KEM-768', sb, mail.smimeEncrypt([kc], 'e'));
  const pk = pgp.generate('Ada <a@example.org>', { alg: 'ed25519', encAlg: null, passphrase: 'p' });
  const pi: string | null = pgp.info(pk.certificate).encAlg;
  const pv = pgp.verify(pk.certificate, pgp.sign(pk.secretKey, 'm', { mode: 'detached' }), { content: 'm' });
  const pa: number | undefined = pv?.at;
  const po = pgp.decrypt(pgp.encrypt('m', { to: [pk.certificate], passphrase: 'x' }), { passphrase: 'x' });
  const ps: boolean | undefined = po?.signed;
  const pd: Uint8Array = pgp.dearmor(pgp.armor('message', sb)).data;
  const k1 = keystore.add(null, 'ML-DSA-44', sb, 'Me', { email: 'me@example.org' });
  const k2 = keystore.trust(k1.files, k1.fingerprint, 'ultimate');
  const kl: string = keystore.list(k2.files, 'me')[0].valid;
  const kx: string = keystore.export(k2.files, k1.fingerprint);
  const ki: number = keystore.imports(null, kx, { email: 'me@example.org' }).keys;
  const ku: string = keystore.url('me@example.org');
  const why = capsule.sealWhy(new Map())?.why;
  const tq: Uint8Array = capsule.tsreq(new Map());
  const bu: Map<string, Uint8Array> = capsule.unpack(capsule.pack(new Map()));
  const chh = capsule.chain([new Map()]).head;
  const ii = capsule.inspect(new Map()).checks;
  const cm = data.commit('{}', 'plan');
  const rv: number | null = data.reveal(cm.record, 'plan', cm.salt);
  const ct: string = data.cite(cm.record, 'bib') + data.report(new Map()) +
    data.env('{}', { packages: await Promise.resolve(packages('.')) }) +
    data.calibrate('{}', ['x']) + data.chunks('x', 'f', 1024);
  const pc: boolean = data.piece('{}', 'x', 0).ok;
  const sy: string = data.synth('{}', new Map(), 'f', 7).record;
  const rec: string = data.add(null, new Map([['a.csv', 'x\n1\n']]), 'a.csv');
  const ad: { kind: string; url: string }[] = data.addrs(rec, 'a.csv');
  const rs: { url: string; time: string } = data.reply({ kind: 'socrata' }, '{}');
  const dr: boolean = data.drift(data.pin(new Map([['a.csv', 'x\n1\n']]), 'a.csv'), 'x\n1\n').ok;
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
