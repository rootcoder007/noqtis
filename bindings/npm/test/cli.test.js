// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Cross-checks against the native CLI: keys, signatures, KEM ciphertexts
// and capsules made by one side are accepted by the other. NOQTIS_CLI is
// the path to a native `noqtis` build; without it these tests skip.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { init, sign, kem, keyfile } from '../lib/index.js';
import { checkDir, sealDir } from '../lib/node.js';

await init();

const cli = process.env.NOQTIS_CLI;
const skip = cli ? false : 'NOQTIS_CLI is not set';
const hex = (u8) => Buffer.from(u8).toString('hex');

function run(args, want = 0) {
  const r = spawnSync(cli, args, { encoding: 'utf8', stdio: ['ignore', 'pipe',
    'pipe'] });
  assert.equal(r.status, want,
    `noqtis ${args.join(' ')}: ${r.status}\n${r.stdout}${r.stderr}`);
  return r.stdout;
}

function tmp(fn) {
  const d = mkdtempSync(join(tmpdir(), 'nqcli-'));
  try {
    fn(d);
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
}

const SIG = ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87', 'SLH-DSA-SHA2-128f',
  'SLH-DSA-SHAKE-128f', 'SLH-DSA-SHA2-192f'];
const KEM = ['ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024', 'HQC-128'];

for (const alg of SIG) {
  test(`cli sign ${alg}`, { skip }, () => tmp((d) => {
    const n = alg.startsWith('ML-DSA') ? 32
      : 3 * Number(alg.match(/(\d+)f$/)[1]) / 8;
    const seed = new Uint8Array(n).map((_, i) => (i * 7 + 3) & 255);
    const k = join(d, 'k');
    run(['keygen', '-a', alg, '-o', k, '--seed', hex(seed)]);
    const pub = keyfile.decode(readFileSync(`${k}.pub`, 'utf8'));
    const sec = keyfile.decode(readFileSync(k, 'utf8'));
    const js = sign.keygen(alg, { seed });
    assert.equal(pub.alg, alg);
    assert.equal(hex(pub.key), hex(js.publicKey));
    assert.equal(hex(sec.key), hex(js.secretKey));
    // the JS key file is the CLI's, byte for byte
    assert.equal(keyfile.encode(alg, 'pub', js.publicKey),
      readFileSync(`${k}.pub`, 'utf8'));

    const msg = join(d, 'msg');
    writeFileSync(msg, 'cross-checked message\n');
    const m = readFileSync(msg);
    // CLI signs, JS verifies
    run(['sign', '-k', k, '-c', 'ctx1', '-o', join(d, 's1'), msg]);
    const s1 = readFileSync(join(d, 's1'));
    assert.equal(sign.verify(alg, js.publicKey, m, s1, { ctx: 'ctx1' }), true);
    assert.equal(sign.verify(alg, js.publicKey, m, s1, { ctx: 'ctx2' }),
      false);
    // deterministic signatures agree byte for byte
    run(['sign', '-k', k, '-d', '-o', join(d, 's2'), msg]);
    assert.equal(hex(readFileSync(join(d, 's2'))),
      hex(sign.sign(alg, js.secretKey, m, { deterministic: true })));
    // pre-hash
    run(['sign', '-k', k, '--ph', 'sha256', '-o', join(d, 's3'), msg]);
    assert.equal(sign.verify(alg, js.publicKey, m, readFileSync(join(d, 's3')),
      { prehash: 'sha256' }), true);
    // JS signs, CLI verifies
    const s4 = sign.sign(alg, js.secretKey, m, { ctx: 'ctx4' });
    writeFileSync(join(d, 's4'), s4);
    run(['verify', '-p', `${k}.pub`, '-s', join(d, 's4'), '-c', 'ctx4', '-q',
      msg]);
    run(['verify', '-p', `${k}.pub`, '-s', join(d, 's4'), '-q', msg], 1);
    const s5 = sign.sign(alg, js.secretKey, m, { prehash: 'sha3-256' });
    writeFileSync(join(d, 's5'), s5);
    run(['verify', '-p', `${k}.pub`, '-s', join(d, 's5'), '--ph', 'sha3-256',
      '-q', msg]);
    s4[10] ^= 1;
    writeFileSync(join(d, 's4'), s4);
    run(['verify', '-p', `${k}.pub`, '-s', join(d, 's4'), '-c', 'ctx4', '-q',
      msg], 1);
  }));
}

for (const alg of KEM) {
  test(`cli kem ${alg}`, { skip }, () => tmp((d) => {
    const js = kem.keygen(alg);
    const k = join(d, 'k');
    writeFileSync(k, keyfile.encode(alg, 'sec', js.secretKey), { mode: 0o600 });
    writeFileSync(`${k}.pub`, keyfile.encode(alg, 'pub', js.publicKey));
    // CLI encapsulates to the JS key, JS decapsulates
    const ss = run(['enc', '-p', `${k}.pub`, '-o', join(d, 'ct'),
      '--stdout']).trim();
    assert.equal(hex(kem.decap(alg, js.secretKey, readFileSync(join(d, 'ct')))),
      ss);
    // JS encapsulates, CLI decapsulates
    const e = kem.encap(alg, js.publicKey);
    writeFileSync(join(d, 'ct2'), e.ciphertext);
    assert.equal(run(['dec', '-k', k, '--stdout', join(d, 'ct2')]).trim(),
      hex(e.sharedSecret));
  }));
}

test('cli capsules', { skip }, () => tmp((d) => {
  const js = sign.keygen('ML-DSA-65');
  const k = join(d, 'k');
  writeFileSync(k, keyfile.encode('ML-DSA-65', 'sec', js.secretKey),
    { mode: 0o600 });
  writeFileSync(`${k}.pub`, keyfile.encode('ML-DSA-65', 'pub', js.publicKey));
  // JS seals, CLI checks
  const c1 = join(d, 'c1');
  mkdirSync(join(c1, 'x'), { recursive: true });
  writeFileSync(join(c1, 'a'), 'a');
  writeFileSync(join(c1, 'x', 'b'), 'bb');
  sealDir(c1, 'ML-DSA-65', js.secretKey, js.publicKey, { meta: { by: 'js' } });
  run(['check', '-p', `${k}.pub`, c1]);
  writeFileSync(join(c1, 'a'), 'A');
  run(['check', c1], 1);
  // CLI seals, JS checks
  const c2 = join(d, 'c2');
  mkdirSync(join(c2, 'y'), { recursive: true });
  writeFileSync(join(c2, 'y', 'z'), new Uint8Array(5000));
  run(['seal', '-k', k, c2]);
  const r = checkDir(c2, { trust: js.publicKey });
  assert.equal(r.ok, true, JSON.stringify(r.checks));
  // the CLI's --json report and the JS report list the same checks
  const j = JSON.parse(run(['check', '--json', c2]));
  assert.deepEqual(j.checks.map((c) => c.check),
    checkDir(c2).checks.map((c) => c.check));
}));
