// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// The CommonJS helpers return promises (they load the ES module lazily).
import type { Bytes, CheckOptions, CheckResult, Files, SealOptions, SignAlg }
  from './index.cjs';

export function readCapsule(dir: string): Promise<Map<string, Bytes>>;
/** lineage may name folders; dir may be null with opts.proof. */
export function checkDir(dir: string | null,
  opts?: Omit<CheckOptions, 'lineage'> & { lineage?: (string | Files)[] }):
  Promise<CheckResult>;
export function sealDir(dir: string, alg: SignAlg, secretKey: Bytes,
  publicKey: Bytes, opts?: SealOptions):
  Promise<{ 'noqtis.json': Bytes; 'noqtis.sig': Bytes }>;
