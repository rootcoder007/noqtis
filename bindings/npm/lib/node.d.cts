// SPDX-License-Identifier: LGPL-3.0-or-later
// The CommonJS helpers return promises (they load the ES module lazily).
import type { Bytes, CheckOptions, CheckResult, Files, Package, SealOptions,
  SignAlg } from './index.cjs';

export function readCapsule(dir: string): Promise<Map<string, Bytes>>;
/** lineage may name folders; dir may be null with opts.proof. */
export function checkDir(dir: string | null,
  opts?: Omit<CheckOptions, 'lineage'> & { lineage?: (string | Files)[] }):
  Promise<CheckResult>;
export function sealDir(dir: string, alg: SignAlg, secretKey: Bytes,
  publicKey: Bytes, opts?: SealOptions):
  Promise<{ 'noqtis.json': Bytes; 'noqtis.sig': Bytes }>;
/** The packages of dir's package-lock.json, for data.env. */
export function packages(dir?: string): Promise<Package[]>;
