// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
import type { Bytes, CheckOptions, CheckResult, Files, SealOptions, SignAlg }
  from './index.js';

/** Every regular file under dir; a link or special file throws (NQEARG). */
export function readCapsule(dir: string): Map<string, Bytes>;
/** lineage may name folders; dir may be null with opts.proof. */
export function checkDir(dir: string | null,
  opts?: Omit<CheckOptions, 'lineage'> & { lineage?: (string | Files)[] }):
  CheckResult;
/** Writes noqtis.json and noqtis.sig into dir and returns them. */
export function sealDir(dir: string, alg: SignAlg, secretKey: Bytes,
  publicKey: Bytes, opts?: SealOptions):
  { 'noqtis.json': Bytes; 'noqtis.sig': Bytes };
