// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
import type { Bytes, CheckResult, SignAlg } from './index.js';

/** Every regular file under dir; a link or special file throws (NQEARG). */
export function readCapsule(dir: string): Map<string, Bytes>;
export function checkDir(dir: string,
  opts?: { trust?: Bytes; anchors?: Bytes[] }): CheckResult;
/** Writes noqtis.json and noqtis.sig into dir and returns them. */
export function sealDir(dir: string, alg: SignAlg, secretKey: Bytes,
  publicKey: Bytes, opts?: { meta?: unknown; time?: number }):
  { 'noqtis.json': Bytes; 'noqtis.sig': Bytes };
