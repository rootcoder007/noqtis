// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// The CommonJS helpers return promises (they load the ES module lazily).
import type { Bytes, CheckResult, SignAlg } from './index.cjs';

export function readCapsule(dir: string): Promise<Map<string, Bytes>>;
export function checkDir(dir: string,
  opts?: { trust?: Bytes; anchors?: Bytes[] }): Promise<CheckResult>;
export function sealDir(dir: string, alg: SignAlg, secretKey: Bytes,
  publicKey: Bytes, opts?: { meta?: unknown; time?: number }):
  Promise<{ 'noqtis.json': Bytes; 'noqtis.sig': Bytes }>;
