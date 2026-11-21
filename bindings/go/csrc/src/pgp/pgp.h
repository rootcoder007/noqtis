/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* OpenPGP (src/pgp/pgp.c): what the tests and the fuzz targets reach
 * past the public API of noqtis.h. */
#ifndef NQPGP_H
#define NQPGP_H

#ifdef NQTEST
/* The Argon2id numbers of passphrase-protected keys and messages, for a
 * test build: t passes, p lanes and 2^m KiB are what is written from
 * then on, and t and m the most that is read (more is NQELIM). A fuzz
 * target sets them small, so that an input cannot ask for gigabytes. */
void nqpgps2k(unsigned t, unsigned p, unsigned m);
#endif

#endif
