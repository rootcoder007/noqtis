/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* OpenPGP (src/pgp/pgp.c): what the tests and the fuzz targets reach
 * past the public API of noqtis.h. */
#ifndef NQPGP_H
#define NQPGP_H

#include <stdint.h>

#ifdef NQTEST
/* The Argon2id numbers of passphrase-protected keys and messages, for a
 * test build: t passes, p lanes and 2^m KiB are what is written from
 * then on, and t and m the most that is read (more is NQELIM). A fuzz
 * target sets them small, so that an input cannot ask for gigabytes. */
void nqpgps2k(unsigned t, unsigned p, unsigned m);
/* Two keys the caller made and vouches for (either may be NULL): read
 * from these very addresses, their self-signatures are taken as good
 * without being checked again. A fuzz target names its own fixed key
 * and certificate, which every call would otherwise verify anew; a key
 * that comes from the input is checked as ever. */
void nqpgpvouch(const uint8_t *a, const uint8_t *b);
#endif

#endif
