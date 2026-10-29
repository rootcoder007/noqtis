/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/*
 * noqtis: base64 (RFC 4648, with padding) and hex, in constant time: key
 * files and seeds are secret, so no table lookup or branch depends on a
 * data byte. Line breaks sit at public positions and are skipped.
 */
#include "cli.h"

/* 1 when a < b, for a, b < 2^31 */
static uint32_t lt(uint32_t a, uint32_t b) {
  return (a - b) >> 31;
}

/* 1 when a == b, for a, b < 2^31 */
static uint32_t eq(uint32_t a, uint32_t b) {
  return ((a ^ b) - 1u) >> 31;
}

static char b64c(uint32_t x) {
  uint32_t c = x + 'A';
  c += 6u & (0u - lt(25u, x));        /* 26..51 -> 'a'.. */
  c -= 75u & (0u - lt(51u, x));       /* 52..61 -> '0'.. */
  c -= 15u & (0u - lt(61u, x));       /* 62 -> '+' */
  c += 3u & (0u - lt(62u, x));        /* 63 -> '/' */
  return (char)c;
}

/* The 6-bit value of c, or a value with bit 8 set when c is not in the
 * alphabet. */
static uint32_t b64v(uint32_t c) {
  uint32_t m, v = 0, ok = 0;
  m = 0u - ((1u - lt(c, 'A')) & lt(c, 'Z' + 1u));
  v |= m & (c - 'A');
  ok |= m;
  m = 0u - ((1u - lt(c, 'a')) & lt(c, 'z' + 1u));
  v |= m & (c - 'a' + 26u);
  ok |= m;
  m = 0u - ((1u - lt(c, '0')) & lt(c, '9' + 1u));
  v |= m & (c - '0' + 52u);
  ok |= m;
  m = 0u - eq(c, '+');
  v |= m & 62u;
  ok |= m;
  m = 0u - eq(c, '/');
  v |= m & 63u;
  ok |= m;
  return v | (~ok & 0x100u);
}

size_t ncb64n(size_t len) {
  size_t e = (len + 2) / 3 * 4;
  return e + (e + 63) / 64;
}

void ncb64e(const uint8_t *in, size_t len, char *out) {
  size_t i, o = 0, col = 0;
  for (i = 0; i < len; i += 3) {
    uint32_t w = (uint32_t)in[i] << 16;
    int two = i + 1 < len, three = i + 2 < len;
    if (two)
      w |= (uint32_t)in[i + 1] << 8;
    if (three)
      w |= in[i + 2];
    out[o++] = b64c((w >> 18) & 63u);
    out[o++] = b64c((w >> 12) & 63u);
    out[o++] = two ? b64c((w >> 6) & 63u) : '=';
    out[o++] = three ? b64c(w & 63u) : '=';
    col += 4;
    if (col == 64) {
      out[o++] = '\n';
      col = 0;
    }
  }
  if (col != 0)
    out[o++] = '\n';
}

int ncb64d(const char *in, size_t inlen, uint8_t *out, size_t outmax,
           size_t *outlen) {
  uint32_t q[4], bad = 0;
  size_t i, nq = 0, o = 0, pad = 0;
  int rc = NQOK;
  *outlen = 0;
  for (i = 0; i < inlen && rc == NQOK; i++) {
    if (in[i] == '\n' || in[i] == '\r')
      continue;
    if (pad > 0 && in[i] != '=') {
      rc = NQEDEC; /* data after padding */
      break;
    }
    if (in[i] == '=') {
      /* padding only in the last two places of a quantum */
      if (nq < 2) {
        rc = NQEDEC;
        break;
      }
      pad++;
      q[nq++] = 0;
    } else {
      q[nq] = b64v((uint8_t)in[i]);
      bad |= q[nq];
      nq++;
    }
    if (nq == 4) {
      uint32_t w = (q[0] << 18) | (q[1] << 12) | (q[2] << 6) | q[3];
      size_t k = 3 - pad;
      if (o + k > outmax) {
        rc = NQEDEC;
        break;
      }
      out[o] = (uint8_t)(w >> 16);
      if (k > 1)
        out[o + 1] = (uint8_t)(w >> 8);
      if (k > 2)
        out[o + 2] = (uint8_t)w;
      /* the bits under the padding must be zero (canonical form) */
      if (pad == 1)
        bad |= (w & 0xffu) << 8;
      if (pad == 2)
        bad |= (w & 0xffffu) << 8;
      o += k;
      nq = 0;
      if (pad > 0)
        pad = 3; /* nothing may follow a padded quantum */
      nqwipe(&w, sizeof w);
    }
  }
  if (nq != 0 || (bad >> 8) != 0)
    rc = NQEDEC;
  nqwipe(q, sizeof q);
  if (rc != NQOK) {
    nqwipe(out, o < outmax ? o : outmax);
    return rc;
  }
  *outlen = o;
  return NQOK;
}

void nchexe(const uint8_t *in, size_t len, char *out) {
  size_t i;
  for (i = 0; i < len; i++) {
    uint32_t h = (uint32_t)in[i] >> 4, l = (uint32_t)in[i] & 15u;
    out[2 * i] = (char)(h + '0' + (39u & (0u - lt(9u, h))));
    out[2 * i + 1] = (char)(l + '0' + (39u & (0u - lt(9u, l))));
  }
}

/* The nibble of c, or a value with bit 8 set. */
static uint32_t hexv(uint32_t c) {
  uint32_t m, v = 0, ok = 0;
  m = 0u - ((1u - lt(c, '0')) & lt(c, '9' + 1u));
  v |= m & (c - '0');
  ok |= m;
  c |= 0x20u; /* lower case */
  m = 0u - ((1u - lt(c, 'a')) & lt(c, 'f' + 1u));
  v |= m & (c - 'a' + 10u);
  ok |= m;
  return v | (~ok & 0x100u);
}

int nchexd(const char *in, size_t inlen, uint8_t *out, size_t outmax,
           size_t *outlen) {
  size_t i;
  uint32_t bad = 0;
  *outlen = 0;
  if (inlen % 2 != 0 || inlen / 2 > outmax)
    return NQEDEC;
  for (i = 0; i < inlen / 2; i++) {
    uint32_t h = hexv((uint8_t)in[2 * i]), l = hexv((uint8_t)in[2 * i + 1]);
    bad |= h | l;
    out[i] = (uint8_t)((h << 4) | (l & 15u));
  }
  if ((bad & 0x100u) != 0) {
    nqwipe(out, inlen / 2);
    return NQEDEC;
  }
  *outlen = inlen / 2;
  return NQOK;
}
