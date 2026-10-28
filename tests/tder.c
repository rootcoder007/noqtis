/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* The strict DER reader: every encoding rule, with accept and reject
 * tables, the depth limit, the typed helpers and the times. */
#include <stdio.h>
#include <string.h>

#include "core/json.h"
#include "der/der.h"
#include "nqt.h"

typedef struct {
  const char *hex; /* one element */
  int want;        /* NQOK, NQEDEC or NQELIM from nqdone */
  const char *why;
} vec;

/* nqdone over every encoding rule */
static const vec rules[] = {
    {"0500", NQOK, "NULL"},
    {"3000", NQOK, "empty SEQUENCE"},
    {"3100", NQOK, "empty SET"},
    {"300302010a", NQOK, "SEQUENCE { INTEGER }"},
    {"04817f" "00", NQEDEC, "long form below 128"},
    {"0482007f" "00", NQEDEC, "leading zero length octet"},
    {"048500000000ff", NQELIM, "five length octets"},
    {"0480", NQEDEC, "indefinite length"},
    {"30800000", NQEDEC, "indefinite constructed"},
    {"0402aa", NQEDEC, "length past the end"},
    {"04", NQEDEC, "no length"},
    {"", NQEDEC, "empty"},
    {"050000", NQEDEC, "trailing byte"},
    {"30020500" "00", NQEDEC, "trailing byte after SEQUENCE"},
    {"0000", NQEDEC, "end-of-contents"},
    {"1f2200", NQEDEC, "high-form universal tag"},
    {"9f1e00", NQEDEC, "high form for tag 30"},
    {"9f1f00", NQOK, "high form for tag 31"},
    {"9f807f00", NQEDEC, "leading zero septet in tag"},
    {"9fff7f00", NQOK, "tag 16383"},
    {"9fffff7f00", NQOK, "tag 2^21 - 1"},
    {"9f8180808000", NQELIM, "tag of four septets"},
    {"9f81", NQEDEC, "tag cut short"},
    {"2203020100", NQEDEC, "constructed INTEGER"},
    {"2403040100", NQEDEC, "constructed OCTET STRING"},
    {"1000", NQEDEC, "primitive SEQUENCE"},
    {"1100", NQEDEC, "primitive SET"},
    {"0900", NQEDEC, "REAL: not a PKIX type"},
    {"0700", NQEDEC, "ObjectDescriptor"},
    {"0d00", NQEDEC, "RELATIVE-OID"},
    {"0e00", NQEDEC, "TIME"},
    {"2800", NQEDEC, "EXTERNAL"},
    {"a000", NQOK, "empty [0] constructed"},
    {"8000", NQOK, "empty [0] primitive"},
    {"a0030500", NQEDEC, "[0] whose child overruns"},
    {"a00405000500", NQOK, "[0] { NULL NULL }"},
    {"3003050000", NQEDEC, "child shorter than the parent"},
    {"300405000500" "00", NQEDEC, "trailing after constructed"},
    {"30063003020100", NQEDEC, "parent longer than its bytes"},
    /* contents */
    {"0101ff", NQOK, "BOOLEAN TRUE"},
    {"010100", NQOK, "BOOLEAN FALSE"},
    {"010101", NQEDEC, "BOOLEAN 01"},
    {"0102ffff", NQEDEC, "BOOLEAN of two octets"},
    {"0100", NQEDEC, "BOOLEAN empty"},
    {"0200", NQEDEC, "INTEGER empty"},
    {"020100", NQOK, "INTEGER 0"},
    {"0202007f", NQEDEC, "INTEGER 00 7f"},
    {"02020080", NQOK, "INTEGER 128"},
    {"0202ff80", NQEDEC, "INTEGER ff 80"},
    {"0202ff7f", NQOK, "INTEGER -129"},
    {"0a0100", NQOK, "ENUMERATED 0"},
    {"0a020001", NQEDEC, "ENUMERATED 00 01"},
    {"050100", NQEDEC, "NULL with contents"},
    {"0600", NQEDEC, "OID empty"},
    {"0603551d13", NQOK, "OID 2.5.29.19"},
    {"0603558001", NQEDEC, "OID leading zero septet"},
    {"0602559d", NQEDEC, "OID cut in a subidentifier"},
    {"0601800", NQEDEC, "odd hex: not decoded"},
    {"06068fffffff7f01", NQOK, "OID arc 2^32 - 1"},
    {"06062a9080808000", NQEDEC, "OID arc 2^32"},
    {"06092a864886f70d010983", NQEDEC, "OID trailing arc cut"},
    {"0301" "00", NQOK, "BIT STRING empty"},
    {"030101", NQEDEC, "BIT STRING empty with unused bits"},
    {"03020800", NQEDEC, "BIT STRING 8 unused bits"},
    {"03020101", NQEDEC, "BIT STRING padding bit set"},
    {"03020102", NQOK, "BIT STRING 7 bits"},
    {"0300", NQEDEC, "BIT STRING no unused-bits octet"},
    {"0c03616263", NQOK, "UTF8String abc"},
    {"0c02c3a9", NQOK, "UTF8String e-acute"},
    {"0c02c080", NQEDEC, "UTF8String overlong NUL"},
    {"0c03e08080", NQEDEC, "UTF8String overlong three octets"},
    {"0c03eda080", NQEDEC, "UTF8String surrogate"},
    {"0c04f4908080", NQEDEC, "UTF8String above U+10FFFF"},
    {"0c04f09f9880", NQOK, "UTF8String four octets"},
    {"0c01ff", NQEDEC, "UTF8String ff"},
    {"0c02c3", NQEDEC, "UTF8String cut"},
    {"0c0180", NQEDEC, "UTF8String lone continuation"},
    {"130a41617a5a303920272829", NQOK, "PrintableString set"},
    {"13022b2c", NQOK, "PrintableString + ,"},
    {"130140", NQEDEC, "PrintableString @"},
    {"13012a", NQEDEC, "PrintableString *"},
    {"130100", NQEDEC, "PrintableString NUL"},
    {"1603612140", NQOK, "IA5String"},
    {"160180", NQEDEC, "IA5String 80"},
    {"1a027e20", NQOK, "VisibleString"},
    {"1a017f", NQEDEC, "VisibleString DEL"},
    {"1a011f", NQEDEC, "VisibleString control"},
    {"1203303120", NQOK, "NumericString"},
    {"120161", NQEDEC, "NumericString letter"},
    {"1e020041", NQOK, "BMPString"},
    {"1e0100", NQEDEC, "BMPString odd"},
    {"1e02d800", NQEDEC, "BMPString surrogate"},
    {"1c0400000041", NQOK, "UniversalString"},
    {"1c020041", NQEDEC, "UniversalString not a multiple of 4"},
    {"1c0400110000", NQEDEC, "UniversalString above U+10FFFF"},
    {"1401ff", NQOK, "T61String any octet"},
    /* SET OF order (X.690 11.6) */
    {"3106020101020102", NQOK, "SET OF in order"},
    {"3106020102020101", NQEDEC, "SET OF out of order"},
    {"3106020101020101", NQOK, "SET OF equal elements"},
    {"3107020101" "02020100", NQOK, "SET OF shorter first"},
    {"3107020201000201" "01", NQEDEC, "SET OF longer first"},
    {"a006020102020101", NQOK, "[0] IMPLICIT SET: no order rule"},
};

/* nqdtime cases: contents, tag (23 UTC, 24 GT), flags, want, seconds */
typedef struct {
  const char *s;
  uint32_t tag;
  unsigned flags;
  int want;
  int64_t secs;
  uint32_t ns;
} tvec;

static const tvec times[] = {
    {"700101000000Z", NQDUTC, 0, NQOK, 0, 0},
    {"491231235959Z", NQDUTC, 0, NQOK, 2524607999, 0},
    {"500101000000Z", NQDUTC, 0, NQOK, -631152000, 0},
    {"20380119031408Z", NQDGEN, NQDT5280, NQELIM, 0, 0}, /* GT < 2050 */
    {"20380119031408Z", NQDGEN, 0, NQOK, 2147483648, 0},
    {"20500101000000Z", NQDGEN, NQDT5280, NQOK, 2524608000, 0},
    {"99991231235959Z", NQDGEN, 0, NQOK, 253402300799, 0},
    {"260101000000Z", NQDUTC, NQDT5280, NQOK, 1767225600, 0},
    {"2601010000Z", NQDUTC, 0, NQEDEC, 0, 0},
    {"260101000000", NQDUTC, 0, NQEDEC, 0, 0},
    {"260101000000+0000", NQDUTC, 0, NQEDEC, 0, 0},
    {"260101000000z", NQDUTC, 0, NQEDEC, 0, 0},
    {"261301000000Z", NQDUTC, 0, NQEDEC, 0, 0},
    {"260001000000Z", NQDUTC, 0, NQEDEC, 0, 0},
    {"260100000000Z", NQDUTC, 0, NQEDEC, 0, 0},
    {"260132000000Z", NQDUTC, 0, NQEDEC, 0, 0},
    {"250229000000Z", NQDUTC, 0, NQEDEC, 0, 0},
    {"240229000000Z", NQDUTC, 0, NQOK, 1709164800, 0},
    {"21000229000000Z", NQDGEN, 0, NQEDEC, 0, 0},
    {"20000229000000Z", NQDGEN, 0, NQOK, 951782400, 0},
    {"260430000000Z", NQDUTC, 0, NQOK, 1777507200, 0},
    {"260431000000Z", NQDUTC, 0, NQEDEC, 0, 0},
    {"260101240000Z", NQDUTC, 0, NQEDEC, 0, 0},
    {"260101006000Z", NQDUTC, 0, NQEDEC, 0, 0},
    {"260101000060Z", NQDUTC, 0, NQEDEC, 0, 0},
    {"2601010000 0Z", NQDUTC, 0, NQEDEC, 0, 0},
    {"26010100000aZ", NQDUTC, 0, NQEDEC, 0, 0},
    {"-60101000000Z", NQDUTC, 0, NQEDEC, 0, 0},
    {"20261028194138Z", NQDGEN, NQDTFRAC, NQOK, 1793216498, 0},
    {"20261028194138.5Z", NQDGEN, NQDTFRAC, NQOK, 1793216498, 500000000},
    {"20261028194138.123456789Z", NQDGEN, NQDTFRAC, NQOK, 1793216498,
     123456789},
    {"20261028194138.1234567891Z", NQDGEN, NQDTFRAC, NQEDEC, 0, 0},
    {"20261028194138.5Z", NQDGEN, 0, NQEDEC, 0, 0},
    {"20261028194138.50Z", NQDGEN, NQDTFRAC, NQEDEC, 0, 0},
    {"20261028194138.Z", NQDGEN, NQDTFRAC, NQEDEC, 0, 0},
    {"20261028194138,5Z", NQDGEN, NQDTFRAC, NQEDEC, 0, 0},
    {"20261028194138.5", NQDGEN, NQDTFRAC, NQEDEC, 0, 0},
    {"202610281941Z", NQDGEN, NQDTFRAC, NQEDEC, 0, 0},
    {"2026102819Z", NQDGEN, NQDTFRAC, NQEDEC, 0, 0},
    {"00000101000000Z", NQDGEN, 0, NQEDEC, 0, 0},
    {"20261028194138Z", NQDUTC, 0, NQEDEC, 0, 0},
    {"261028194138Z", NQDGEN, 0, NQEDEC, 0, 0},
};

static size_t unhex(const char *h, uint8_t *out, size_t cap) {
  size_t n = 0;
  if (nqunhex(h, strlen(h), out, cap, &n) != NQOK) {
    return (size_t)-1;
  }
  return n;
}

static void trules(void) {
  uint8_t b[512];
  size_t i;
  for (i = 0; i < sizeof rules / sizeof rules[0]; i++) {
    size_t n = unhex(rules[i].hex, b, sizeof b);
    int r;
    if (n == (size_t)-1) {
      /* the deliberately odd hex row */
      NQTCHK(strlen(rules[i].hex) % 2 == 1);
      continue;
    }
    r = nqdone(n ? b : (const uint8_t *)"", n, NULL);
    if (r != rules[i].want) {
      fprintf(stderr, "rule \"%s\": %d, expected %d\n", rules[i].why, r,
              rules[i].want);
    }
    NQTEQI(r, rules[i].want);
  }
  /* the long form starts at 128 */
  memset(b, 0, sizeof b);
  b[0] = 0x04;
  b[1] = 0x81;
  b[2] = 0x80;
  NQTEQI(nqdone(b, 3 + 128, NULL), NQOK);
  NQTEQI(nqdone(b, 3 + 127, NULL), NQEDEC);
  NQTEQI(nqdone(b, 3 + 129, NULL), NQEDEC);
  b[1] = 0x82;
  b[2] = 0x01;
  b[3] = 0x00;
  NQTEQI(nqdone(b, 4 + 256, NULL), NQOK);
}

static void ttimes(void) {
  size_t i;
  for (i = 0; i < sizeof times / sizeof times[0]; i++) {
    nqdtlv t;
    int64_t s = -1;
    uint32_t ns = 7;
    int r, want = times[i].want == NQELIM ? NQEDEC : times[i].want;
    memset(&t, 0, sizeof t);
    t.cls = NQDUNI;
    t.tag = times[i].tag;
    t.v.p = (const uint8_t *)times[i].s;
    t.v.n = strlen(times[i].s);
    r = nqdtime(&t, times[i].flags, &s, &ns);
    if (r != want) {
      fprintf(stderr, "time %s: %d, expected %d\n", times[i].s, r, want);
    }
    NQTEQI(r, want);
    if (want == NQOK) {
      NQTEQI(s, times[i].secs);
      NQTEQI(ns, times[i].ns);
    }
    /* the tree check accepts exactly the DER forms (fraction allowed in
     * GeneralizedTime, no RFC 5280 profile) */
    if (times[i].flags == 0 || times[i].flags == NQDTFRAC) {
      int pr = nqdprim(times[i].tag, t.v.p, t.v.n);
      int pw = times[i].want;
      if (times[i].flags == 0 && pw != NQOK &&
          nqdtime(&t, NQDTFRAC, NULL, NULL) == NQOK) {
        pw = NQOK; /* rejected only for its fraction */
      }
      NQTEQI(pr, pw);
    }
  }
  /* a UTCTime is not a GeneralizedTime and the other way round */
  {
    nqdtlv t;
    memset(&t, 0, sizeof t);
    t.cls = NQDUNI;
    t.tag = NQDOCT;
    t.v.p = (const uint8_t *)"700101000000Z";
    t.v.n = 13;
    NQTEQI(nqdtime(&t, 0, NULL, NULL), NQEDEC);
    t.tag = NQDUTC;
    t.cls = NQDCTX;
    NQTEQI(nqdtime(&t, 0, NULL, NULL), NQEDEC);
  }
}

/* n nested SEQUENCEs around a NULL */
static size_t nest(uint8_t *b, size_t cap, unsigned n) {
  size_t len = 2, i;
  if (2u * n + 2 > cap || n > 60) {
    return 0;
  }
  for (i = 0; i < n; i++) {
    b[i * 2] = 0x30;
    b[i * 2 + 1] = (uint8_t)(2 * (n - i));
  }
  b[2 * n] = 0x05;
  b[2 * n + 1] = 0x00;
  len = 2u * n + 2;
  return len;
}

static void tdepth(void) {
  uint8_t b[256];
  size_t n;
  nqdtlv t;
  nqdcur c, in;
  unsigned d;
  int r;
  /* 32 nested constructed elements: the limit */
  n = nest(b, sizeof b, NQDDEPTH);
  NQTEQI(nqdone(b, n, NULL), NQOK);
  n = nest(b, sizeof b, NQDDEPTH + 1);
  NQTEQI(nqdone(b, n, NULL), NQELIM);
  n = nest(b, sizeof b, 60);
  NQTEQI(nqdone(b, n, NULL), NQELIM);
  /* the cursor keeps the same limit */
  n = nest(b, sizeof b, NQDDEPTH + 1);
  nqdinit(&c, b, n);
  r = nqdnext(&c, &t);
  for (d = 0; r == NQOK && t.con; d++) {
    r = nqddown(&t, &in);
    if (r != NQOK) {
      break;
    }
    r = nqdnext(&in, &t);
  }
  NQTEQI(r, NQELIM);
  NQTEQI(d, NQDDEPTH);
  n = nest(b, sizeof b, NQDDEPTH);
  nqdinit(&c, b, n);
  r = nqdnext(&c, &t);
  for (d = 0; r == NQOK && t.con; d++) {
    r = nqddown(&t, &in);
    if (r == NQOK) {
      r = nqdnext(&in, &t);
    }
  }
  NQTEQI(r, NQOK);
  NQTEQI(t.tag, NQDNULL);
  NQTEQI(t.depth, NQDDEPTH);
}

static void thelpers(void) {
  uint8_t b[64];
  size_t n;
  nqdtlv t;
  nqspan s;
  int64_t v;
  int neg, x;
  uint32_t bits;
  unsigned u;
  struct {
    const char *hex;
    int r;
    int64_t v;
  } ints[] = {
      {"020100", NQOK, 0},
      {"02017f", NQOK, 127},
      {"020180", NQOK, -128},
      {"02020080", NQOK, 128},
      {"0202ff7f", NQOK, -129},
      {"02087fffffffffffffff", NQOK, INT64_MAX},
      {"02088000000000000000", NQOK, INT64_MIN},
      {"0209008000000000000000", NQELIM, 0},
      {"0202007f", NQEDEC, 0},
      {"0a0101", NQEDEC, 0},
  };
  size_t i;
  for (i = 0; i < sizeof ints / sizeof ints[0]; i++) {
    n = unhex(ints[i].hex, b, sizeof b);
    NQTEQI(nqdhdr(b, n, &t), NQOK);
    v = 99;
    NQTEQI(nqdi64(&t, &v), ints[i].r);
    if (ints[i].r == NQOK) {
      NQTEQI(v == ints[i].v, 1);
    }
  }
  /* magnitude and sign */
  n = unhex("020300ff01", b, sizeof b);
  nqdhdr(b, n, &t);
  NQTEQI(nqdint(&t, &s, &neg), NQOK);
  NQTEQI(neg, 0);
  NQTEQI(s.n, 2);
  NQTEQI(s.p[0], 0xff);
  n = unhex("0201ff", b, sizeof b);
  nqdhdr(b, n, &t);
  NQTEQI(nqdint(&t, &s, &neg), NQOK);
  NQTEQI(neg, 1);
  n = unhex("0a0105", b, sizeof b);
  nqdhdr(b, n, &t);
  NQTEQI(nqdenum(&t, &v), NQOK);
  NQTEQI(v, 5);
  NQTEQI(nqdi64(&t, &v), NQEDEC); /* ENUMERATED is not INTEGER */
  /* BOOLEAN */
  n = unhex("0101ff", b, sizeof b);
  nqdhdr(b, n, &t);
  NQTEQI(nqdbool(&t, &x), NQOK);
  NQTEQI(x, 1);
  n = unhex("0101fe", b, sizeof b);
  nqdhdr(b, n, &t);
  NQTEQI(nqdbool(&t, &x), NQEDEC);
  n = unhex("8101ff", b, sizeof b);
  nqdhdr(b, n, &t);
  NQTEQI(nqdbool(&t, &x), NQEDEC); /* tagged: not a universal BOOLEAN */
  /* NULL */
  n = unhex("0500", b, sizeof b);
  nqdhdr(b, n, &t);
  NQTEQI(nqdnull(&t), NQOK);
  /* OID */
  n = unhex("0603551d13", b, sizeof b);
  nqdhdr(b, n, &t);
  NQTEQI(nqdoid(&t, &s), NQOK);
  NQTEQI(nqdoideq(&t, (const uint8_t *)"\x55\x1d\x13", 3), 1);
  NQTEQI(nqdoideq(&t, (const uint8_t *)"\x55\x1d\x14", 3), 0);
  NQTEQI(nqdoideq(&t, (const uint8_t *)"\x55\x1d", 2), 0);
  /* bit strings */
  n = unhex("03020780", b, sizeof b);
  nqdhdr(b, n, &t);
  NQTEQI(nqdbits(&t, &s, &u), NQOK);
  NQTEQI(u, 7);
  NQTEQI(nqdbit0(&t, &s), NQEDEC);
  NQTEQI(nqdnbits(&t, &bits), NQOK);
  NQTEQI(bits, 1);
  n = unhex("030205a0", b, sizeof b); /* bits 0 and 2 */
  nqdhdr(b, n, &t);
  NQTEQI(nqdnbits(&t, &bits), NQOK);
  NQTEQI(bits, 5);
  n = unhex("030204a0", b, sizeof b); /* a trailing zero bit */
  nqdhdr(b, n, &t);
  NQTEQI(nqdbits(&t, &s, &u), NQOK);
  NQTEQI(nqdnbits(&t, &bits), NQEDEC);
  n = unhex("03030701 80", b, sizeof b);
  NQTCHK(n == (size_t)-1);
  n = unhex("0303070180", b, sizeof b); /* keyCertSign... bit 8 */
  nqdhdr(b, n, &t);
  NQTEQI(nqdnbits(&t, &bits), NQOK);
  NQTEQI(bits, 0x100 | 0x80);
  n = unhex("0306000102030405", b, sizeof b); /* 40 bits */
  nqdhdr(b, n, &t);
  NQTEQI(nqdnbits(&t, &bits), NQELIM);
  n = unhex("030100", b, sizeof b);
  nqdhdr(b, n, &t);
  NQTEQI(nqdnbits(&t, &bits), NQOK);
  NQTEQI(bits, 0);
  NQTEQI(nqdbit0(&t, &s), NQOK);
  NQTEQI(s.n, 0);
}

static void tcursor(void) {
  /* SEQUENCE { INTEGER 1, [0] { NULL }, OCTET STRING } */
  uint8_t b[64];
  size_t n = unhex("300c020101a00205000403616263", b, sizeof b);
  nqdtlv t, x;
  nqdcur c, in, in2;
  int got;
  NQTEQI(nqdone(b, n, &t), NQOK);
  NQTEQI(nqddown(&t, &c), NQOK);
  NQTEQI(nqdopt(&c, NQDUNI, 0, NQDBOOL, &x, &got), NQOK);
  NQTEQI(got, 0);
  NQTEQI(nqdget(&c, NQDUNI, 0, NQDOCT, &x), NQEDEC); /* not consumed */
  NQTEQI(nqdget(&c, NQDUNI, 0, NQDINT, &x), NQOK);
  NQTEQI(nqdopt(&c, NQDCTX, 1, 0, &x, &got), NQOK);
  NQTEQI(got, 1);
  NQTEQI(nqddown(&x, &in), NQOK);
  NQTEQI(nqdget(&in, NQDUNI, 0, NQDNULL, &x), NQOK);
  NQTEQI(nqddone(&in), NQOK);
  NQTEQI(nqdend(&in), 1);
  NQTEQI(nqdnext(&in, &x), NQEDEC);
  NQTEQI(nqddone(&c), NQEDEC);
  NQTEQI(nqdpeek(&c, &x), NQOK);
  NQTEQI(x.tag, NQDOCT);
  NQTEQI(nqddown(&x, &in2), NQEDEC); /* primitive */
  NQTEQI(nqdnext(&c, &x), NQOK);
  NQTEQI(x.v.n, 3);
  NQTEQI(nqddone(&c), NQOK);
  NQTEQI(nqdopt(&c, NQDUNI, 0, NQDINT, &x, &got), NQOK);
  NQTEQI(got, 0);
  /* a cursor over a SEQUENCE that holds a bad child reports it */
  n = unhex("3004020000aa", b, sizeof b);
  NQTEQI(nqdone(b, n, NULL), NQEDEC);
  n = unhex("30020200", b, sizeof b);
  NQTEQI(nqdhdr(b, n, &t), NQOK);
  NQTEQI(nqddown(&t, &c), NQOK);
  NQTEQI(nqdnext(&c, &x), NQOK); /* headers only: contents unchecked */
  NQTEQI(nqdwalk(b, n), NQEDEC);
  /* NULL buffers */
  NQTEQI(nqdone(NULL, 0, NULL), NQEDEC);
  NQTEQI(nqdwalk(NULL, 0), NQEDEC);
  NQTEQI(nqdhdr(NULL, 4, &t), NQEDEC);
}

/* Every prefix and every single-byte change of a valid structure either
 * parses or fails cleanly, and none reads out of bounds (ASan). */
static void tbounds(void) {
  uint8_t b[64], m[64];
  size_t n = unhex("3017020101a00b30090603551d130402300001"
                   "01ff0402abcd",
                   b, sizeof b), i, k;
  unsigned ok = 0, bad = 0;
  NQTCHK(n != (size_t)-1);
  for (i = 0; i <= n; i++) {
    int r;
    memcpy(m, b, i);
    r = nqdone(m, i, NULL);
    NQTCHK(r == NQOK || r == NQEDEC || r == NQELIM);
  }
  for (i = 0; i < n; i++) {
    for (k = 0; k < 256; k++) {
      int r;
      memcpy(m, b, n);
      m[i] = (uint8_t)k;
      r = nqdone(m, n, NULL);
      NQTCHK(r == NQOK || r == NQEDEC || r == NQELIM);
      if (r == NQOK) {
        ok++;
      } else {
        bad++;
      }
    }
  }
  NQTCHK(ok > 0 && bad > 0);
}

int main(void) {
  trules();
  ttimes();
  tdepth();
  thelpers();
  tcursor();
  tbounds();
  return nqtdone("tder");
}
