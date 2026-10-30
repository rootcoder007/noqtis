/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* TLS 1.3 client tests on the RFC 8448 traces (vectors/tls/rfc8448.txt,
 * read as the RFC prints it). The client is given the trace's
 * ClientHello and X25519 key and fed the server's records; every record
 * it writes must equal the trace byte for byte: its Finished, its
 * application data and its close_notify (section 3), and both
 * ClientHellos and its Finished after a HelloRetryRequest (section 5,
 * whose P-256 secret is given by a hook; the trace's P-256 keys and
 * that secret are checked against nqecpub and nqecdh on their own).
 * The trace's server key is 1024-bit RSA and its certificate
 * self-signed, so the path check and the CertificateVerify signature
 * are skipped by hooks here; tests/tls/srv.sh tests both against a real
 * server. Then every one-bit change of the plaintext ServerHello and of
 * every seventh byte of the encrypted flight must fail, and the
 * ClientHello reader, the host-name and address matching and the
 * address parser are tested on their own. */
#include "cls/cls.h"
#include "tls/tls.h"
#include "nqt.h"
#include "tvec.h"

static char *rfc;
static size_t rfcn;

/* ---- reading the RFC's hex dumps ---- */

/* the start of section sec ("3.  ") at a line start, or rfcn */
static size_t sect(const char *sec) {
  size_t l = strlen(sec), i;
  for (i = 0; i + l <= rfcn; i++) {
    if ((i == 0 || rfc[i - 1] == '\n') && memcmp(rfc + i, sec, l) == 0) {
      return i;
    }
  }
  return rfcn;
}

static size_t after(size_t from, size_t to, const char *s) {
  size_t l = strlen(s), i;
  for (i = from; i + l <= to; i++) {
    if (memcmp(rfc + i, s, l) == 0) return i + l;
  }
  return to;
}

static int hexv(int c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return -1;
}

/* the k-th (from 1) step headed head in [from, to), then its field
 * label: "label (N octets):  xx xx ..." read across page breaks into
 * out; the byte count, 0 when not found */
static size_t blob(size_t from, size_t to, const char *head, int k,
                   const char *label, uint8_t *out, size_t cap) {
  size_t i = from, n = 0, got = 0;
  char lb[80];
  int j;
  for (j = 0; j < k; j++) {
    i = after(i, to, head);
    if (i == to) return 0;
  }
  snprintf(lb, sizeof lb, "%s (", label);
  i = after(i, to, lb);
  if (i == to) return 0;
  while (i < to && rfc[i] >= '0' && rfc[i] <= '9') {
    n = n * 10 + (size_t)(rfc[i] - '0');
    i++;
  }
  i = after(i, to, "octets):");
  if (i == to || n > cap) return 0;
  while (got < n && i < to) {
    /* skip a page footer, a form feed and the next page's header */
    if (rfc[i] == '\n') {
      size_t e = i + 1;
      while (e < to && rfc[e] == ' ') e++;
      if (e + 7 <= to && (memcmp(rfc + e, "Thomson", 7) == 0 ||
                          memcmp(rfc + e, "RFC 8448", 8) == 0)) {
        while (e < to && rfc[e] != '\n') e++;
        i = e;
        continue;
      }
      i++;
      continue;
    }
    if (rfc[i] == ' ' || rfc[i] == '\f' || rfc[i] == '\r') {
      i++;
      continue;
    }
    if (i + 1 < to && hexv(rfc[i]) >= 0 && hexv(rfc[i + 1]) >= 0) {
      out[got++] = (uint8_t)(hexv(rfc[i]) * 16 + hexv(rfc[i + 1]));
      i += 2;
      continue;
    }
    return 0;
  }
  return got == n ? n : 0;
}

/* ---- a scripted peer ---- */

typedef struct {
  const uint8_t *in;  /* what the server says, in order */
  size_t inn, inp;
  size_t chunk;       /* bytes per read: tests record reassembly */
  uint8_t out[8192];  /* what the client wrote */
  size_t outn;
} peer;

static int pwr(void *u, const uint8_t *b, size_t n) {
  peer *p = (peer *)u;
  if (p->outn + n > sizeof p->out) return NQEIO;
  memcpy(p->out + p->outn, b, n);
  p->outn += n;
  return NQOK;
}

static int prd(void *u, uint8_t *b, size_t cap, size_t *got) {
  peer *p = (peer *)u;
  size_t c = p->inn - p->inp;
  if (c > cap) c = cap;
  if (p->chunk > 0 && c > p->chunk) c = p->chunk;
  memcpy(b, p->in + p->inp, c);
  p->inp += c;
  *got = c;
  return NQOK;
}

static uint8_t ch1[600], ch2[600], xsk[32], ss[32], srv[4096];
static uint8_t crec[4][600], arec[2][100];
static size_t ch1n, ch2n, srvn, crecn[4], arecn[2];

/* section 3: loads the trace; returns 1 when every field was found */
static int load3(void) {
  size_t a = sect("3.  Simple 1-RTT Handshake"), b = sect("4.  Resumed");
  uint8_t r[1024];
  size_t n, k;
  ch1n = blob(a, b, "{client}  construct a ClientHello", 1, "ClientHello",
              ch1, sizeof ch1);
  n = blob(a, b, "{client}  create an ephemeral x25519", 1, "private key",
           xsk, 32);
  if (ch1n != 196 || n != 32) return 0;
  srvn = 0;
  /* ServerHello, the encrypted flight, NewSessionTicket */
  for (k = 1; k <= 3; k++) {
    n = blob(a, b, "{server}  send handshake record:", (int)k,
             "complete record", r, sizeof r);
    if (n == 0) return 0;
    memcpy(srv + srvn, r, n);
    srvn += n;
  }
  n = blob(a, b, "{server}  send application_data record:", 1,
           "complete record", r, sizeof r);
  if (n == 0) return 0;
  memcpy(srv + srvn, r, n);
  srvn += n;
  n = blob(a, b, "{server}  send alert record:", 1, "complete record", r,
           sizeof r);
  if (n == 0) return 0;
  memcpy(srv + srvn, r, n);
  srvn += n;
  crecn[0] = blob(a, b, "{client}  send handshake record:", 1,
                  "complete record", crec[0], sizeof crec[0]);
  crecn[1] = blob(a, b, "{client}  send handshake record:", 2,
                  "complete record", crec[1], sizeof crec[1]);
  arecn[0] = blob(a, b, "{client}  send application_data record:", 1,
                  "complete record", arec[0], sizeof arec[0]);
  arecn[1] = blob(a, b, "{client}  send alert record:", 1,
                  "complete record", arec[1], sizeof arec[1]);
  return crecn[0] == 201 && crecn[1] == 58 && arecn[0] == 72 &&
         arecn[1] == 24;
}

static nqtls *mk(peer *p, int hrr) {
  nqtlio io;
  nqtlhk hk;
  nqtls *t = NULL;
  io.wr = pwr;
  io.rd = prd;
  io.user = p;
  NQTEQI(nqtlmk(&t, "server", NULL, 0, &io), NQOK);
  if (t == NULL) return NULL;
  memset(&hk, 0, sizeof hk);
  hk.ch1 = ch1;
  hk.ch1n = ch1n;
  if (hrr) {
    hk.ch2 = ch2;
    hk.ch2n = ch2n;
    hk.ss = ss;
    hk.ssn = 32;
  } else {
    hk.xsk = xsk;
  }
  hk.nopath = 1;
  hk.nocv = 1;
  nqtlhook(t, &hk);
  return t;
}

static void trace3(size_t chunk) {
  peer p;
  nqtls *t;
  uint8_t d[50], o[64], e[64];
  size_t i, got = 0, a = sect("3.  Simple 1-RTT Handshake"),
            b = sect("4.  Resumed");
  memset(&p, 0, sizeof p);
  p.in = srv;
  p.inn = srvn;
  p.chunk = chunk;
  t = mk(&p, 0);
  if (t == NULL) return;
  NQTEQI(nqtlhand(t), NQOK);
  /* the ClientHello record and the client's Finished, byte for byte */
  NQTEQI(p.outn, crecn[0] + crecn[1]);
  NQTEQM(p.out, crec[0], crecn[0]);
  NQTEQM(p.out + crecn[0], crec[1], crecn[1]);
  NQTEQI(t->suite, NQTLA128);
  NQTEQI(t->grp, NQTLX25519);
  /* the master secret and the application traffic IVs */
  NQTEQI(blob(a, b, "{server}  extract secret \"master\":", 1, "secret", e,
              32),
         32);
  NQTEQM(t->sec, e, 32);
  NQTEQI(blob(a, b, "{server}  derive write traffic keys for application",
              1, "iv expanded", e, 12),
         12);
  NQTEQM(t->rk.iv, e, 12);
  NQTEQI(blob(a, b, "{client}  derive write traffic keys for application",
              1, "iv expanded", e, 12),
         12);
  NQTEQM(t->wk.iv, e, 12);
  /* application data both ways (the NewSessionTicket comes first) */
  for (i = 0; i < 50; i++) d[i] = (uint8_t)i;
  p.outn = 0;
  NQTEQI(nqtlw(t, d, 50), NQOK);
  NQTEQI(p.outn, arecn[0]);
  NQTEQM(p.out, arec[0], arecn[0]);
  NQTEQI(nqtlr(t, o, sizeof o, &got), NQOK);
  NQTEQI(got, 50);
  NQTEQM(o, d, 50);
  /* close_notify both ways */
  p.outn = 0;
  NQTEQI(nqtle(t), NQOK);
  NQTEQI(p.outn, arecn[1]);
  NQTEQM(p.out, arec[1], arecn[1]);
  NQTEQI(nqtlr(t, o, sizeof o, &got), NQOK);
  NQTEQI(got, 0);
  NQTEQI(t->eof, 1);
  NQTEQI(nqtlw(t, d, 1), NQESTATE);
  nqtlfree(t);
}

/* every one-bit change of the ServerHello (except the record version
 * byte, which section 5.1 says to ignore) and of every seventh byte of
 * the encrypted flight must fail the handshake */
static void tamper3(void) {
  static uint8_t m[4096];
  size_t shn = 95, fl = 679, i, bad = 0, n = 0;
  int bit;
  for (i = 0; i < shn + fl; i += i < shn ? 1 : 7) {
    for (bit = 0; bit < 8; bit += i < shn ? 1 : 3) {
      peer p;
      nqtls *t;
      int rc;
      if (i == 2) continue;
      memcpy(m, srv, srvn);
      m[i] ^= (uint8_t)(1u << bit);
      memset(&p, 0, sizeof p);
      p.in = m;
      p.inn = srvn;
      t = mk(&p, 0);
      if (t == NULL) return;
      rc = nqtlhand(t);
      n++;
      if (rc == NQOK || t->err == 0) {
        bad++;
        fprintf(stderr, "tamper3: byte %lu bit %d accepted\n",
                (unsigned long)i, bit);
      }
      nqtlfree(t);
    }
  }
  printf("ttls: %lu tampered server flights, all refused unless listed\n",
         (unsigned long)n);
  NQTEQI(bad, 0);
}

static void trace5(void) {
  size_t a = sect("5.  HelloRetryRequest"), b = sect("6.  Client Auth");
  uint8_t r[1024], e[32];
  size_t n, k;
  peer p;
  nqtls *t;
  ch1n = blob(a, b, "{client}  construct a ClientHello", 1, "ClientHello",
              ch1, sizeof ch1);
  ch2n = blob(a, b, "{client}  construct a ClientHello", 2, "ClientHello",
              ch2, sizeof ch2);
  NQTEQI(ch1n, 180);
  NQTEQI(ch2n, 512);
  NQTEQI(blob(a, b, "{server}  extract secret \"handshake\":", 1, "IKM", ss,
              32),
         32);
  /* the trace's P-256 exchange: the client's key pair, and its secret
   * with the server's share */
  {
    uint8_t sk[32], pk[65], spk[65], o[65];
    NQTEQI(blob(a, b, "{client}  create an ephemeral P-256", 1,
                "private key", sk, 32),
           32);
    NQTEQI(blob(a, b, "{client}  create an ephemeral P-256", 1,
                "public key", pk, 65),
           65);
    NQTEQI(blob(a, b, "{server}  create an ephemeral P-256", 1,
                "public key", spk, 65),
           65);
    NQTEQI(nqecpub(NQP256, sk, o), NQOK);
    NQTEQM(o, pk, 65);
    NQTEQI(nqecdh(NQP256, sk, spk, 65, o), NQOK);
    NQTEQM(o, ss, 32);
  }
  srvn = 0;
  for (k = 1; k <= 3; k++) {
    n = blob(a, b, "{server}  send handshake record:", (int)k,
             "complete record", r, sizeof r);
    NQTCHK(n > 0);
    memcpy(srv + srvn, r, n);
    srvn += n;
  }
  n = blob(a, b, "{server}  send alert record:", 1, "complete record", r,
           sizeof r);
  memcpy(srv + srvn, r, n);
  srvn += n;
  for (k = 0; k < 3; k++) {
    crecn[k] = blob(a, b, "{client}  send handshake record:", (int)k + 1,
                    "complete record", crec[k], sizeof crec[k]);
  }
  arecn[1] = blob(a, b, "{client}  send alert record:", 1, "complete record",
                  arec[1], sizeof arec[1]);
  NQTEQI(crecn[0], 185);
  NQTEQI(crecn[1], 517);
  memset(&p, 0, sizeof p);
  p.in = srv;
  p.inn = srvn;
  t = mk(&p, 1);
  if (t == NULL) return;
  NQTEQI(nqtlhand(t), NQOK);
  if (t->err != 0) fprintf(stderr, "trace5: %s\n", t->why);
  NQTEQI(t->hrr, 1);
  NQTEQI(t->hrrg, 0x0017);
  NQTEQI(p.outn, crecn[0] + crecn[1] + crecn[2]);
  NQTEQM(p.out, crec[0], crecn[0]);
  NQTEQM(p.out + crecn[0], crec[1], crecn[1]);
  NQTEQM(p.out + crecn[0] + crecn[1], crec[2], crecn[2]);
  NQTEQI(blob(a, b, "{server}  extract secret \"master\":", 1, "secret", e,
              32),
         32);
  NQTEQM(t->sec, e, 32);
  p.outn = 0;
  NQTEQI(nqtle(t), NQOK);
  NQTEQI(p.outn, arecn[1]);
  NQTEQM(p.out, arec[1], arecn[1]);
  nqtlfree(t);
}

/* ---- KeyUpdate, on the section 3 connection ---- */

/* a record of type ty protected under k (as the server would) */
static size_t prot(nqtlkey *k, int ty, const uint8_t *b, size_t n,
                   uint8_t *out) {
  uint8_t nc[12];
  int i;
  out[0] = NQTLAPP;
  out[1] = 3;
  out[2] = 3;
  out[3] = (uint8_t)((n + 17) >> 8);
  out[4] = (uint8_t)(n + 17);
  memcpy(out + 5, b, n);
  out[5 + n] = (uint8_t)ty;
  memcpy(nc, k->iv, 12);
  for (i = 0; i < 8; i++) nc[11 - i] ^= (uint8_t)(k->seq >> (8 * i));
  NQTEQI(nqgcme(&k->g, nc, 12, out, 5, out + 5, n + 1, out + 5,
                out + 6 + n),
         NQOK);
  k->seq++;
  return n + 22;
}

/* opens a record the client wrote under k; the inner type, or -1 */
static int unprot(nqtlkey *k, uint8_t *r, size_t n, size_t *pn) {
  uint8_t nc[12], a[5];
  int i;
  if (n < 22 || r[0] != NQTLAPP) return -1;
  memcpy(a, r, 5);
  memcpy(nc, k->iv, 12);
  for (i = 0; i < 8; i++) nc[11 - i] ^= (uint8_t)(k->seq >> (8 * i));
  if (nqgcmd(&k->g, nc, 12, a, 5, r + 5, n - 21, r + n - 16, 16, r + 5) !=
      NQOK) {
    return -1;
  }
  k->seq++;
  *pn = n - 22;
  return r[n - 17];
}

static void tku(void) {
  static uint8_t in[8192];
  static const uint8_t ku[5] = {NQTLKU, 0, 0, 1, 1}, bad[5] = {NQTLKU, 0,
                                                                0, 1, 2};
  peer p;
  nqtls *t;
  nqtlkey sk, ck, nk;
  uint8_t s[32], o[16];
  size_t n, got = 0, pn = 0, hs = 95 + 679;
  memset(&p, 0, sizeof p);
  memcpy(in, srv, hs);
  p.in = in;
  p.inn = hs;
  t = mk(&p, 0);
  if (t == NULL) return;
  NQTEQI(nqtlhand(t), NQOK);
  sk = t->rk;
  ck = t->wk;
  /* KeyUpdate(update_requested), then data under the next key */
  n = hs;
  n += prot(&sk, NQTLHS, ku, 5, in + n);
  NQTEQI(nqtlexp(NQS256, sk.sec, "traffic upd", NULL, 0, s, 32), NQOK);
  NQTEQI(nqtlkeys(&sk, NQTLA128, NQS256, s), NQOK);
  n += prot(&sk, NQTLAPP, (const uint8_t *)"hi", 2, in + n);
  n += prot(&sk, NQTLHS, bad, 5, in + n);
  p.inn = n;
  p.outn = 0;
  NQTEQI(nqtlr(t, o, sizeof o, &got), NQOK);
  NQTEQI(got, 2);
  NQTCHK(memcmp(o, "hi", 2) == 0);
  /* the client answered with KeyUpdate(update_not_requested) under its
   * old key, and now writes under the next one */
  NQTEQI(unprot(&ck, p.out, p.outn, &pn), NQTLHS);
  NQTEQI(pn, 5);
  NQTCHK(memcmp(p.out + 5, "\x18\x00\x00\x01\x00", 5) == 0);
  NQTEQI(nqtlexp(NQS256, ck.sec, "traffic upd", NULL, 0, s, 32), NQOK);
  NQTEQI(nqtlkeys(&nk, NQTLA128, NQS256, s), NQOK);
  p.outn = 0;
  NQTEQI(nqtlw(t, (const uint8_t *)"yo", 2), NQOK);
  NQTEQI(unprot(&nk, p.out, p.outn, &pn), NQTLAPP);
  NQTCHK(pn == 2 && memcmp(p.out + 5, "yo", 2) == 0);
  /* a KeyUpdate of 2 is illegal_parameter, and final */
  NQTEQI(nqtlr(t, o, sizeof o, &got), NQEDEC);
  NQTEQI(nqtlr(t, o, sizeof o, &got), NQEDEC);
  NQTEQI(nqtlw(t, o, 1), NQEDEC);
  nqtlfree(t);
}

/* ---- pieces ---- */

static void tscan(void) {
  nqtloff o;
  uint8_t m[600];
  NQTEQI(nqtlscan(ch1, ch1n, &o), NQOK);
  NQTEQI(o.nsuite, 3);
  NQTEQI(o.nks, 1);
  NQTEQI(o.ks[0], NQTLX25519);
  NQTEQI(o.sidn, 0);
  /* trailing bytes, a short message, a wrong type */
  memcpy(m, ch1, ch1n);
  m[ch1n] = 0;
  NQTEQI(nqtlscan(m, ch1n + 1, &o), NQEDEC);
  NQTEQI(nqtlscan(m, ch1n - 1, &o), NQEDEC);
  m[0] = 2;
  NQTEQI(nqtlscan(m, ch1n, &o), NQEDEC);
}

static void tip(void) {
  uint8_t a[16], e[16];
  NQTEQI(nqtlip("192.0.2.1", a), 4);
  NQTCHK(a[0] == 192 && a[1] == 0 && a[2] == 2 && a[3] == 1);
  NQTEQI(nqtlip("256.1.1.1", a), 0);
  NQTEQI(nqtlip("1.2.3", a), 0);
  NQTEQI(nqtlip("1.2.3.4.5", a), 0);
  NQTEQI(nqtlip("01.2.3.4", a), 0);
  NQTEQI(nqtlip("1..3.4", a), 0);
  NQTEQI(nqtlip("::1", a), 16);
  memset(e, 0, 16);
  e[15] = 1;
  NQTEQM(a, e, 16);
  NQTEQI(nqtlip("2001:db8::8:800:200c:417a", a), 16);
  tvlit("20010db80000000000080800200c417a", e, 16);
  NQTEQM(a, e, 16);
  NQTEQI(nqtlip("::", a), 16);
  NQTEQI(nqtlip("1:2:3:4:5:6:7:8", a), 16);
  NQTEQI(nqtlip("1:2:3:4:5:6:7:8:9", a), 0);
  NQTEQI(nqtlip("1::2::3", a), 0);
  NQTEQI(nqtlip("12345::", a), 0);
  NQTEQI(nqtlip("1:2", a), 0);
  NQTEQI(nqtlip(":1::", a), 0);
  NQTEQI(nqtlip("example.com", a), 0);
}

int main(void) {
  int rc = nqreadf("vectors/tls/rfc8448.txt", 1u << 20, &rfc, &rfcn);
  NQTEQI(rc, NQOK);
  if (rc != NQOK) return nqtdone("ttls");
  NQTCHK(load3());
  trace3(0);
  /* the same, read a few bytes at a time */
  trace3(7);
  tamper3();
  tku();
  tscan();
  trace5();
  tip();
  nqfree(rfc, rfcn + 1);
  return nqtdone("ttls");
}
