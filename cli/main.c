/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* noqtis: entry point, help, option parsing, version and algs. */
#include "cli.h"

#include <errno.h>

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#ifdef _MSC_VER
#include <crtdbg.h>
#endif
#include <shellapi.h>
#endif

/* the URLs --tsa takes */
#ifdef NQTLSON
#define NCTSAU "http:// or https://"
#else
#define NCTSAU "http:// only"
#endif

typedef struct {
  const char *name;
  int (*run)(int argc, char **argv);
  const char *brief;
  const char *use;
} nccmd;

static int ncver(int argc, char **argv);
static int ncalgs(int argc, char **argv);
static int ncself(int argc, char **argv);
static int nchelp(int argc, char **argv);

static const nccmd cmds[] = {
  {"keygen", nckeygen, "make a key pair",
   "usage: noqtis keygen -a <alg> -o <key> [--seed <hex|file>]\n"
   "                     [--pass-fd <n> | --pass-env <name>\n"
   "                      [--kdf argon2id|pbkdf2]] [--force]\n"
   "  Writes the secret key to <key> (owner-only) and the public key to\n"
   "  <key>.pub. <alg> is a signature or KEM name from `noqtis algs`.\n"
   "  --seed  deterministic key generation from the standard's seed\n"
   "          (hex digits, or a file holding the raw seed bytes)\n"
   "  --pass-fd, --pass-env  keep the secret key under a passphrase\n"
   "          (Argon2id, 64 MiB, 3 passes), read from descriptor <n> up\n"
   "          to a newline, or from the variable named <name>; never\n"
   "          from the command line\n"
   "  --kdf   how the passphrase becomes the key's key: argon2id (the\n"
   "          default) or pbkdf2 (PBKDF2-HMAC-SHA-256, 600000 iterations,\n"
   "          for places whose rules ask for it); reading needs nothing\n"
   "  --force replace existing files\n"},
  {"passwd", ncpasswd, "change or remove a secret key's passphrase",
   "usage: noqtis passwd -k <key> [--pass-fd <n> | --pass-env <name>]\n"
   "                     (--new-pass-fd <n> | --new-pass-env <name> |\n"
   "                      --no-pass) [--kdf argon2id|pbkdf2]\n"
   "  Writes the secret key in <key> again, under the new passphrase\n"
   "  (Argon2id, 64 MiB, 3 passes, or PBKDF2-HMAC-SHA-256, 600000\n"
   "  iterations: the one <key> is under now unless --kdf names one,\n"
   "  Argon2id for a key under none) or, with --no-pass, under none, and\n"
   "  says which KDF protects it. The key itself and <key>.pub do not\n"
   "  change.\n"
   "  --pass-fd, --pass-env  the passphrase <key> is under now\n"
   "  --new-pass-fd, --new-pass-env  the new one, read from descriptor\n"
   "          <n> up to a newline, or from the variable named <name>;\n"
   "          never from the command line\n"
   "  --kdf   how the new passphrase becomes the key's key: argon2id\n"
   "          (64 MiB, 3 passes) or pbkdf2, as for keygen; without it\n"
   "          the file keeps the KDF it was under, and a key under none\n"
   "          gets argon2id\n"},
  {"sign", ncsign, "sign a file",
   "usage: noqtis sign -k <key> [-o <sig>] [-a] [-c <ctx>] [-d]\n"
   "                   [--ph <hash>] [--pass-fd <n> | --pass-env <name>]\n"
   "                   [--force] <file>\n"
   "  Writes the raw signature to <sig> (default <file>.sig); <file> may\n"
   "  be - for stdin (then -o is required).\n"
   "  -a      write it as text (--armor): -----BEGIN NOQTIS SIGNATURE-----\n"
   "          and base64, which verify reads as well\n"
   "  --pass-fd, --pass-env  the passphrase of a protected key\n"
   "  -c      context string (at most 255 bytes)\n"
   "  -d      deterministic signature (no per-signature randomness)\n"
   "  --ph    pre-hash variant (HashML-DSA, HashSLH-DSA) with <hash>\n"},
  {"verify", ncvrfy, "check a signature",
   "usage: noqtis verify -p <key.pub> -s <sig> [-c <ctx>] [--ph <hash>]\n"
   "                     [-q] <file>\n"
   "       noqtis verify -p <key.pub> --dsse [-o <payload>] [-q] <env>\n"
   "  Exit 0 when the signature is valid, 1 when it is not, 2 on a usage\n"
   "  or file error. <sig> is the raw signature or an armored one (sign\n"
   "  -a). --dsse checks a DSSE envelope (from `noqtis export --as\n"
   "  dsse`); -o writes its payload.\n"},
  {"enc", ncenc, "encapsulate a shared secret (KEM)",
   "usage: noqtis enc -p <key.pub> -o <ct> [--force] (<ss> | --stdout)\n"
   "  Writes the ciphertext to <ct> and the shared secret to <ss>\n"
   "  (owner-only). --stdout prints the secret in hex instead.\n"},
  {"dec", ncdec, "decapsulate a shared secret (KEM)",
   "usage: noqtis dec -k <key> (-o <ss> | --stdout)\n"
   "                  [--pass-fd <n> | --pass-env <name>] [--force] <ct>\n"
   "  Writes the shared secret to <ss> (owner-only), or prints it in hex\n"
   "  with --stdout. A tampered ciphertext gives an unrelated secret\n"
   "  (implicit rejection), not an error. --pass-fd and --pass-env give\n"
   "  the passphrase of a protected key.\n"},
  {"box", ncbox, "seal a file to ML-KEM keys, in chunks",
   "usage: noqtis box -p <key.pub> [-p <key.pub> ...] -o <out> [-c <ctx>]\n"
   "                  [-s <key> [--pass-fd <n> | --pass-env <name>]]\n"
   "                  [-a] [--chunk <bytes>] [--force] <file>\n"
   "  Encrypts <file> (- for stdin) to the ML-KEM key in <key.pub> as\n"
   "  noqtis-kstream-1 and writes it to <out> (- for stdout), one chunk\n"
   "  at a time (64 KiB, or 1024 to 16777216 bytes with --chunk).\n"
   "  -p      given more than once (up to 32): any one of the keys opens\n"
   "          it (noqtis-kstream-2)\n"
   "  -s      sign it with the secret signature key <key> (--sign): the\n"
   "          signature is inside the encryption and names the\n"
   "          recipients (noqtis-kstream-2); --pass-fd and --pass-env\n"
   "          give the passphrase of a protected <key>\n"
   "  -a      write the stream as text (--armor): -----BEGIN NOQTIS\n"
   "          SEALED STREAM----- and base64, a third longer; unbox reads\n"
   "          it as well\n"
   "  -c      context string, needed again to unbox (at most 255 bytes)\n"
   "  --force replace an existing <out>\n"},
  {"unbox", ncunbox, "open a file sealed with noqtis box",
   "usage: noqtis unbox -k <key> -o <out> [-c <ctx>]\n"
   "                    [-s <sender.pub> | --any-sender]\n"
   "                    [--pass-fd <n> | --pass-env <name>] [--force] <file>\n"
   "  Decrypts <file> (- for stdin) to <out> (owner-only; - for stdout),\n"
   "  writing each chunk only once it verifies. When one does not, exit 2\n"
   "  and <out> is removed. <file> is the stream or an armored one (box\n"
   "  -a).\n"
   "  -s      the sender's public signature key (--sender): a signed\n"
   "          stream must verify under it, and one that is not signed\n"
   "          is refused\n"
   "  --any-sender  open a signed stream without checking who sent it\n"
   "  --pass-fd, --pass-env  the passphrase of a protected <key>\n"},
  {"keys", nckeys, "the key store: other people's keys by name",
   "usage: noqtis keys [--store <dir>] list [<name>]\n"
   "       noqtis keys find <name>\n"
   "       noqtis keys add (-n <name> [-e <email>] | --card <file>)\n"
   "                       <key.pub>\n"
   "       noqtis keys certify -k <key> [--pass-fd <n> | --pass-env <name>]\n"
   "                           [-o <cert>] [--force] <name>\n"
   "       noqtis keys addcert <cert>\n"
   "       noqtis keys trust <name> <level>\n"
   "       noqtis keys export [-o <key.pub>] [--force] <name>\n"
   "       noqtis keys bundle [-o <file>] [--force] <name>\n"
   "       noqtis keys import <file>\n"
   "       noqtis keys fetch [--url] <email>\n"
   "       noqtis keys rm <name>\n"
   "       noqtis keys path\n"
   "  The key store holds public keys by their holders' names. <name> is\n"
   "  part of a name or address, or the start of a fingerprint (8 hex\n"
   "  digits or more); list shows every key it answers, the others need\n"
   "  exactly one. Each line: fingerprint, algorithm, trust, validity,\n"
   "  certifications, name.\n"
   "  add      put a key in, under a name or with its identity card\n"
   "  certify  sign, with <key>, that the key belongs to its name\n"
   "  addcert  put in a certification someone else made\n"
   "  trust    how far the key's holder is trusted to certify: unknown,\n"
   "           never, marginal, full, or ultimate for your own keys\n"
   "  find     as list; exit 1 when no key answers\n"
   "  bundle   write a key with its card, and the keys it certified as\n"
   "           its own, as text to publish or send\n"
   "  import   put the keys of such a bundle in; they are not valid\n"
   "           until certified\n"
   "  fetch    look <email> up at its domain, over https, and import\n"
   "           what is there: https://<domain>/.well-known/noqtis/<hash\n"
   "           of the name>; --url prints that address and fetches nothing\n"
   "  A key is valid when one valid key trusted fully certified it, or\n"
   "  three trusted marginally. Elsewhere, -p @<name> takes a valid key\n"
   "  of the store in place of a key file.\n"
   "  --store  the folder (default: $NOQTIS_KEYS, else noqtis/keys under\n"
   "           the user's configuration folder)\n"},
  {"cert", nccert, "make or show an X.509 certificate for a key",
   "usage: noqtis cert -k <key> -n <name> [-e <email>] [--days <n>]\n"
   "                   [--pass-fd <n> | --pass-env <name>] -o <cert>\n"
   "                   [--force]\n"
   "       noqtis cert -k <key> --issuer <cert> --kem <kem.pub>\n"
   "                   [--days <n>] [--pass-fd <n> | --pass-env <name>]\n"
   "                   -o <cert> [--force]\n"
   "       noqtis cert --show <cert>\n"
   "  The first form writes a self-signed X.509 certificate (PEM) for the\n"
   "  signature key <key>, ML-DSA, SLH-DSA or Ed25519, under <name> and\n"
   "  <email>: give it to those who are to trust the key. The second\n"
   "  writes one for the ML-KEM public key <kem.pub>, issued by <key>\n"
   "  under the name of its certificate <cert>: what others encrypt to.\n"
   "  --days  how long it is valid (default 730)\n"
   "  --show  print what a certificate says\n"},
  {"token", nctoken, "keys on a PKCS #11 token: list, make, sign, decapsulate",
   "usage: noqtis token list [-m <module>]\n"
   "       noqtis token keys [common]\n"
   "       noqtis token keygen -a <alg> -n <label> [-o <key.pub>] [--force]\n"
   "                           [common]\n"
   "       noqtis token pub (-n <label> | --id <hex>) -o <key.pub> [--force]\n"
   "                        [common]\n"
   "       noqtis token sign (-n <label> | --id <hex>) [-c <ctx>] [-o <sig>]\n"
   "                         [--force] [common] <file>\n"
   "       noqtis token dec (-n <label> | --id <hex>) -o <ss> [--force]\n"
   "                        [common] <ct>\n"
   "  common: [-m <module>] [--slot <n>] [--pin-fd <n> | --pin-env <name>]\n"
   "  Private keys that stay on a token (a smart card, an HSM, a software\n"
   "  token), through its PKCS #11 module: ML-DSA, SLH-DSA, Ed25519 and\n"
   "  ML-KEM keys (PKCS #11 version 3.2).\n"
   "  list     the tokens present\n"
   "  keys     the private keys noqtis can use (shown after the PIN)\n"
   "  keygen   make a key pair on the token; -o writes the public key\n"
   "  pub      write a key's public key as a key file\n"
   "  sign     the signature `noqtis sign` writes; `noqtis verify` checks it\n"
   "  dec      decapsulate what `noqtis enc` wrote; the secret goes to <ss>\n"
   "  -m       the module's path (default: $NOQTIS_PKCS11); a path, not a\n"
   "           name to search for\n"
   "  --slot   the token, when more than one is present\n"
   "  The PIN is read from --pin-fd or --pin-env, never the command line.\n"},
  {"pgp", ncpgp, "OpenPGP keys, signatures and encrypted messages",
   "usage: noqtis pgp keygen -n <user ID> [-a <alg>] [--sign-only]\n"
   "                         [--pass-fd <n> | --pass-env <name>] -o <key>\n"
   "                         [--force]\n"
   "       noqtis pgp show <key>\n"
   "       noqtis pgp sign -k <key> [--detached | --clear] [--binary]\n"
   "                       [--pass-fd <n> | --pass-env <name>] [-o <out>]\n"
   "                       [--force] <file>\n"
   "       noqtis pgp verify --cert <cert> [--content <file>] [-o <out>]\n"
   "                         [--force] <file>\n"
   "       noqtis pgp encrypt [--to <cert> ...] [--symmetric] [-k <key>]\n"
   "                          [--binary] [--pass-fd <n> | --pass-env <name>]\n"
   "                          [-o <out>] [--force] <file>\n"
   "       noqtis pgp decrypt (-k <key> | --symmetric) [--cert <cert>]\n"
   "                          [--pass-fd <n> | --pass-env <name>] [-o <out>]\n"
   "                          [--force] <file>\n"
   "  OpenPGP (RFC 9580) in its version 6 forms, armored unless --binary.\n"
   "  keygen   a secret key in <key> and its certificate in <key>.pub,\n"
   "           for <user ID> (\"Name <address>\"); -a mldsa65-ed25519\n"
   "           (default), ed25519, slh-shake-128s, slh-shake-128f or\n"
   "           slh-shake-256s, with an encryption subkey (ML-KEM-768 with\n"
   "           X25519; X25519 for ed25519) unless --sign-only; under a\n"
   "           passphrase when one is given\n"
   "  show     what a key or a certificate says\n"
   "  sign     a signed message of <file>; --detached the signature\n"
   "           alone, --clear the text with the signature under it\n"
   "  verify   check one under the certificate: exit 0 and the signer\n"
   "           when it verifies, 1 when not; --content is what a detached\n"
   "           signature signs; -o writes the content\n"
   "  encrypt  to the certificates given with --to (up to 32), and with\n"
   "           --symmetric to the passphrase; -k signs it first (with\n"
   "           --symmetric the passphrase is the message's, and <key>\n"
   "           must not be under one)\n"
   "  decrypt  with the secret key, or with --symmetric the passphrase;\n"
   "           --cert requires it to be signed by that certificate\n"
   "  Versions 3 and 4, RSA and compressed data are not supported.\n"},
  {"smime", ncsmime, "sign, verify, encrypt or decrypt mail (S/MIME, CMS)",
   "usage: noqtis smime sign -k <key> --cert <cert> [--detached] [--der]\n"
   "                         [--text | --entity] [-o <out>] [--force]\n"
   "                         [--pass-fd <n> | --pass-env <name>] <file>\n"
   "       noqtis smime verify --anchor <cert> [--anchor <cert> ...]\n"
   "                           [--content <file>] [--entity] [-o <out>]\n"
   "                           [--force] <file>\n"
   "       noqtis smime encrypt --to <cert> [--to <cert> ...] [--der]\n"
   "                            [--text | --entity] [-o <out>] [--force]\n"
   "                            <file>\n"
   "       noqtis smime decrypt -k <key> [--cert <cert>] [--entity]\n"
   "                            [-o <out>] [--force]\n"
   "                            [--pass-fd <n> | --pass-env <name>] <file>\n"
   "  sign     an S/MIME message of <file>, signed with <key> whose\n"
   "           certificate is <cert> (`noqtis cert`); --detached keeps\n"
   "           the content in the clear beside the signature\n"
   "  verify   check one against the --anchor certificates (up to 32):\n"
   "           exit 0 and the signer when it verifies, 1 when not; -o\n"
   "           writes the content\n"
   "  encrypt  to the ML-KEM certificates given with --to (up to 32)\n"
   "  decrypt  with the ML-KEM secret key <key>\n"
   "  --der     write the CMS structure itself (DER) instead of a MIME\n"
   "            message; verify and decrypt read either, and verify\n"
   "            takes what a detached one signs with --content\n"
   "  --text    the content is text: it stays readable, and its line\n"
   "            ends become CRLF (default: every byte comes back as it\n"
   "            was)\n"
   "  --entity  <file> is a MIME entity already; verify and decrypt\n"
   "            write the entity instead of its body\n"},
  {"armor", ncarmor, "write a file as text (ASCII armor)",
   "usage: noqtis armor [-l <label>] [-o <out>] [--force] [<file>]\n"
   "  Writes <file> (- or none: stdin) to <out> (- or none: stdout) as\n"
   "  RFC 7468 text: a line -----BEGIN <label>-----, base64 in lines of\n"
   "  64 characters, a line -----END <label>-----. It is a third longer\n"
   "  and holds the same bytes; nothing is encrypted or signed by it.\n"
   "  -l      the label (--label): capitals and digits with single spaces\n"
   "          between them (default NOQTIS DATA)\n"
   "  --force replace an existing <out>\n"},
  {"dearmor", ncdearmor, "read the bytes an armored file holds",
   "usage: noqtis dearmor [-o <out>] [--force] [<file>]\n"
   "  Writes the bytes that the armor in <file> (- or none: stdin) holds\n"
   "  to <out> (- or none: stdout), whatever its label. Exit 2, and <out>\n"
   "  is removed, when the text is not one whole armor.\n"
   "  --force replace an existing <out>\n"},
  {"hash", nchash, "print or check file digests",
   "usage: noqtis hash [-a <hash>] [-c|--check] [<file>...]\n"
   "  Prints `<hex>  <file>` lines like sha256sum (- or no file: stdin).\n"
   "  --check reads such lines from the files and checks each digest;\n"
   "  exit 1 if any differs or cannot be read.\n"
   "  <hash>: sha224 sha256 (default) sha384 sha512 sha512-224\n"
   "          sha512-256 sha3-224 sha3-256 sha3-384 sha3-512\n"
   "          shake128 shake256 kt128 kt256\n"},
  {"seal", ncseal, "seal a capsule folder",
   "usage: noqtis seal -k <key> [-p <key.pub>] [--meta <json-file>]\n"
   "                   [--pass-fd <n> | --pass-env <name>]\n"
   "                   [--format 1|2|3] [--salt-key <file>]\n"
   "                   [--input [<name>=]<dir>]...\n"
   "                   [--tsa <url>]... [--anchor <der-file>]...\n"
   "                   [-r|--recursive] <dir>\n"
   "       noqtis seal --token [--module <path>] [--slot <n>]\n"
   "                   (--label <name> | --id <hex>)\n"
   "                   [--pin-fd <n> | --pin-env <name>] [the options\n"
   "                   above but -k, -p and --pass-*] <dir>\n"
   "  Writes noqtis.json and noqtis.sig into <dir>, covering every file.\n"
   "  The public key defaults to <key>.pub.\n"
   "  --token   seal with a signature key that stays on a PKCS #11\n"
   "            token (a smart card, a hardware security module),\n"
   "            named as for `noqtis token`; the public key in the\n"
   "            seal is the token's\n"
   "  --format  3 (the default): a Merkle tree over the files with a\n"
   "            secret salt in each leaf, so that `noqtis prove` can show\n"
   "            some of them and a proof confirms no guess of the others;\n"
   "            2: the same without salts (a proof lets a guess of\n"
   "            another file be confirmed); 1: a flat list of the files.\n"
   "            Readers older than 0.3.0 read 1 and 2 only.\n"
   "  --salt-key  a file of 32 secret bytes the salts are derived from\n"
   "            (default: fresh salts, so two seals of the same folder\n"
   "            differ); with it, and SOURCE_DATE_EPOCH, the same folder\n"
   "            gives the same capsule. Keep it secret.\n"
   "  --input   a sealed capsule this one was made from (up to 32): it\n"
   "            must check, and its id is recorded (format 3 or 2)\n"
   "  --tsa     an RFC 3161 time-stamping authority (" NCTSAU "; the\n"
   "            token is signed). The seal holds one timestamp: give\n"
   "            --tsa again for fallbacks, tried in order until one\n"
   "            answers with a token that checks. If none does, the\n"
   "            seal is removed and the exit status is 2.\n"
   "  --anchor  the TSA's root or issuing certificate (DER), to check\n"
   "            the token at seal time too (up to 32)\n"
   "  -r        seal every folder under <dir> (and <dir>) that holds\n"
   "            noqtis.json or noqtis.data.json, deepest first; <dir>\n"
   "            last\n"
   "  --pass-fd, --pass-env  the passphrase of a protected <key> (with\n"
   "            -r, a descriptor is read once for every folder)\n"},
  {"check", ncchk, "check a sealed capsule folder",
   "usage: noqtis check [-p <key.pub>] [--json] [--anchor <der-file>]...\n"
   "                    [--only <path>]... [--lineage <dir>]...\n"
   "                    [--keys <file>]... [--card <file>]\n"
   "                    <dir|file|url>\n"
   "       noqtis check [<options>] -r|--recursive <dir>\n"
   "       noqtis check [-p <key.pub>] [--json] [--anchor <der-file>]...\n"
   "                    --proof <file|url> [<dir|url>]\n"
   "  Prints every check and its result; exit 0 only if all pass. Without\n"
   "  -p the key inside the seal is trusted, and the report says so.\n"
   "  For each failed check, stderr says what to do.\n"
   "  <file> a bundle from `noqtis export --as bundle`: checked as the\n"
   "         folder it holds, in full (only one made with --no-files\n"
   "         is a partial check, of its data record: PARTIAL OK)\n"
   "  <url>  the http:// (or https://, with TLS) URL of a capsule's\n"
   "         folder: the seal and the manifest are fetched and checked\n"
   "         first, then the listed files (only --only's, when given)\n"
   "  --only     check only this file (up to 32): a partial check, which\n"
   "             the report says; the others are neither read nor needed\n"
   "  --lineage  the folder of an input capsule (up to 32): each input of\n"
   "             <dir> found among them is checked too, and theirs\n"
   "  --proof    check a proof from `noqtis prove`; with <dir>, the\n"
   "             proven files there too\n"
   "  --keys     a key statement from `noqtis rotate` or `revoke` (up to\n"
   "             32), followed from the -p key, which it needs\n"
   "  --card     an identity card from `noqtis idcard`: when it verifies\n"
   "             and is for the key that made the seal, the report says\n"
   "             who sealed the folder; otherwise its row fails and says\n"
   "             why\n"
   "  --anchor  a TSA root or issuing certificate (DER), up to 32: the\n"
   "            seal must then carry a timestamp that verifies under one\n"
   "            of them. Without --anchor, a timestamped seal fails its\n"
   "            timestamp check (it cannot be checked).\n"
   "  -r        check every sealed folder under <dir> (and <dir>), deepest\n"
   "            first, with the same options; a count goes to stderr\n"},
  {"chain", ncchain, "check an append-only chain of capsules",
   "usage: noqtis chain [-p <key.pub>] [--anchor <der-file>]... [--json]\n"
   "                    <dir>...\n"
   "  Checks the capsules given, oldest first, as a chain: each one checks\n"
   "  (as `noqtis check` with -p and --anchor), each after the first has\n"
   "  exactly one input, the one before it, and every one is sealed by\n"
   "  the same key. The last row is the chain's head: the last link's id.\n"
   "  Start a chain with `noqtis seal <dir>`; add a link with\n"
   "  `noqtis seal --input prev=<last> <new>`.\n"
   "  Exit 0 when the chain checks, 1 when it does not, 2 on a usage\n"
   "  error.\n"},
  {"prove", ncprove, "prove some files of a capsule, without the rest",
   "usage: noqtis prove [-p <key.pub>] [-o <file>] [-f] <dir> <path>...\n"
   "  Writes a proof (JSON) that the named files are in the format 3 or\n"
   "  2 capsule <dir>: the seal, the manifest's Merkle root and, per\n"
   "  file, its entry and audit path. The proof names no other file and\n"
   "  holds no other digest; of a format 2 capsule its hashes let a\n"
   "  guess of another file be confirmed, of a format 3 one they do not.\n"
   "  Check it with `noqtis check --proof`. The capsule must check first\n"
   "  (against -p when given).\n"
   "  -o  write to <file> (default stdout); -f replaces it\n"},
  {"export", ncexp, "a capsule as in-toto, DSSE, RO-Crate, BagIt or a bundle",
   "usage: noqtis export --as intoto|dsse|rocrate|bagit|bundle [-k <key>]\n"
   "                     [-p <key.pub>] [--pass-fd <n> | --pass-env <name>]\n"
   "                     [-o <file|dir>] [-f] [--no-files] <dir>\n"
   "  The capsule must check. intoto: an in-toto Statement v1 of its\n"
   "  files and their SHA-256; dsse: that statement in a DSSE envelope\n"
   "  signed with -k (check it with `noqtis verify --dsse`); rocrate:\n"
   "  RO-Crate 1.1 metadata (ro-crate-metadata.json); bagit: a BagIt 1.0\n"
   "  bag in the new folder -o, with a checked copy of every file;\n"
   "  bundle: the capsule in the one file -o (noqtis-bundle-1), which\n"
   "  `noqtis check <file>` checks; --no-files leaves out every file but\n"
   "  the data record.\n"
   "  -o  write to <file> (default stdout); -f replaces it\n"
   "  --pass-fd, --pass-env  the passphrase of a protected <key>\n"},
  {"pack", ncpack, "start, build and check a reproducibility bundle",
   "usage: noqtis pack init [-t|--template plain|r|python] <dir>\n"
   "       noqtis pack build -k <key> [-p <key.pub>] [--format 1|2|3]\n"
   "                         [--salt-key <file>]\n"
   "                         [--pass-fd <n> | --pass-env <name>]\n"
   "                         [--lock <file>]... [-o <file>] [-f]\n"
   "                         [--no-files] <dir>\n"
   "       noqtis pack check [-p <key.pub>] <dir|file>\n"
   "       noqtis pack unpack <file> <dir>\n"
   "  A bundle is a capsule whose data record holds the environment and\n"
   "  its lock files, sealed, and shipped as one file.\n"
   "  init    start one from a template: data/, the code folder (code/,\n"
   "          R/ or src/), output/, a README and an empty data record\n"
   "  build   record the environment (`noqtis env`, --lock as there),\n"
   "          seal (`noqtis seal`), and with -o write the bundle file\n"
   "          (`noqtis export --as bundle`)\n"
   "  check   before shipping: the capsule (`noqtis check`), the data\n"
   "          record (`noqtis data check`, lock files included), and that\n"
   "          the environment and at least one lock file are recorded\n"
   "  unpack  the bundle file into a new folder\n"
   "  --format, --salt-key  as for `noqtis seal` (build); with a salt key\n"
   "          and SOURCE_DATE_EPOCH the same folder gives the same bundle\n"
   "  --pass-fd, --pass-env  the passphrase of a protected <key> (build)\n"
   "  Exit 0 when everything passes, 1 when a check fails or a bundle is\n"
   "  malformed, 2 on a usage or file error.\n"},
  {"rotate", ncrot, "say that a seal key was replaced by a new one",
   "usage: noqtis rotate -k <key> [-p <key.pub>] -n <new> [--new-pub <new.pub>]\n"
   "                     [--pass-fd <n> | --pass-env <name>]\n"
   "                     [--new-pass-fd <n> | --new-pass-env <name>]\n"
   "                     [--at <time>] [--reason <text>] [-o <file>] [-f]\n"
   "  Writes a key statement (JSON), signed by both keys, that <key> was\n"
   "  replaced by <new> from <time> (YYYY-MM-DDTHH:MM:SSZ, UTC; default\n"
   "  now). `noqtis check -p <key.pub> --keys <file>` then accepts seals\n"
   "  made with <new>, and seals made with <key> only with a verified\n"
   "  timestamp from before <time>.\n"
   "  -o  write to <file> (default stdout); -f replaces it\n"
   "  --pass-fd, --pass-env  the passphrase of a protected <key>;\n"
   "  --new-pass-fd, --new-pass-env  that of <new> (one descriptor may\n"
   "  give both)\n"},
  {"revoke", ncrev, "say that a seal key must no longer be trusted",
   "usage: noqtis revoke -k <key> [-p <key.pub>] [--at <time>]\n"
   "                     [--pass-fd <n> | --pass-env <name>]\n"
   "                     [--reason <text>] [-o <file>] [-f]\n"
   "  Writes a key statement (JSON), signed by <key>, that it is revoked\n"
   "  from <time> (YYYY-MM-DDTHH:MM:SSZ, UTC; default now). With it,\n"
   "  `noqtis check --keys` accepts a seal made with <key> only with a\n"
   "  verified timestamp from before <time>.\n"
   "  -o  write to <file> (default stdout); -f replaces it\n"
   "  --pass-fd, --pass-env  the passphrase of a protected <key>\n"},
  {"expire", ncexpire, "say until when a seal key seals",
   "usage: noqtis expire -k <key> [-p <key.pub>] --at <time>\n"
   "                     [--pass-fd <n> | --pass-env <name>]\n"
   "                     [--reason <text>] [-o <file>] [-f]\n"
   "  Writes a key statement (JSON), signed by <key>, that it seals until\n"
   "  <time> (YYYY-MM-DDTHH:MM:SSZ, UTC) and not after. With it, `noqtis\n"
   "  check --keys` accepts a seal made with <key> as before until that\n"
   "  time has come, and from then on only with a verified timestamp\n"
   "  from before <time>.\n"
   "  -o  write to <file> (default stdout); -f replaces it\n"
   "  --pass-fd, --pass-env  the passphrase of a protected <key>\n"},
  {"idcard", ncidc, "make or check an identity card for a signing key",
   "usage: noqtis idcard -k <key> [-p <key.pub>] --name <name>\n"
   "                     [--orcid <id>] [--email <addr>] [--url <url>]\n"
   "                     [--affil <text>] [--pass-fd <n> | --pass-env <name>]\n"
   "                     [-o <file>] [-f]\n"
   "       noqtis idcard --verify <card> [-p <key.pub>]\n"
   "  Writes an identity card (JSON) that binds the public key of <key> to\n"
   "  a name and, when given, an ORCID iD, an e-mail address, an https://\n"
   "  web page and an affiliation, signed by <key> itself. --verify checks\n"
   "  a card and prints who it names and its key's SHA-256; with -p, the\n"
   "  card must be for that key. `noqtis check --card` names the sealer.\n"
   "  --orcid  0000-0002-1825-0097 or https://orcid.org/...; its check\n"
   "           digit must be right, and the card holds the bare iD\n"
   "  -o  write to <file> (default stdout); -f replaces it\n"
   "  --pass-fd, --pass-env  the passphrase of a protected <key>\n"
   "  Exit 0 when a card is written or verifies, 1 when it does not\n"
   "  verify, 2 on a usage or file error.\n"},
  {"timestamp", ncts, "add a timestamp to a sealed capsule",
   "usage: noqtis timestamp --tsa <url>... [--anchor <der-file>]...\n"
   "                        [--force] <dir>\n"
   "  Asks each RFC 3161 time-stamping authority in turn (" NCTSAU ")\n"
   "  for a token over the seal's signature and stores the first that\n"
   "  checks in noqtis.sig; the manifest and the signature are unchanged.\n"
   "  --anchor  the TSA's root or issuing certificate (DER), to check the\n"
   "            token now too (up to 32)\n"
   "  --force   replace a timestamp the seal already has\n"
   "  If no TSA gives a token that checks, nothing is written (exit 2).\n"},
  {"ers", ncers, "start or renew a capsule's evidence record (RFC 4998)",
   "usage: noqtis ers --tsa <url>... [--anchor <der-file>]...\n"
   "                  [--hash sha256|sha384|sha512] <dir>\n"
   "  Keeps a sealed capsule provable for decades: noqtis.ers holds\n"
   "  archive timestamps over the seal (noqtis.sig), from the TSAs given\n"
   "  (" NCTSAU "), the first that checks. The first run starts the\n"
   "  record; run it again before the last TSA certificate expires (it\n"
   "  adds a timestamp over the last one), or with another --hash when\n"
   "  the record's hash weakens (a new chain over the seal and the record\n"
   "  so far). The record there is checked before it is extended.\n"
   "  `noqtis check --anchor` checks it. While it is there, `noqtis seal`\n"
   "  and `noqtis timestamp` refuse the folder.\n"
   "  --anchor  a TSA's root or issuing certificate (DER), for the record\n"
   "            there and the new timestamp (up to 32)\n"
   "  --hash    the new timestamp's hash (default: the record's, or\n"
   "            SHA-256 for a new record)\n"
   "  Exit 0 when the record is written, 1 when the record there does not\n"
   "  check, 2 when no TSA gave a timestamp that checks or on a usage\n"
   "  error.\n"},
  {"data", ncdata, "make, show and check a capsule's data record",
   "usage: noqtis data init [-f] <dir>\n"
   "       noqtis data add [--url <url>] [--title <text>]\n"
   "                       [--publisher <text>] [--licence <text>]\n"
   "                       [--retrieved <time>|now] [--etag <text>]\n"
   "                       [--modified <text>] [--archived <url>]\n"
   "                       [--mirror <url>]... [--synthetic] <dir> <file>...\n"
   "       noqtis data put <dir> <member> <json-file|->\n"
   "       noqtis data del <dir> <member> [<path|name>]\n"
   "       noqtis data fmt <dir>\n"
   "       noqtis data show [--json] <dir>\n"
   "       noqtis data check [--json] <dir>\n"
   "       noqtis data syn --seed <n> [--rows <n>] <dir> <file>\n"
   "  The data record, noqtis.data.json in the capsule folder, says where\n"
   "  each file came from, its schema and summaries (noqtis-data(5)). Seal\n"
   "  the folder after changing it: the seal lists it like any file.\n"
   "  init   write an empty record (-f replaces one)\n"
   "  add    record each file's SHA-256 and size as a source, keeping\n"
   "         what the record already says of it; the options describe\n"
   "         where it came from (<time>: YYYY-MM-DDTHH:MM:SSZ, UTC)\n"
   "  put    add an element (JSON) to a member: sources, schemas, stats,\n"
   "         chunks, steps, checks, commits; or set env or cite\n"
   "  del    remove an element by its path or name, or a whole member\n"
   "  fmt    rewrite a record edited by hand in canonical form\n"
   "  show   print the record, one element a line (--json: as it is)\n"
   "  check  check the record and each file it lists against it\n"
   "  syn    write a synthetic <file> from its schema in the record (the\n"
   "         recipe), the same for the same seed, and record it as\n"
   "         synthetic; never in place of a file not marked synthetic\n"
   "  Exit 0 when every check passes, 1 when one fails, 2 on a usage or\n"
   "  file error.\n"},
  {"schema", ncschema, "pin and check the schema of CSV files",
   "usage: noqtis schema infer [-d|--delim <c>] [--no-header] [--ranges]\n"
   "                           [--put] <dir> <file>...\n"
   "       noqtis schema check [--json] <dir> [<file>...]\n"
   "  infer  print each CSV file's schema as JSON: its columns, the\n"
   "         narrowest type each fits (bool, int, real, date, text),\n"
   "         whether it has missing values (\"\" or NA) and the number of\n"
   "         rows; --ranges pins each number and date column's range;\n"
   "         --put records it in the data record instead\n"
   "  check  check the files against the schemas the record pins (all,\n"
   "         or those of the files named): header, types, missing\n"
   "         values, ranges, sets, row counts and rules\n"
   "  --delim     the field delimiter (default ,; tab for a tab)\n"
   "  --no-header the first line is data; columns are named V1, V2, ...\n"
   "  Exit 0 when every check passes, 1 when one fails, 2 on a usage or\n"
   "  file error.\n"},
  {"src", ncsrc, "fetch a capsule's sources, and say if they changed",
   "usage: noqtis src add (--url <url> | --portal ckan|socrata|arcgis\n"
   "                      [--base <url>] [--id <id>] [--resource <id>]\n"
   "                      [--format <fmt>] [--layer <n>]) [--mirror <url>]...\n"
   "                      [--archived <url>] [--wayback] [--synthetic]\n"
   "                      [--max <bytes>] [--timeout <s>] <dir> <file>\n"
   "       noqtis src resolve [--json] [-w|--write] [--wayback] <dir>\n"
   "                          [<file>...]\n"
   "       noqtis src fetch [--json] [-f|--force] [--max <bytes>]\n"
   "                        [--timeout <s>] <dir> [<file>...]\n"
   "       noqtis src refresh [--json] [-w|--write] [--max <bytes>]\n"
   "                          [--timeout <s>] <dir> [<file>...]\n"
   "       noqtis src list [--json] <dir>\n"
   "  add      record <file> as a source, by its address or its portal\n"
   "           and dataset; a file not there yet is fetched first.\n"
   "           --wayback pins the Wayback Machine's copy as archived\n"
   "  resolve  ask each portal where its file is now (-w records it);\n"
   "           --wayback pins each source's Wayback Machine copy\n"
   "  fetch    restore each missing file from the first address that\n"
   "           gives the recorded bytes: its url, portal, mirrors, then\n"
   "           its archived copy; bytes that differ are never written\n"
   "  refresh  fetch each source from its url or portal again and say\n"
   "           whether it is unchanged or changed (old and new SHA-256\n"
   "           and size) or unreachable; -w writes the new bytes and\n"
   "           records them (then seal again)\n"
   "  list     each source and its addresses, in the order fetch tries\n"
   "  --max      the largest file fetched (default 1 GiB)\n"
   "  --timeout  seconds for each file (default 600)\n"
   "  Exit 0 when all went well (refresh: nothing changed), 1 when a\n"
   "  file could not be fetched or (refresh) changed, 3 when refresh\n"
   "  found nothing changed but a source unreachable, 2 on a usage or\n"
   "  file error.\n"},
  {"drift", ncdrift, "summarise CSV files, and say later if they drifted",
   "usage: noqtis drift pin [-d|--delim <c>] [--no-header] <dir> <file>...\n"
   "       noqtis drift check [--json] [--psi-warn <x>] [--psi-fail <x>]\n"
   "                          [--alpha <p>] [--min-n <n>] [--benford]\n"
   "                          [-d <c>] [--no-header]\n"
   "                          <dir> [<file>[=<current-file>]...]\n"
   "       noqtis drift cal [-d <c>] [--no-header]\n"
   "                        <dir> <file>=<unchanged-file>...\n"
   "  pin    record each CSV file's summaries in the data record: a\n"
   "         quantile sketch, PSI bins and first-digit counts for numeric\n"
   "         columns, the 1,000 most frequent values of the others; of a\n"
   "         fixed size, so the data need not be kept\n"
   "  check  compare each file (or the current file given after =) with\n"
   "         its summary: Kolmogorov-Smirnov, PSI and Jensen-Shannon for\n"
   "         numeric columns, chi-square of homogeneity, PSI and JS for the\n"
   "         others, Benford's first-digit test\n"
   "  cal    calibrate the warnings of each file's summary on files known\n"
   "         not to have drifted from it (a re-fetch, a split of the same\n"
   "         data): a column then warns only beyond the largest PSI and\n"
   "         below the smallest p-value seen on them\n"
   "  --psi-fail  PSI from which a column fails (default 0.25), when both\n"
   "              samples have --min-n values (default 1000)\n"
   "  --psi-warn  PSI from which it warns (default 0.1)\n"
   "  --alpha     a KS or chi-square p-value below it warns (default\n"
   "              0.001); with --benford, a Benford one too\n"
   "  Exit 0 when nothing drifted, 1 when a column failed, 3 when one\n"
   "  only warned, 2 on a usage or file error.\n"},
  {"chunk", ncchunk, "record chunk digests of a large file, check a piece",
   "usage: noqtis chunk pin [--size <bytes>] <dir> <file>...\n"
   "       noqtis chunk check [--at <offset>] [--json] <dir> <file>\n"
   "                          [<piece>]\n"
   "  pin    record in the data record the SHA-256 of each run of --size\n"
   "         bytes (default 1048576; 1024 to 1 GiB) of each file, the last\n"
   "         one short; the file is read, never split\n"
   "  check  check the file, or a piece of it that starts at byte --at of\n"
   "         the file (a multiple of the chunk size; default 0), against\n"
   "         them: each whole chunk the piece holds, and a short last one\n"
   "         when the piece ends where the file does. Only the piece is\n"
   "         read; `noqtis check --only noqtis.data.json` checks the\n"
   "         record's seal without the file.\n"
   "  Exit 0 when every chunk read matches, 1 when one differs, 2 on a\n"
   "  usage or file error.\n"},
  {"env", ncenv, "record the environment in the data record",
   "usage: noqtis env [--rng <kind> [--seed <seed>]] [--lock <file>]... <dir>\n"
   "  Records in the data record's env the platform (os, arch), the noqtis\n"
   "  version, the locale and time zone, the random number generator and\n"
   "  its seed when given, and the SHA-256 of lock files: those named\n"
   "  (paths in <dir>), else renv.lock, uv.lock, poetry.lock,\n"
   "  Pipfile.lock, requirements.txt, Cargo.lock, go.sum,\n"
   "  package-lock.json, pnpm-lock.yaml, yarn.lock, environment.yml or\n"
   "  Manifest.toml at the top of <dir>. A binding fills runtime.\n"},
  {"commit", nccommit, "commit to a file now, to reveal it later",
   "usage: noqtis commit [--kind randomisation|preregistration|other]\n"
   "                     [--label <text>] [--after <time>] [-o <salt>] [-f]\n"
   "                     <dir> <file>\n"
   "  Records in the data record a commitment to <file> (a randomisation\n"
   "  list, an analysis plan): its SHA3-256 under a fresh 32-byte secret\n"
   "  salt, written to <file>.salt (owner-only; -o elsewhere). Keep the\n"
   "  salt and <file> out of the capsule until the reveal; seal the\n"
   "  capsule (with a timestamp) so the commitment is dated.\n"},
  {"reveal", ncreveal, "check a file against a commitment",
   "usage: noqtis reveal <dir> <file> <salt>\n"
   "  Exit 0 when <file> and its salt match a commitment of the data\n"
   "  record of <dir>, 1 when none matches, 2 on a usage or file error.\n"},
  {"cite", nccite, "print how to cite the data",
   "usage: noqtis cite [--format cff|bibtex] <dir>\n"
   "  Prints a CITATION.cff (default) or a BibTeX entry from the data\n"
   "  record's cite.\n"},
  {"diff", ncdiff, "what changed between two capsules",
   "usage: noqtis diff [--json] <dir> <dir>\n"
   "  Lists the files added, removed or changed between the two sealed\n"
   "  capsules' manifests, and what differs in their data records:\n"
   "  sources, schemas (columns added, removed or retyped, rows),\n"
   "  summaries (counts, medians, the PSI between them), the\n"
   "  environment, steps, checks, commitments and citation. Nothing is\n"
   "  checked: run `noqtis check` on each first.\n"
   "  Exit 0 when nothing differs, 1 when something does, 2 on a usage\n"
   "  or file error.\n"},
  {"report", ncrpt, "check a capsule and write a report of it",
   "usage: noqtis report [-p <key.pub>] [-f|--format md|txt] [-o <file>]\n"
   "                     [--force] [-j|--json] [--github] <dir>\n"
   "  Checks the capsule (as `noqtis check`, with -p the key the seal\n"
   "  must carry) and its data record (as `noqtis data check`) once, and\n"
   "  writes a report of both: the result, every check, and what the\n"
   "  record says of the data (sources, schemas, drift summaries,\n"
   "  environment, steps, recorded checks, commitments, citation), in\n"
   "  Markdown (default) or plain text, to <file> or standard output.\n"
   "  --force     replace <file> when it exists\n"
   "  --json      print instead one line of JSON: status, the counts\n"
   "              (total, failed, verified, changed) and every check\n"
   "  --github    print a GitHub workflow annotation per failed check\n"
   "  A folder that is not sealed fails. Exit 0 when every check passed,\n"
   "  1 when one failed, 2 on a usage or file error.\n"},
  {"inspect", ncinsp, "show what a capsule says (nothing checked)",
   "usage: noqtis inspect [--json] <dir>\n"
   "  Prints the seal's format, algorithm and key fingerprint (SHA-256 of\n"
   "  the public key), the manifest's created time, meta, number of files\n"
   "  and total size, and whether a timestamp is there. Nothing is\n"
   "  checked: run `noqtis check` for that. Exit 0 when the seal and the\n"
   "  manifest parse, 1 when one does not, 2 on a usage or folder error.\n"},
  {"algs", ncalgs, "list algorithms and sizes",
   "usage: noqtis algs\n"},
  {"selftest", ncself, "run the known-answer self-test",
   "usage: noqtis selftest\n"
   "  Runs nqselftest: known answers for every algorithm family (SLH-DSA\n"
   "  by its key generation only; nqselftest(3) lists the tests). Exit 0\n"
   "  when every one matches, 1 when one does not.\n"},
  {"version", ncver, "print the version",
   "usage: noqtis version [--check]\n"
   "  --check asks whether a newer release exists and says so. Exit 0,\n"
   "  1 when that cannot be asked, 2 on a usage error.\n"},
  {"help", nchelp, "show help for a command",
   "usage: noqtis help [<command>]\n"}
};

#define NCNCMD (sizeof cmds / sizeof cmds[0])

/* s for a terminal: every C0 control character, DEL and C1 control
 * (U+0080..U+009F, CSI among them) as \xNN, so a file name or a
 * server's text cannot move the cursor, clear lines or recolour the
 * screen. The result lives until the fourth call after. */
const char *ncesc(const char *s) {
  static char *b[4];
  static size_t cap[4];
  static int k = 0;
  const unsigned char *p = (const unsigned char *)s;
  size_t i, n = 0, o = 0;
  if (s == NULL)
    return "";
  for (i = 0; p[i] != 0; i++) {
    int c1 = p[i] == 0xc2 && p[i + 1] >= 0x80 && p[i + 1] <= 0x9f;
    if (c1) {
      n += 8;
      i++;
    } else {
      n += p[i] < 0x20 || p[i] == 0x7f ? 4 : 1;
    }
  }
  if (n == i)
    return s;
  k = (k + 1) % 4;
  if (cap[k] < n + 1) {
    char *nb = (char *)realloc(b[k], n + 1);
    if (nb == NULL)
      return "?";
    b[k] = nb;
    cap[k] = n + 1;
  }
  for (i = 0; p[i] != 0; i++) {
    if (p[i] == 0xc2 && p[i + 1] >= 0x80 && p[i + 1] <= 0x9f) {
      snprintf(b[k] + o, 9, "\\x%02x\\x%02x", p[i], p[i + 1]);
      o += 8;
      i++;
    } else if (p[i] < 0x20 || p[i] == 0x7f) {
      snprintf(b[k] + o, 5, "\\x%02x", p[i]);
      o += 4;
    } else {
      b[k][o++] = (char)p[i];
    }
  }
  b[k][o] = '\0';
  return b[k];
}

void ncmsg(const char *cmd, const char *fmt, ...) {
  va_list ap;
  char sb[1024], *b = sb;
  int n;
  fflush(stdout);
  if (cmd != NULL)
    fprintf(stderr, "noqtis %s: ", cmd);
  else
    fputs("noqtis: ", stderr);
  va_start(ap, fmt);
  n = vsnprintf(sb, sizeof sb, fmt, ap);
  va_end(ap);
  if (n >= (int)sizeof sb && (b = (char *)malloc((size_t)n + 1)) != NULL) {
    va_start(ap, fmt);
    vsnprintf(b, (size_t)n + 1, fmt, ap);
    va_end(ap);
  } else if (b == NULL) {
    b = sb;
  }
  /* one line, whatever the arguments held */
  fputs(ncesc(n < 0 ? "" : b), stderr);
  if (b != sb)
    free(b);
  fputc('\n', stderr);
}

int nclib(const char *cmd, const char *what, int rc) {
  /* out of descriptors is said as such: errno holds nothing else that
   * could be taken for it */
  int e = errno;
  if (rc == NQEIO && (e == EMFILE || e == ENFILE))
    ncmsg(cmd, "%s: %s: %s", what, nqerr(rc), strerror(e));
  else
    ncmsg(cmd, "%s: %s", what, nqerr(rc));
  return NCUSE;
}

int ncuse(FILE *f, const char *cmd) {
  size_t i;
  for (i = 0; i < NCNCMD; i++) {
    if (strcmp(cmds[i].name, cmd) == 0) {
      fputs(cmds[i].use, f);
      return 1;
    }
  }
  return 0;
}

static void ncall(FILE *f) {
  size_t i;
  fputs("usage: noqtis <command> [options] [args]\n\ncommands:\n", f);
  for (i = 0; i < NCNCMD; i++)
    fprintf(f, "  %-8s %s\n", cmds[i].name, cmds[i].brief);
  fputs("\n`noqtis help <command>` shows a command's options.\n"
        "Exit status: 0 success, 1 verification failed, 2 usage or file "
        "error\n(or standard output not written), 3 a warning (drift check, "
        "src refresh).\n", f);
}

static int cmdopt(const char *cmd, const ncopt *o, size_t n, const char *a,
                  size_t *at) {
  size_t i;
  (void)cmd;
  for (i = 0; i < n; i++) {
    if (a[1] == '-') {
      size_t l = strlen(o[i].l);
      if (o[i].l[0] != '\0' && strncmp(a + 2, o[i].l, l) == 0 &&
          (a[2 + l] == '\0' || a[2 + l] == '=')) {
        *at = i;
        return a[2 + l] == '=' ? 2 : 1;
      }
    } else if (o[i].s != '\0' && a[1] == o[i].s) {
      *at = i;
      return a[2] != '\0' ? 3 : 1;
    }
  }
  return 0;
}

int ncargs(const char *cmd, int argc, char **argv, const ncopt *o,
           size_t n, int *npos, int *help) {
  /* which one-value options were given: a second -p would otherwise
   * silently replace the first (`check -p trusted.pub "$@"`) */
  unsigned char seen[64];
  int i, np = 0, dash = 0;
  *help = 0;
  memset(seen, 0, sizeof seen);
  if (n > sizeof seen)
    return NCUSE;
  for (i = 1; i < argc; i++) {
    char *a = argv[i];
    const char *v;
    size_t at = 0;
    int how;
    if (dash || a[0] != '-' || a[1] == '\0') {
      argv[np++] = a;
      continue;
    }
    if (strcmp(a, "--") == 0) {
      dash = 1;
      continue;
    }
    if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
      *help = 1;
      continue;
    }
    how = cmdopt(cmd, o, n, a, &at);
    if (how == 0) {
      ncmsg(cmd, "unknown option %s (see `noqtis help %s`)", a, cmd);
      return NCUSE;
    }
    if (!o[at].arg) {
      if (how != 1) {
        ncmsg(cmd, "option %s takes no value", a);
        return NCUSE;
      }
      *o[at].flag = 1;
      continue;
    }
    if (how == 2) {
      v = strchr(a, '=') + 1;
    } else if (how == 3) {
      v = a + 2;
    } else {
      if (i + 1 >= argc) {
        ncmsg(cmd, "option %s needs a value", a);
        return NCUSE;
      }
      v = argv[++i];
    }
    if (o[at].arg == NCMANY) {
      if (*o[at].flag >= NCMAXV) {
        ncmsg(cmd, "option %s may be given at most %d times", a, NCMAXV);
        return NCUSE;
      }
      o[at].val[(*o[at].flag)++] = v;
    } else {
      if (seen[at]) {
        ncmsg(cmd, "option %s is given more than once", a);
        return NCUSE;
      }
      seen[at] = 1;
      *o[at].val = v;
    }
  }
  *npos = np;
  return NCOK;
}

static int noargs(const char *cmd, int argc, char **argv) {
  int np, help, rc = ncargs(cmd, argc, argv, NULL, 0, &np, &help);
  if (rc != NCOK)
    return rc;
  if (help) {
    ncuse(stdout, cmd);
    return -1;
  }
  if (np != 0) {
    ncmsg(cmd, "unexpected argument %s", argv[0]);
    return NCUSE;
  }
  return NCOK;
}

static int ncver(int argc, char **argv) {
  int rc;
  if (argc == 2 && strcmp(argv[1], "--check") == 0)
    return ncupdnow();
  rc = noargs("version", argc, argv);
  if (rc != NCOK)
    return rc < 0 ? NCOK : rc;
  printf("noqtis %s\n", nqver());
  return NCOK;
}

static int ncself(int argc, char **argv) {
  int rc = noargs("selftest", argc, argv);
  if (rc != NCOK)
    return rc < 0 ? NCOK : rc;
  if (nqselftest() != NQOK) {
    printf("selftest: a known answer did not match\n");
    return NCBAD;
  }
  printf("selftest: every known answer matches\n");
  return NCOK;
}

static int ncalgs(int argc, char **argv) {
  int i, rc = noargs("algs", argc, argv);
  if (rc != NCOK)
    return rc < 0 ? NCOK : rc;
  printf("%-22s %-4s %7s %7s %7s %4s\n", "algorithm", "type", "pk", "sk",
         "sig/ct", "ss");
  for (i = 1; i <= 64; i++) {
    nqssz s;
    const char *nm = nqsname((nqsalg)i);
    if (nm == NULL || nqssize((nqsalg)i, &s) != NQOK)
      break;
    printf("%-22s %-4s %7lu %7lu %7lu %4s\n", nm, "sig",
           (unsigned long)s.pk, (unsigned long)s.sk, (unsigned long)s.sig,
           "-");
  }
  for (i = 1; i <= 64; i++) {
    nqksz k;
    const char *nm = nqkname((nqkalg)i);
    if (nm == NULL || nqksize((nqkalg)i, &k) != NQOK)
      break;
    printf("%-22s %-4s %7lu %7lu %7lu %4lu\n", nm, "kem",
           (unsigned long)k.pk, (unsigned long)k.sk, (unsigned long)k.ct,
           (unsigned long)k.ss);
  }
  return NCOK;
}

static int nchelp(int argc, char **argv) {
  int i;
  for (i = 1; i < argc; i++) {
    if (argv[i][0] == '-')
      continue;
    if (!ncuse(stdout, argv[i])) {
      ncmsg("help", "unknown command %s", argv[i]);
      return NCUSE;
    }
    return NCOK;
  }
  ncall(stdout);
  return NCOK;
}

/* every command ends here: standard output that could not be written
 * (a full disk, /dev/full, a closed pipe when SIGPIPE is ignored) is
 * exit 2 with a message, whatever the command found, as hash and export
 * do, since what it printed is not all there; a command that already
 * failed with 2 has said why */
static int outend(const char *cmd, int rc) {
  if (fflush(stdout) == 0 && !ferror(stdout))
    return rc;
  if (rc != NCUSE)
    ncmsg(cmd, "cannot write to stdout");
  return NCUSE;
}

static int run(int argc, char **argv) {
  size_t i;
  ncbin();
  if (argc < 2) {
    ncall(stderr);
    return NCUSE;
  }
  if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
    ncall(stdout);
    return outend(NULL, NCOK);
  }
  if (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "-V") == 0) {
    printf("noqtis %s\n", nqver());
    return outend(NULL, NCOK);
  }
  ncprog();
  nqsettmp(nctmpev, NULL);
  nqdsettmp(nctmpev, NULL);
  for (i = 0; i < NCNCMD; i++) {
    if (strcmp(cmds[i].name, argv[1]) == 0)
      return outend(cmds[i].name, cmds[i].run(argc - 1, argv + 1));
  }
  ncmsg(NULL, "unknown command %s (see `noqtis help`)", argv[1]);
  return NCUSE;
}

#ifdef _WIN32
/* The arguments as UTF-8, from the wide command line, so that paths and
 * context strings outside the ANSI code page survive. */
int main(void) {
  int argc = 0, i, rc;
  wchar_t **w;
  char **argv, **own;
#ifdef _MSC_VER
  /* A failed check of the debug C runtime, and a fault, are written to
   * standard error and end the program: no dialog opens and waits for
   * someone to answer it (a script or a service has no one). */
  (void)_CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE | _CRTDBG_MODE_DEBUG);
  (void)_CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);
  (void)_CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_FILE | _CRTDBG_MODE_DEBUG);
  (void)_CrtSetReportFile(_CRT_ERROR, _CRTDBG_FILE_STDERR);
  (void)_set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
  (void)SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
#endif
  w = CommandLineToArgvW(GetCommandLineW(), &argc);
  if (w == NULL)
    return NCUSE;
  /* ncargs() reorders argv in place, so free from a copy of the pointers */
  argv = (char **)calloc((size_t)argc + 1, sizeof *argv);
  own = (char **)calloc((size_t)argc + 1, sizeof *own);
  if (argv == NULL || own == NULL)
    return NCUSE;
  for (i = 0; i < argc; i++) {
    int n = WideCharToMultiByte(CP_UTF8, 0, w[i], -1, NULL, 0, NULL, NULL);
    if (n <= 0 || (argv[i] = (char *)malloc((size_t)n)) == NULL ||
        WideCharToMultiByte(CP_UTF8, 0, w[i], -1, argv[i], n, NULL,
                            NULL) != n) {
      fputs("noqtis: cannot convert the arguments to UTF-8\n", stderr);
      return NCUSE;
    }
    own[i] = argv[i];
  }
  LocalFree(w);
  rc = run(argc, argv);
  for (i = 0; i < argc; i++)
    free(own[i]);
  free(own);
  free(argv);
  return rc;
}
#else
int main(int argc, char **argv) {
  return run(argc, argv);
}
#endif
