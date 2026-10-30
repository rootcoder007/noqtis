# DER, X.509, OCSP, CRL and RFC 3161 fixtures

- `bricklayer-x509.txt`, `bricklayer-tsp.txt`: copied unchanged from
  rmoriebricklayer 1.0.3 (`tests/testthat/x509-fixtures.txt` and
  `tests/testthat/timestamp-token.txt`, last changed in commit 1fc28abe).
  Lines are `name|hex` (DER). Throwaway test CAs made with OpenSSL; see the
  comments at the top of each file.
- `local/`: one run of `gen.sh` (OpenSSL 3.5.9 on l14, 2026-10-28) with
  throwaway keys, discarded after the run: an RSA root, an intermediate
  signed with RSA-PSS (pathlen 0), a TSA, leaves (good, revoked, unknown),
  a delegated OCSP responder, a second CA below the intermediate and its
  leaf (a path one too long), a P-384 root over a P-256 TSA, and an
  ML-DSA-65 root over an ML-DSA-44 TSA certificate; timestamp tokens and
  responses from `openssl ts -reply` (`l_*.tsr` the TimeStampResp, `l_*.tok`
  the bare token; `nonces.txt` the request nonces); OCSP responses from
  `openssl ocsp` (`o_*.der`: SHA-1 and SHA-256 CertIDs, by name and by key,
  delegated, without certificates, good, revoked, unknown); CRLs from
  `openssl ca -gencrl` (`rsa_crl.der` by the intermediate, revoking
  `rsa_leaf_rev`; `rsa_crl_root.der` by the root). Every token and response
  verified with `openssl ts -verify` / `openssl ocsp` when it was made.
  OpenSSL 3.5 cannot sign a timestamp with ML-DSA, so the ML-DSA
  certificates serve the path tests only.
- `nc/`: one run of `nc.sh` (OpenSSL 3.5.9 on l14, 2026-10-30) with
  throwaway P-256 keys, discarded after the run: a root, intermediates
  carrying nameConstraints (DNS, IP, directory name and mail, URI, and
  two with a maximum or a minimum that the profile forbids), a
  self-issued intermediate, and leaves inside and outside them (the
  table at the end of `nc.sh`). `openssl verify` agrees with
  `tests/tx509.c` on every leaf but three, where noqtis is stricter on
  purpose: `l_dns_wild` (`*.example.com`, whose one label could be the
  excluded `bad.example.com`), `l_uri_has` (a URI below a URI
  constraint: noqtis does not compare URIs and fails closed), and
  `nc_max` / `nc_min`, which noqtis refuses to parse (RFC 5280
  4.2.1.10: minimum 0, no maximum). `oracle.txt` was rebuilt with
  `oracle.sh` after these were added.
- `public/`: real RFC 3161 responses, requested on 2026-10-28 (19:41 UTC)
  for `data.txt` with `openssl ts -query -data data.txt -<hash> -cert`
  (`nonces.txt` holds each request's nonce; `r-ssl-nonce0.tsr` was asked
  with `-no_nonce`) and posted with
  `curl --data-binary @q.tsq -H 'Content-Type: application/timestamp-query'`
  to https://freetsa.org/tsr, http://timestamp.digicert.com,
  http://ts.ssl.com, http://timestamp.sectigo.com and
  http://timestamp.globalsign.com/tsa/r6advanced1. Anchors:
  - `anchor-freetsa.org.der`: https://freetsa.org/files/cacert.pem
  - `anchor-timestamp.digicert.com.der`: DigiCert Assured ID Root CA,
    https://cacerts.digicert.com/DigiCertAssuredIDRootCA.crt (the token
    carries the cross-certificate of Trusted Root G4 under it);
    `anchor-digicert-g4.der`: the self-signed DigiCert Trusted Root G4,
    https://cacerts.digicert.com/DigiCertTrustedRootG4.crt. The tokens
    verify under either.
  - `anchor-ts.ssl.com.der`: SSL.com Root Certification Authority RSA,
    from Fedora's `/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem`
  - `anchor-timestamp.sectigo.com.der`: USERTrust RSA Certification
    Authority, from the same bundle (the token carries Sectigo Public Time
    Stamping Root R46 cross-signed by it); `anchor-sectigo-r46.der`: the
    self-signed R46,
    http://crt.sectigo.com/SectigoPublicTimeStampingRootR46.crt
  - `anchor-timestamp.globalsign.com.der`: GlobalSign Root CA - R6,
    https://secure.globalsign.com/cacert/root-r6.crt
  Each response verified with `openssl ts -verify -data data.txt -CAfile
  <anchor>` before it was saved.
- `oracle.txt`: the signatures the tests' stub verifier accepts (see
  `tests/tderh.h`). Rebuild with `oracle.sh` after changing fixtures: it
  lists a request only when `openssl pkeyutl -verify` accepts it.

## The anchor rule the tests rely on

A certificate stands for a trust anchor when its subject Name equals the
anchor's (`nqxneq`) and its SubjectPublicKeyInfo is byte-identical
(`nqxalias`). A path ends at the anchor when it reaches such a
certificate, and the anchor's own validity and constraints apply. A token
may carry certificates that are on its path, byte-equal to an anchor, or
aliases of an anchor (the anchor's subject and key, whoever issued them:
a cross-certificate of a self-signed root, or a copy of the root). Every
one must parse strictly; nothing but subject and key is taken from an
alias, and any other certificate in the token is refused. So a mutated
embedded copy of an anchor that keeps its subject and key and still
parses is tolerated, because only the configured anchor is trusted: the
mutation test counts these as the anchor-alias class. The leaf is
never its own anchor.
