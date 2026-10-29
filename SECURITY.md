# Security policy

noqtis has not had an external security audit. Please report a vulnerability
privately through GitHub's "Report a vulnerability" button on this
repository (Security tab,
<https://github.com/rootcoder007/noqtis/security/advisories/new>), not in
a public issue. We aim to reply within 7 days and to publish a fix and
advisory within 90 days. Fixed vulnerabilities are listed at
<https://github.com/rootcoder007/noqtis/security/advisories>.

## Release signing key

Each release's `SHA256SUMS` is signed with this SSH key (namespace
`file`), alongside its keyless Sigstore signature:

```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIITExiNM+YezpSqyif5ZOhFb+abk4iy7CadyZnUMLRMj
```

Fingerprint `SHA256:Vl6mPTcRqQIOHJtPzEQWa8rbHJ+oRkxWmCfcHPrvjHA`. To check
a release, put it in an allowed-signers file:

```sh
echo "noqtis ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIITExiNM+YezpSqyif5ZOhFb+abk4iy7CadyZnUMLRMj" > allowed_signers
ssh-keygen -Y verify -f allowed_signers -I noqtis -n file \
  -s SHA256SUMS.sig < SHA256SUMS
```

A new key is announced here, signed by the old one, before it is used.

