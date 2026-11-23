# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# fish completion for noqtis(1).

set -l cmds keygen passwd sign verify enc dec box unbox keys cert smime pgp token armor dearmor hash seal check prove export rotate revoke expire idcard inspect timestamp ers data src schema drift diff report env commit reveal cite pack chunk chain algs selftest version
set -l algs ML-DSA-44 ML-DSA-65 ML-DSA-87 SLH-DSA-SHA2-128s SLH-DSA-SHA2-128f \
    SLH-DSA-SHA2-192s SLH-DSA-SHA2-192f SLH-DSA-SHA2-256s SLH-DSA-SHA2-256f \
    SLH-DSA-SHAKE-128s SLH-DSA-SHAKE-128f SLH-DSA-SHAKE-192s \
    SLH-DSA-SHAKE-192f SLH-DSA-SHAKE-256s SLH-DSA-SHAKE-256f Ed25519 \
    ML-DSA-44+Ed25519 ML-DSA-65+Ed25519 ML-DSA-87+Ed25519 ML-KEM-512 \
    ML-KEM-768 ML-KEM-1024 HQC-128 HQC-192 HQC-256
set -l hashes sha224 sha256 sha384 sha512 sha512-224 sha512-256 sha3-224 \
    sha3-256 sha3-384 sha3-512 shake128 shake256

complete -c noqtis -f
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -s V -l version -d 'print the version'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a keygen -d 'make a key pair'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a passwd -d "change or remove a secret key's passphrase"
complete -c noqtis -n "__fish_seen_subcommand_from passwd" -s k -l key -r -F -d 'secret key file'
complete -c noqtis -n "__fish_seen_subcommand_from passwd rotate" -l new-pass-fd -x -d 'read the new passphrase from descriptor'
complete -c noqtis -n "__fish_seen_subcommand_from passwd rotate" -l new-pass-env -x -d 'read the new passphrase from variable'
complete -c noqtis -n "__fish_seen_subcommand_from passwd" -l no-pass -d 'keep the key under no passphrase'
complete -c noqtis -n "__fish_seen_subcommand_from keygen passwd" -l kdf -x -a "argon2id pbkdf2" -d 'how the passphrase protects the key'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a box -d 'seal a file to an ML-KEM key'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a unbox -d 'open a boxed file'
complete -c noqtis -n "__fish_seen_subcommand_from box" -l chunk -x -d 'chunk size in bytes'
complete -c noqtis -n "__fish_seen_subcommand_from box sign" -s a -l armor -d 'write it as text (ASCII armor)'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a keys -d "the key store: other people's keys by name"
complete -c noqtis -n "__fish_seen_subcommand_from keys" -a "list find add certify addcert trust export bundle import fetch rm path"
complete -c noqtis -n "__fish_seen_subcommand_from keys" -l store -r -F -d 'folder of the key store'
complete -c noqtis -n "__fish_seen_subcommand_from keys" -s n -l name -x -d 'name of the key holder'
complete -c noqtis -n "__fish_seen_subcommand_from keys" -s e -l email -x -d 'address of the key holder'
complete -c noqtis -n "__fish_seen_subcommand_from keys" -l card -r -F -d 'identity card of the key'
complete -c noqtis -n "__fish_seen_subcommand_from keys" -s k -l key -r -F -d 'secret key to certify with'
complete -c noqtis -n "__fish_seen_subcommand_from keys" -s o -l out -r -F -d 'output file'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a cert -d "make or show an X.509 certificate for a key"
complete -c noqtis -n "__fish_seen_subcommand_from cert" -s k -l key -r -F -d 'secret signature key'
complete -c noqtis -n "__fish_seen_subcommand_from cert" -s n -l name -x -d 'name of the holder'
complete -c noqtis -n "__fish_seen_subcommand_from cert" -s e -l email -x -d 'address of the holder'
complete -c noqtis -n "__fish_seen_subcommand_from cert" -l days -x -d 'days it is valid'
complete -c noqtis -n "__fish_seen_subcommand_from cert" -l issuer -r -F -d 'certificate of the signing key'
complete -c noqtis -n "__fish_seen_subcommand_from cert" -l kem -r -F -d 'ML-KEM public key to certify'
complete -c noqtis -n "__fish_seen_subcommand_from cert" -l show -r -F -d 'print what a certificate says'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a smime -d "sign, verify, encrypt or decrypt mail (S/MIME)"
complete -c noqtis -n "__fish_seen_subcommand_from smime" -a "sign verify encrypt decrypt"
complete -c noqtis -n "__fish_seen_subcommand_from smime" -s k -l key -r -F -d 'secret key'
complete -c noqtis -n "__fish_seen_subcommand_from smime" -l cert -r -F -d 'certificate of the key'
complete -c noqtis -n "__fish_seen_subcommand_from smime" -l anchor -r -F -d 'trusted certificate'
complete -c noqtis -n "__fish_seen_subcommand_from smime" -l to -r -F -d 'ML-KEM certificate of a recipient'
complete -c noqtis -n "__fish_seen_subcommand_from smime" -l content -r -F -d 'what a detached signature signs'
complete -c noqtis -n "__fish_seen_subcommand_from smime" -l detached -d 'keep the content in the clear'
complete -c noqtis -n "__fish_seen_subcommand_from smime" -l der -d 'write the CMS structure (DER)'
complete -c noqtis -n "__fish_seen_subcommand_from smime" -l text -d 'the content is text'
complete -c noqtis -n "__fish_seen_subcommand_from smime" -l entity -d 'the file is a MIME entity'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a token -d "keys on a PKCS #11 token"
complete -c noqtis -n "__fish_seen_subcommand_from token" -a "list keys keygen pub sign dec"
complete -c noqtis -n "__fish_seen_subcommand_from token" -s m -l module -r -F -d 'PKCS #11 module'
complete -c noqtis -n "__fish_seen_subcommand_from token" -l slot -x -d 'slot of the token'
complete -c noqtis -n "__fish_seen_subcommand_from token" -s n -l label -x -d 'label of the key'
complete -c noqtis -n "__fish_seen_subcommand_from token" -l id -x -d 'ID of the key, in hex'
complete -c noqtis -n "__fish_seen_subcommand_from token" -s a -l alg -x -d 'algorithm of a new key'
complete -c noqtis -n "__fish_seen_subcommand_from token" -s c -l ctx -x -d 'context string'
complete -c noqtis -n "__fish_seen_subcommand_from token" -l pin-fd -x -d 'read the PIN from descriptor'
complete -c noqtis -n "__fish_seen_subcommand_from token" -l pin-env -x -d 'read the PIN from variable'
complete -c noqtis -n "__fish_seen_subcommand_from token" -s o -l out -r -F -d 'output file'
complete -c noqtis -n "__fish_seen_subcommand_from token" -s f -l force -d 'replace an existing output'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a pgp -d "OpenPGP keys, signatures and encrypted messages"
complete -c noqtis -n "__fish_seen_subcommand_from pgp" -a "keygen show sign verify encrypt decrypt"
complete -c noqtis -n "__fish_seen_subcommand_from pgp" -s k -l key -r -F -d 'secret key'
complete -c noqtis -n "__fish_seen_subcommand_from pgp" -s n -l name -x -d 'user ID of a new key'
complete -c noqtis -n "__fish_seen_subcommand_from pgp" -s a -l alg -x -a "mldsa65-ed25519 ed25519 slh-shake-128s slh-shake-128f slh-shake-256s" -d 'algorithm of a new key'
complete -c noqtis -n "__fish_seen_subcommand_from pgp" -l cert -r -F -d 'certificate of the signer'
complete -c noqtis -n "__fish_seen_subcommand_from pgp" -l to -r -F -d 'certificate of a recipient'
complete -c noqtis -n "__fish_seen_subcommand_from pgp" -l content -r -F -d 'what a detached signature signs'
complete -c noqtis -n "__fish_seen_subcommand_from pgp" -l detached -d 'the signature alone'
complete -c noqtis -n "__fish_seen_subcommand_from pgp" -l clear -d 'the text with the signature under it'
complete -c noqtis -n "__fish_seen_subcommand_from pgp" -l binary -d 'no ASCII armor'
complete -c noqtis -n "__fish_seen_subcommand_from pgp" -l symmetric -d 'a passphrase for the message'
complete -c noqtis -n "__fish_seen_subcommand_from pgp" -l sign-only -d 'no encryption subkey'
complete -c noqtis -n "__fish_seen_subcommand_from pgp" -l pass-fd -x -d 'read the passphrase from descriptor'
complete -c noqtis -n "__fish_seen_subcommand_from pgp" -l pass-env -x -d 'read the passphrase from variable'
complete -c noqtis -n "__fish_seen_subcommand_from pgp" -s o -l out -r -F -d 'output file'
complete -c noqtis -n "__fish_seen_subcommand_from pgp" -s f -l force -d 'replace an existing output'
complete -c noqtis -n "__fish_seen_subcommand_from cert smime" -s o -l out -r -F -d 'output file'
complete -c noqtis -n "__fish_seen_subcommand_from cert smime" -s f -l force -d 'replace an existing output'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a armor -d "write a file as text (ASCII armor)"
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a dearmor -d "read the bytes an armored file holds"
complete -c noqtis -n "__fish_seen_subcommand_from armor" -s l -l label -x -d 'the label of the BEGIN and END lines'
complete -c noqtis -n "__fish_seen_subcommand_from armor dearmor" -s o -l out -r -F -d 'output file'
complete -c noqtis -n "__fish_seen_subcommand_from armor dearmor" -s f -l force -d 'replace an existing output'
complete -c noqtis -n "__fish_seen_subcommand_from box" -s s -l sign -r -F -d 'sign with this secret key'
complete -c noqtis -n "__fish_seen_subcommand_from box" -l pass-fd -x -d 'read the passphrase from descriptor'
complete -c noqtis -n "__fish_seen_subcommand_from box" -l pass-env -x -d 'read the passphrase from variable'
complete -c noqtis -n "__fish_seen_subcommand_from unbox" -s s -l sender -r -F -d 'the sender public key'
complete -c noqtis -n "__fish_seen_subcommand_from unbox" -l any-sender -d 'open a signed file whoever signed it'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a sign -d 'sign a file'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a verify -d 'verify a signature'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a enc -d 'encapsulate a shared secret'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a dec -d 'decapsulate a shared secret'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a hash -d 'print or check digests'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a seal -d 'seal a folder'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a check -d 'check a sealed folder'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a prove -d 'prove some files of a capsule'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a export -d 'a capsule as in-toto, DSSE, RO-Crate, BagIt or a bundle'
complete -c noqtis -n "__fish_seen_subcommand_from export" -l as -x -a "intoto dsse rocrate bagit bundle" -d format
complete -c noqtis -n "__fish_seen_subcommand_from export" -l no-files -d 'a bundle of the data record alone'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a pack -d 'start, build and check a reproducibility bundle'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a chunk -d 'chunk digests of a large file, a piece checked'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a chain -d 'check an append-only chain of capsules'
complete -c noqtis -n "__fish_seen_subcommand_from verify" -l dsse -d 'check a DSSE envelope'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a rotate -d 'say a seal key was replaced'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a revoke -d 'say a seal key is revoked'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a expire -d 'say until when a seal key seals'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a idcard -d 'make or check an identity card'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a inspect -d 'show what a seal says'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a selftest -d 'run the known-answer self-test'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a timestamp -d 'add public timestamps'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a ers -d 'start or renew an evidence record'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a data -d 'make, show and check a data record'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a schema -d 'pin and check the schema of CSV files'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a diff -d 'what changed between two capsules'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a src -d 'fetch the sources and say if they changed'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a drift -d 'summarise CSV files and check them for drift'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a env -d 'record the environment'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a commit -d 'commit to a file, to reveal it later'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a reveal -d 'check a file against a commitment'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a cite -d 'print how to cite the data'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a algs -d 'list the algorithms'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a version -d 'print the version'

# files after the commands that take one; folders after the capsule ones
complete -c noqtis -n "__fish_seen_subcommand_from sign verify enc dec hash" -F
complete -c noqtis -n "__fish_seen_subcommand_from seal check prove inspect timestamp ers" -a '(__fish_complete_directories)'

complete -c noqtis -n "__fish_seen_subcommand_from keygen" -s a -l alg -x -a "$algs" -d algorithm
complete -c noqtis -n "__fish_seen_subcommand_from hash" -s a -l alg -x -a "$hashes kt128 kt256" -d hash
complete -c noqtis -n "__fish_seen_subcommand_from keygen sign enc dec prove" -s o -l out -r -F -d 'file to write'
complete -c noqtis -n "__fish_seen_subcommand_from keygen" -l seed -r -F -d 'seed as hex or a seed file'
complete -c noqtis -n "__fish_seen_subcommand_from keygen passwd sign dec seal rotate revoke expire idcard export pack" -l pass-fd -x -d 'read the passphrase from descriptor'
complete -c noqtis -n "__fish_seen_subcommand_from keygen passwd sign dec seal rotate revoke expire idcard export pack" -l pass-env -x -d 'read the passphrase from variable'
complete -c noqtis -n "__fish_seen_subcommand_from keygen sign enc dec prove" -s f -l force -d 'replace existing files'
complete -c noqtis -n "__fish_seen_subcommand_from timestamp" -l force -d 'replace an existing timestamp'
complete -c noqtis -n "__fish_seen_subcommand_from sign dec seal" -s k -l key -r -F -d 'secret key'
complete -c noqtis -n "__fish_seen_subcommand_from seal" -l token -d 'sign with a key on a PKCS #11 token'
complete -c noqtis -n "__fish_seen_subcommand_from seal" -l module -r -F -d 'PKCS #11 module'
complete -c noqtis -n "__fish_seen_subcommand_from seal" -l slot -x -d 'slot of the token'
complete -c noqtis -n "__fish_seen_subcommand_from seal" -l label -x -d 'label of the key on the token'
complete -c noqtis -n "__fish_seen_subcommand_from seal" -l id -x -d 'ID of the key on the token, in hex'
complete -c noqtis -n "__fish_seen_subcommand_from seal" -l pin-fd -x -d 'read the PIN from descriptor'
complete -c noqtis -n "__fish_seen_subcommand_from seal" -l pin-env -x -d 'read the PIN from variable'
complete -c noqtis -n "__fish_seen_subcommand_from verify enc seal check prove" -s p -l pub -r -F -d 'public key'
complete -c noqtis -n "__fish_seen_subcommand_from verify" -s s -l sig -r -F -d signature
complete -c noqtis -n "__fish_seen_subcommand_from sign verify" -s c -l ctx -x -d 'context string'
complete -c noqtis -n "__fish_seen_subcommand_from sign" -s d -l det -d 'deterministic signature'
complete -c noqtis -n "__fish_seen_subcommand_from sign verify" -l ph -x -a "$hashes" -d 'pre-hash with'
complete -c noqtis -n "__fish_seen_subcommand_from verify" -s q -l quiet -d 'print nothing'
complete -c noqtis -n "__fish_seen_subcommand_from enc dec" -l stdout -d 'print the shared secret'
complete -c noqtis -n "__fish_seen_subcommand_from hash" -s c -l check -d 'check a list of sums'
complete -c noqtis -n "__fish_seen_subcommand_from seal" -s m -l meta -r -F -d 'metadata JSON'
complete -c noqtis -n "__fish_seen_subcommand_from seal timestamp ers" -l tsa -x -d 'RFC 3161 timestamp authority URL'
complete -c noqtis -n "__fish_seen_subcommand_from seal check timestamp ers" -l anchor -r -F -d 'trusted root certificate (DER)'
complete -c noqtis -n "__fish_seen_subcommand_from check inspect" -s j -l json -d 'JSON report'
complete -c noqtis -n "__fish_seen_subcommand_from version" -l check -d 'ask whether a newer release exists'
complete -c noqtis -n "__fish_seen_subcommand_from seal" -l token -d 'seal with a key on a PKCS #11 token'
complete -c noqtis -n "__fish_seen_subcommand_from seal" -l module -r -F -d 'PKCS #11 module'
complete -c noqtis -n "__fish_seen_subcommand_from seal" -l slot -x -d 'slot of the token'
complete -c noqtis -n "__fish_seen_subcommand_from seal" -l label -x -d 'label of the key on the token'
complete -c noqtis -n "__fish_seen_subcommand_from seal" -l id -x -d 'hexadecimal ID of the key on the token'
complete -c noqtis -n "__fish_seen_subcommand_from seal" -l pin-fd -x -d 'read the PIN from descriptor'
complete -c noqtis -n "__fish_seen_subcommand_from seal" -l pin-env -x -d 'read the PIN from variable'
complete -c noqtis -n "__fish_seen_subcommand_from seal" -l format -x -a "1 2" -d 'capsule format'
complete -c noqtis -n "__fish_seen_subcommand_from seal" -l input -x -a '(__fish_complete_directories)' -d 'an input capsule'
complete -c noqtis -n "__fish_seen_subcommand_from check" -l only -r -F -d 'check only this file'
complete -c noqtis -n "__fish_seen_subcommand_from check" -l lineage -x -a '(__fish_complete_directories)' -d 'an input capsule folder'
complete -c noqtis -n "__fish_seen_subcommand_from check" -l proof -r -F -d 'a proof from noqtis prove'
complete -c noqtis -n "__fish_seen_subcommand_from check" -l keys -r -F -d 'a key statement'
complete -c noqtis -n "__fish_seen_subcommand_from check" -l card -r -F -d 'an identity card'
complete -c noqtis -n "__fish_seen_subcommand_from idcard" -s k -l key -r -F -d 'secret key'
complete -c noqtis -n "__fish_seen_subcommand_from idcard" -s p -l pub -r -F -d 'its public key'
complete -c noqtis -n "__fish_seen_subcommand_from idcard" -l name -x -d 'your name'
complete -c noqtis -n "__fish_seen_subcommand_from idcard" -l orcid -x -d 'your ORCID iD'
complete -c noqtis -n "__fish_seen_subcommand_from idcard" -l email -x -d 'your e-mail address'
complete -c noqtis -n "__fish_seen_subcommand_from idcard" -l url -x -d 'your web page, https://'
complete -c noqtis -n "__fish_seen_subcommand_from idcard" -l affil -x -d 'your affiliation'
complete -c noqtis -n "__fish_seen_subcommand_from idcard" -s o -l out -r -F -d 'file to write'
complete -c noqtis -n "__fish_seen_subcommand_from idcard" -s f -l force -d 'replace the file'
complete -c noqtis -n "__fish_seen_subcommand_from idcard" -l verify -r -F -d 'check a card'
complete -c noqtis -n "__fish_seen_subcommand_from rotate revoke expire" -s k -l key -r -F -d 'secret key'
complete -c noqtis -n "__fish_seen_subcommand_from rotate revoke expire" -s p -l pub -r -F -d 'its public key'
complete -c noqtis -n "__fish_seen_subcommand_from rotate" -s n -l new -r -F -d 'the new secret key'
complete -c noqtis -n "__fish_seen_subcommand_from rotate" -l new-pub -r -F -d 'the new public key'
complete -c noqtis -n "__fish_seen_subcommand_from rotate revoke expire" -l at -x -d 'when, YYYY-MM-DDTHH:MM:SSZ'
complete -c noqtis -n "__fish_seen_subcommand_from rotate revoke expire" -l reason -x -d 'why'
complete -c noqtis -n "__fish_seen_subcommand_from rotate revoke expire" -s o -l out -r -F -d 'file to write'
complete -c noqtis -n "__fish_seen_subcommand_from rotate revoke expire" -s f -l force -d 'replace the file'
complete -c noqtis -n "__fish_seen_subcommand_from ers" -l hash -x -a 'sha256 sha384 sha512' -d 'the new timestamp\'s hash'

# noqtis data
complete -c noqtis -n "__fish_seen_subcommand_from data; and not __fish_seen_subcommand_from init add put del fmt show check syn" -a "init add put del fmt show check syn"
complete -c noqtis -n "__fish_seen_subcommand_from data" -F
complete -c noqtis -n "__fish_seen_subcommand_from data" -s f -l force -d 'replace the record'
complete -c noqtis -n "__fish_seen_subcommand_from data" -s u -l url -x -d 'where the file came from'
complete -c noqtis -n "__fish_seen_subcommand_from data" -l title -x -d 'its title'
complete -c noqtis -n "__fish_seen_subcommand_from data" -l publisher -x -d 'its publisher'
complete -c noqtis -n "__fish_seen_subcommand_from data" -l licence -x -d 'its licence'
complete -c noqtis -n "__fish_seen_subcommand_from data" -l retrieved -x -d 'when, YYYY-MM-DDTHH:MM:SSZ or now'
complete -c noqtis -n "__fish_seen_subcommand_from data" -l etag -x -d "the server's ETag"
complete -c noqtis -n "__fish_seen_subcommand_from data" -l modified -x -d "the server's Last-Modified"
complete -c noqtis -n "__fish_seen_subcommand_from data" -l archived -x -d 'an archived copy'
complete -c noqtis -n "__fish_seen_subcommand_from data" -l mirror -x -d 'another URL with the same bytes'
complete -c noqtis -n "__fish_seen_subcommand_from data" -l synthetic -d 'a generated stand-in'
complete -c noqtis -n "__fish_seen_subcommand_from data" -s j -l json -d 'JSON output'
complete -c noqtis -n "__fish_seen_subcommand_from data" -l seed -x -d 'the seed of a synthetic file'
complete -c noqtis -n "__fish_seen_subcommand_from data" -l rows -x -d 'its rows'

# noqtis schema
complete -c noqtis -n "__fish_seen_subcommand_from schema; and not __fish_seen_subcommand_from infer check" -a "infer check"
complete -c noqtis -n "__fish_seen_subcommand_from schema" -F
complete -c noqtis -n "__fish_seen_subcommand_from schema" -s d -l delim -x -d 'the delimiter'
complete -c noqtis -n "__fish_seen_subcommand_from schema" -l no-header -d 'the first line is data'
complete -c noqtis -n "__fish_seen_subcommand_from schema" -l ranges -d 'pin number and date ranges'
complete -c noqtis -n "__fish_seen_subcommand_from schema" -l put -d 'record the schema'
complete -c noqtis -n "__fish_seen_subcommand_from schema" -s j -l json -d 'JSON output'

# noqtis diff, seal -r, check -r
complete -c noqtis -n "__fish_seen_subcommand_from diff" -a '(__fish_complete_directories)'
complete -c noqtis -n "__fish_seen_subcommand_from diff" -s j -l json -d 'JSON output'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a report -d 'check a capsule and write a report of it'
complete -c noqtis -n "__fish_seen_subcommand_from report" -a '(__fish_complete_directories)'
complete -c noqtis -n "__fish_seen_subcommand_from report" -s p -l pub -r -d 'the key the seal must carry'
complete -c noqtis -n "__fish_seen_subcommand_from report" -s f -l format -x -a "md txt" -d "the report's format"
complete -c noqtis -n "__fish_seen_subcommand_from report" -s o -l out -r -d 'write the report to a file'
complete -c noqtis -n "__fish_seen_subcommand_from report" -l force -d 'replace the file when it exists'
complete -c noqtis -n "__fish_seen_subcommand_from report" -s j -l json -d 'a JSON summary instead'
complete -c noqtis -n "__fish_seen_subcommand_from report" -l github -d 'GitHub workflow annotations'
complete -c noqtis -n "__fish_seen_subcommand_from seal check" -s r -l recursive -d 'every capsule under the folder'

# noqtis src
complete -c noqtis -n "__fish_seen_subcommand_from src; and not __fish_seen_subcommand_from add resolve fetch refresh list" -a "add resolve fetch refresh list"
complete -c noqtis -n "__fish_seen_subcommand_from src" -F
complete -c noqtis -n "__fish_seen_subcommand_from src" -s u -l url -x -d 'the address of the file'
complete -c noqtis -n "__fish_seen_subcommand_from src" -l portal -x -a 'ckan socrata arcgis' -d 'the portal'
complete -c noqtis -n "__fish_seen_subcommand_from src" -l base -x -d 'the portal address'
complete -c noqtis -n "__fish_seen_subcommand_from src" -l id -x -d 'the dataset'
complete -c noqtis -n "__fish_seen_subcommand_from src" -l resource -x -d 'the resource'
complete -c noqtis -n "__fish_seen_subcommand_from src" -l format -x -d 'the format'
complete -c noqtis -n "__fish_seen_subcommand_from src" -l layer -x -d 'the layer'
complete -c noqtis -n "__fish_seen_subcommand_from src" -l mirror -x -d 'a copy'
complete -c noqtis -n "__fish_seen_subcommand_from src" -l archived -x -d 'an archived copy'
complete -c noqtis -n "__fish_seen_subcommand_from src" -l wayback -d 'pin the Wayback Machine copy'
complete -c noqtis -n "__fish_seen_subcommand_from src" -l synthetic -d 'a generated stand-in'
complete -c noqtis -n "__fish_seen_subcommand_from src" -l max -x -d 'the largest file'
complete -c noqtis -n "__fish_seen_subcommand_from src" -l timeout -x -d 'seconds per file'
complete -c noqtis -n "__fish_seen_subcommand_from src" -s j -l json -d 'JSON output'
complete -c noqtis -n "__fish_seen_subcommand_from src" -s w -l write -d 'record what changed'
complete -c noqtis -n "__fish_seen_subcommand_from src" -s f -l force -d 'replace a file that differs'

# noqtis drift
complete -c noqtis -n "__fish_seen_subcommand_from drift; and not __fish_seen_subcommand_from pin check cal" -a "pin check cal"
complete -c noqtis -n "__fish_seen_subcommand_from drift" -F
complete -c noqtis -n "__fish_seen_subcommand_from drift" -s d -l delim -x -d 'the delimiter'
complete -c noqtis -n "__fish_seen_subcommand_from drift" -l no-header -d 'the first line is data'
complete -c noqtis -n "__fish_seen_subcommand_from drift" -s j -l json -d 'JSON output'
complete -c noqtis -n "__fish_seen_subcommand_from drift" -l psi-warn -x -d 'PSI that warns'
complete -c noqtis -n "__fish_seen_subcommand_from drift" -l psi-fail -x -d 'PSI that fails'
complete -c noqtis -n "__fish_seen_subcommand_from drift" -l alpha -x -d 'p-value that warns'
complete -c noqtis -n "__fish_seen_subcommand_from drift" -l min-n -x -d 'values both need before PSI fails'
complete -c noqtis -n "__fish_seen_subcommand_from drift" -l benford -d 'Benford test warns too'

# noqtis env, commit, reveal, cite
complete -c noqtis -n "__fish_seen_subcommand_from env commit reveal cite" -F
complete -c noqtis -n "__fish_seen_subcommand_from env" -l rng -x -d 'the random number generator'
complete -c noqtis -n "__fish_seen_subcommand_from env" -l seed -x -d 'its seed'
complete -c noqtis -n "__fish_seen_subcommand_from env" -l lock -r -F -d 'a lock file'
complete -c noqtis -n "__fish_seen_subcommand_from commit" -l kind -x -a "randomisation preregistration other" -d 'what the file is'
complete -c noqtis -n "__fish_seen_subcommand_from commit" -l label -x -d 'a short name'
complete -c noqtis -n "__fish_seen_subcommand_from commit" -l after -x -d 'not before, UTC'
complete -c noqtis -n "__fish_seen_subcommand_from commit" -s o -l out -r -F -d 'the salt file'
complete -c noqtis -n "__fish_seen_subcommand_from commit" -s f -l force -d 'replace the salt file'
complete -c noqtis -n "__fish_seen_subcommand_from cite" -l format -x -a "cff bibtex" -d 'the format'

# noqtis pack
complete -c noqtis -n "__fish_seen_subcommand_from pack; and not __fish_seen_subcommand_from init build check unpack" -a "init build check unpack"
complete -c noqtis -n "__fish_seen_subcommand_from pack" -F
complete -c noqtis -n "__fish_seen_subcommand_from pack" -s t -l template -x -a "plain r python" -d 'the template'
complete -c noqtis -n "__fish_seen_subcommand_from pack" -s k -l key -r -F -d 'secret key'
complete -c noqtis -n "__fish_seen_subcommand_from pack" -s p -l pub -r -F -d 'its public key'
complete -c noqtis -n "__fish_seen_subcommand_from pack" -l format -x -a "1 2" -d 'capsule format'
complete -c noqtis -n "__fish_seen_subcommand_from pack" -l lock -r -F -d 'a lock file'
complete -c noqtis -n "__fish_seen_subcommand_from pack" -s o -l out -r -F -d 'the bundle file'
complete -c noqtis -n "__fish_seen_subcommand_from pack" -s f -l force -d 'replace the file'
complete -c noqtis -n "__fish_seen_subcommand_from pack" -l no-files -d 'a bundle of the data record alone'

# noqtis chunk
complete -c noqtis -n "__fish_seen_subcommand_from chunk; and not __fish_seen_subcommand_from pin check" -a "pin check"
complete -c noqtis -n "__fish_seen_subcommand_from chunk" -F
complete -c noqtis -n "__fish_seen_subcommand_from chunk" -l size -x -d 'bytes in a chunk'
complete -c noqtis -n "__fish_seen_subcommand_from chunk" -l at -x -d 'where the piece starts'
complete -c noqtis -n "__fish_seen_subcommand_from chunk" -s j -l json -d 'JSON output'

# noqtis chain
complete -c noqtis -n "__fish_seen_subcommand_from chain" -F
complete -c noqtis -n "__fish_seen_subcommand_from chain" -s p -l pub -r -F -d 'the key of every link'
complete -c noqtis -n "__fish_seen_subcommand_from chain" -l anchor -r -F -d 'trusted root certificate'
complete -c noqtis -n "__fish_seen_subcommand_from chain" -s j -l json -d 'JSON output'
