# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# fish completion for noqtis(1).

set -l cmds keygen sign verify enc dec hash seal check prove export rotate revoke inspect timestamp algs version
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
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a sign -d 'sign a file'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a verify -d 'verify a signature'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a enc -d 'encapsulate a shared secret'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a dec -d 'decapsulate a shared secret'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a hash -d 'print or check digests'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a seal -d 'seal a folder'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a check -d 'check a sealed folder'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a prove -d 'prove some files of a capsule'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a export -d 'a capsule as in-toto, DSSE, RO-Crate or BagIt'
complete -c noqtis -n "__fish_seen_subcommand_from export" -l as -x -a "intoto dsse rocrate bagit" -d format
complete -c noqtis -n "__fish_seen_subcommand_from verify" -l dsse -d 'check a DSSE envelope'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a rotate -d 'say a seal key was replaced'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a revoke -d 'say a seal key is revoked'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a inspect -d 'show what a seal says'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a timestamp -d 'add public timestamps'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a algs -d 'list the algorithms'
complete -c noqtis -n "not __fish_seen_subcommand_from $cmds" -a version -d 'print the version'

# files after the commands that take one; folders after the capsule ones
complete -c noqtis -n "__fish_seen_subcommand_from sign verify enc dec hash" -F
complete -c noqtis -n "__fish_seen_subcommand_from seal check prove inspect timestamp" -a '(__fish_complete_directories)'

complete -c noqtis -n "__fish_seen_subcommand_from keygen" -s a -l alg -x -a "$algs" -d algorithm
complete -c noqtis -n "__fish_seen_subcommand_from hash" -s a -l alg -x -a "$hashes" -d hash
complete -c noqtis -n "__fish_seen_subcommand_from keygen sign enc dec prove" -s o -l out -r -F -d 'file to write'
complete -c noqtis -n "__fish_seen_subcommand_from keygen" -l seed -r -F -d 'seed as hex or a seed file'
complete -c noqtis -n "__fish_seen_subcommand_from keygen sign enc dec prove" -s f -l force -d 'replace existing files'
complete -c noqtis -n "__fish_seen_subcommand_from timestamp" -l force -d 'replace an existing timestamp'
complete -c noqtis -n "__fish_seen_subcommand_from sign dec seal" -s k -l key -r -F -d 'secret key'
complete -c noqtis -n "__fish_seen_subcommand_from verify enc seal check prove" -s p -l pub -r -F -d 'public key'
complete -c noqtis -n "__fish_seen_subcommand_from verify" -s s -l sig -r -F -d signature
complete -c noqtis -n "__fish_seen_subcommand_from sign verify" -s c -l ctx -x -d 'context string'
complete -c noqtis -n "__fish_seen_subcommand_from sign" -s d -l det -d 'deterministic signature'
complete -c noqtis -n "__fish_seen_subcommand_from sign verify" -l ph -x -a "$hashes" -d 'pre-hash with'
complete -c noqtis -n "__fish_seen_subcommand_from verify" -s q -l quiet -d 'print nothing'
complete -c noqtis -n "__fish_seen_subcommand_from enc dec" -l stdout -d 'print the shared secret'
complete -c noqtis -n "__fish_seen_subcommand_from hash" -s c -l check -d 'check a list of sums'
complete -c noqtis -n "__fish_seen_subcommand_from seal" -s m -l meta -r -F -d 'metadata JSON'
complete -c noqtis -n "__fish_seen_subcommand_from seal timestamp" -l tsa -x -d 'RFC 3161 timestamp authority URL'
complete -c noqtis -n "__fish_seen_subcommand_from seal check timestamp" -l anchor -r -F -d 'trusted root certificate (DER)'
complete -c noqtis -n "__fish_seen_subcommand_from check inspect" -s j -l json -d 'JSON report'
complete -c noqtis -n "__fish_seen_subcommand_from seal" -l format -x -a "1 2" -d 'capsule format'
complete -c noqtis -n "__fish_seen_subcommand_from seal" -l input -x -a '(__fish_complete_directories)' -d 'an input capsule'
complete -c noqtis -n "__fish_seen_subcommand_from check" -l only -r -F -d 'check only this file'
complete -c noqtis -n "__fish_seen_subcommand_from check" -l lineage -x -a '(__fish_complete_directories)' -d 'an input capsule folder'
complete -c noqtis -n "__fish_seen_subcommand_from check" -l proof -r -F -d 'a proof from noqtis prove'
complete -c noqtis -n "__fish_seen_subcommand_from check" -l keys -r -F -d 'a key statement'
complete -c noqtis -n "__fish_seen_subcommand_from rotate revoke" -s k -l key -r -F -d 'secret key'
complete -c noqtis -n "__fish_seen_subcommand_from rotate revoke" -s p -l pub -r -F -d 'its public key'
complete -c noqtis -n "__fish_seen_subcommand_from rotate" -s n -l new -r -F -d 'the new secret key'
complete -c noqtis -n "__fish_seen_subcommand_from rotate" -l new-pub -r -F -d 'the new public key'
complete -c noqtis -n "__fish_seen_subcommand_from rotate revoke" -l at -x -d 'when, YYYY-MM-DDTHH:MM:SSZ'
complete -c noqtis -n "__fish_seen_subcommand_from rotate revoke" -l reason -x -d 'why'
complete -c noqtis -n "__fish_seen_subcommand_from rotate revoke" -s o -l out -r -F -d 'file to write'
complete -c noqtis -n "__fish_seen_subcommand_from rotate revoke" -s f -l force -d 'replace the file'
