# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# bash completion for noqtis(1): commands, options, algorithm and hash
# names, and file or folder arguments.

_noqtis() {
  local cur prev cmd opts
  local algs="ML-DSA-44 ML-DSA-65 ML-DSA-87 SLH-DSA-SHA2-128s
    SLH-DSA-SHA2-128f SLH-DSA-SHA2-192s SLH-DSA-SHA2-192f SLH-DSA-SHA2-256s
    SLH-DSA-SHA2-256f SLH-DSA-SHAKE-128s SLH-DSA-SHAKE-128f
    SLH-DSA-SHAKE-192s SLH-DSA-SHAKE-192f SLH-DSA-SHAKE-256s
    SLH-DSA-SHAKE-256f Ed25519 ML-DSA-44+Ed25519 ML-DSA-65+Ed25519
    ML-DSA-87+Ed25519 ML-KEM-512 ML-KEM-768 ML-KEM-1024 HQC-128 HQC-192
    HQC-256"
  local hashes="sha224 sha256 sha384 sha512 sha512-224 sha512-256 sha3-224
    sha3-256 sha3-384 sha3-512 shake128 shake256"
  COMPREPLY=()
  cur=${COMP_WORDS[COMP_CWORD]}
  prev=${COMP_WORDS[COMP_CWORD-1]}
  if [ "$COMP_CWORD" -eq 1 ]; then
    COMPREPLY=($(compgen -W "keygen sign verify enc dec hash seal check
      prove export rotate revoke idcard inspect timestamp algs version -V
      --version" -- "$cur"))
    return
  fi
  cmd=${COMP_WORDS[1]}
  case $prev in
    -a | --alg)
      if [ "$cmd" = hash ]; then
        COMPREPLY=($(compgen -W "$hashes" -- "$cur"))
      else
        COMPREPLY=($(compgen -W "$algs" -- "$cur"))
      fi
      return ;;
    --ph)
      COMPREPLY=($(compgen -W "$hashes" -- "$cur"))
      return ;;
    --tsa | -c | --ctx | --format | --at | --reason | --as | --name | \
      --orcid | --email | --url | --affil)
      [ "$prev" = --format ] && COMPREPLY=($(compgen -W "1 2" -- "$cur"))
      [ "$prev" = --as ] &&
        COMPREPLY=($(compgen -W "intoto dsse rocrate bagit" -- "$cur"))
      return ;;
    --input | --lineage)
      COMPREPLY=($(compgen -d -- "$cur"))
      return ;;
    -k | --key | -p | --pub | -s | --sig | -o | --out | -m | --meta | \
      --anchor | --seed | --proof | --keys | -n | --new | --new-pub | \
      --card | --verify)
      COMPREPLY=($(compgen -f -- "$cur"))
      return ;;
  esac
  case $cmd in
    keygen) opts="-a --alg -o --out --seed -f --force" ;;
    sign) opts="-k --key -o --out -c --ctx -d --det --ph -f --force" ;;
    verify) opts="-p --pub -s --sig -c --ctx --ph -q --quiet --dsse -o
      --out" ;;
    export) opts="--as -k --key -p --pub -o --out -f --force" ;;
    enc) opts="-p --pub -o --out --stdout -f --force" ;;
    dec) opts="-k --key -o --out --stdout -f --force" ;;
    hash) opts="-a --alg -c --check" ;;
    seal) opts="-k --key -p --pub -m --meta --format --input --tsa
      --anchor" ;;
    check) opts="-p --pub -j --json --anchor --only --lineage --proof
      --keys --card" ;;
    idcard) opts="-k --key -p --pub --name --orcid --email --url --affil -o
      --out -f --force --verify" ;;
    rotate) opts="-k --key -p --pub -n --new --new-pub --at --reason -o --out
      -f --force" ;;
    revoke) opts="-k --key -p --pub --at --reason -o --out -f --force" ;;
    prove) opts="-p --pub -o --out -f --force" ;;
    inspect) opts="-j --json" ;;
    timestamp) opts="--tsa --anchor --force" ;;
    *) return ;;
  esac
  if [[ $cur == -* ]]; then
    COMPREPLY=($(compgen -W "$opts" -- "$cur"))
  else
    case $cmd in
      seal | check | inspect | timestamp | export)
        COMPREPLY=($(compgen -d -- "$cur")) ;;
      prove) COMPREPLY=($(compgen -d -- "$cur") $(compgen -f -- "$cur")) ;;
      *) COMPREPLY=($(compgen -f -- "$cur")) ;;
    esac
  fi
}
complete -o filenames -F _noqtis noqtis
