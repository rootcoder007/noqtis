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
    COMPREPLY=($(compgen -W "keygen passwd sign verify enc dec box unbox keys cert smime pgp token armor dearmor hash seal check
      prove export rotate revoke expire idcard inspect timestamp ers data src schema drift diff report env commit reveal cite pack chunk chain algs selftest version -V
      --version" -- "$cur"))
    return
  fi
  cmd=${COMP_WORDS[1]}
  case $prev in
    -a | --alg)
      if [ "$cmd" = hash ]; then
        COMPREPLY=($(compgen -W "$hashes kt128 kt256" -- "$cur"))
      else
        COMPREPLY=($(compgen -W "$algs" -- "$cur"))
      fi
      return ;;
    --ph)
      COMPREPLY=($(compgen -W "$hashes" -- "$cur"))
      return ;;
    --kdf)
      COMPREPLY=($(compgen -W "argon2id pbkdf2" -- "$cur"))
      return ;;
    --tsa | -c | --ctx | --format | --at | --reason | --as | --name | \
      --orcid | --email | --url | --affil)
      [ "$prev" = --format ] && COMPREPLY=($(compgen -W "1 2" -- "$cur"))
      [ "$prev" = --as ] &&
        COMPREPLY=($(compgen -W "intoto dsse rocrate bagit bundle" -- "$cur"))
      return ;;
    -t | --template)
      COMPREPLY=($(compgen -W "plain r python" -- "$cur"))
      return ;;
    --size)
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
    keygen) opts="-a --alg -o --out --seed --pass-fd --pass-env --kdf -f --force" ;;
    passwd) opts="-k --key --pass-fd --pass-env --new-pass-fd --new-pass-env --no-pass --kdf" ;;
    sign) opts="-k --key -o --out -a --armor -c --ctx -d --det --ph --pass-fd --pass-env
      -f --force" ;;
    verify) opts="-p --pub -s --sig -c --ctx --ph -q --quiet --dsse -o
      --out" ;;
    export) opts="--as -k --key -p --pub --pass-fd --pass-env -o --out -f --force
      --no-files" ;;
    enc) opts="-p --pub -o --out --stdout -f --force" ;;
    keys) opts="list find add certify addcert trust export bundle import fetch rm path --store --url -n --name -e --email --card -k --key -o --out --pass-fd --pass-env -f --force" ;;
    cert) opts="-k --key -n --name -e --email --days --issuer --kem --show -o --out --pass-fd --pass-env -f --force" ;;
    token) opts="list keys keygen pub sign dec -m --module --slot -n --label --id -a --alg -c --ctx -o --out --pin-fd --pin-env -f --force" ;;
    pgp) opts="keygen show sign verify encrypt decrypt -k --key -n --name -a --alg --cert --to --content --detached --clear --binary --symmetric --sign-only -o --out --pass-fd --pass-env -f --force" ;;
    smime) opts="sign verify encrypt decrypt -k --key --cert --anchor --to --content --detached --der --text --entity -o --out --pass-fd --pass-env -f --force" ;;
    armor) opts="-l --label -o --out -f --force" ;;
    dearmor) opts="-o --out -f --force" ;;
    box) opts="-p --pub -o --out -a --armor -c --ctx --chunk -s --sign --pass-fd --pass-env -f --force" ;;
    unbox) opts="-k --key -o --out -c --ctx -s --sender --any-sender --pass-fd --pass-env -f --force" ;;
    dec) opts="-k --key -o --out --stdout --pass-fd --pass-env -f --force" ;;
    hash) opts="-a --alg -c --check" ;;
    seal) opts="-k --key -p --pub --pass-fd --pass-env -m --meta --format --input
      --tsa --anchor -r --recursive --token --module --slot --label --id
      --pin-fd --pin-env" ;;
    check) opts="-p --pub -j --json --anchor --only --lineage --proof
      --keys --card -r --recursive" ;;
    diff) opts="-j --json" ;;
    report) opts="-p --pub -f --format -o --out --force -j --json --github" ;;
    env) opts="--rng --seed --lock" ;;
    commit) opts="--kind --label --after -o --out -f --force" ;;
    reveal) opts="" ;;
    cite) opts="--format" ;;
    src)
      if [ "$COMP_CWORD" -eq 2 ]; then
        COMPREPLY=($(compgen -W "add resolve fetch refresh list" -- "$cur"))
        return
      fi
      opts="-u --url --portal --base --id --resource --format --layer --mirror
        --archived --wayback --synthetic --max --timeout -j --json -w --write
        -f --force" ;;
    drift)
      if [ "$COMP_CWORD" -eq 2 ]; then
        COMPREPLY=($(compgen -W "pin check cal" -- "$cur"))
        return
      fi
      opts="-d --delim --no-header -j --json --psi-warn --psi-fail --alpha
        --min-n --benford" ;;
    idcard) opts="-k --key -p --pub --pass-fd --pass-env --name --orcid --email
      --url --affil -o --out -f --force --verify" ;;
    rotate) opts="-k --key -p --pub -n --new --new-pub --pass-fd --pass-env
      --new-pass-fd --new-pass-env --at --reason -o --out -f --force" ;;
    revoke|expire) opts="-k --key -p --pub --pass-fd --pass-env --at --reason
      -o --out -f --force" ;;
    prove) opts="-p --pub -o --out -f --force" ;;
    inspect) opts="-j --json" ;;
    version) opts="--check" ;;
    timestamp) opts="--tsa --anchor --force" ;;
    ers) opts="--tsa --anchor --hash" ;;
    data)
      if [ "$COMP_CWORD" -eq 2 ]; then
        COMPREPLY=($(compgen -W "init add put del fmt show check syn" -- "$cur"))
        return
      fi
      opts="-f --force -u --url --title --publisher --licence --retrieved
        --etag --modified --archived --mirror --synthetic -j --json --seed
        --rows" ;;
    pack)
      if [ "$COMP_CWORD" -eq 2 ]; then
        COMPREPLY=($(compgen -W "init build check unpack" -- "$cur"))
        return
      fi
      opts="-t --template -k --key -p --pub --pass-fd --pass-env --format --lock
        -o --out -f --force --no-files" ;;
    chunk)
      if [ "$COMP_CWORD" -eq 2 ]; then
        COMPREPLY=($(compgen -W "pin check" -- "$cur"))
        return
      fi
      opts="--size --at -j --json" ;;
    chain) opts="-p --pub --anchor -j --json" ;;
    schema)
      if [ "$COMP_CWORD" -eq 2 ]; then
        COMPREPLY=($(compgen -W "infer check" -- "$cur"))
        return
      fi
      opts="-d --delim --no-header --ranges --put -j --json" ;;
    *) return ;;
  esac
  if [[ $cur == -* ]]; then
    COMPREPLY=($(compgen -W "$opts" -- "$cur"))
  else
    case $cmd in
      seal | check | inspect | timestamp | ers | export | diff | report)
        COMPREPLY=($(compgen -d -- "$cur")) ;;
      data | src | schema | drift | env | commit | reveal | cite | pack | chunk | \
        chain)
        COMPREPLY=($(compgen -d -- "$cur") $(compgen -f -- "$cur")) ;;
      prove) COMPREPLY=($(compgen -d -- "$cur") $(compgen -f -- "$cur")) ;;
      *) COMPREPLY=($(compgen -f -- "$cur")) ;;
    esac
  fi
}
complete -o filenames -F _noqtis noqtis
