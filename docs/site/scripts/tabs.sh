#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Runs the command of every install tab (src/components/Switch.astro) in a clean container,
# all at once; each installs NOQTIS, hashes "abc" with SHA-256 and must print the known
# digest. Needs podman. PowerShell (install.ps1) is tested on Windows in CI instead.
#   sh scripts/tabs.sh
D=${TMPDIR:-/tmp}/nqtabs; rm -rf $D; mkdir -p $D
K=ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
O=https://download.opensuse.org/repositories/home:/rootcoder007
run() { n=$1; img=$2; shift 2; ( podman run --rm -i "$img" sh > $D/$n.log 2>&1 <<X
$*
X
  r=$?; if grep -q "$K" $D/$n.log; then echo "PASS $n (rc=$r)"; else echo "FAIL $n (rc=$r): $(tail -3 $D/$n.log | tr '\n' ' ' | cut -c1-200)"; fi ) & }

run git docker.io/library/debian:trixie-slim "set -e; apt-get update -qq; apt-get install -y -qq git cmake gcc make ca-certificates >/dev/null
git clone -q https://github.com/rootcoder007/noqtis.git; cd noqtis
cmake -S . -B build >/dev/null && cmake --build build -j4 >/dev/null
cmake --install build --prefix ~/.local >/dev/null
printf abc > /tmp/f; ~/.local/bin/noqtis hash /tmp/f"

run c docker.io/library/debian:trixie-slim "set -e; export DEBIAN_FRONTEND=noninteractive; apt-get update -qq; apt-get install -y -qq curl gpg ca-certificates gcc pkg-config libc6-dev >/dev/null
install -d -m 0755 /etc/apt/keyrings
curl -fsSL $O/Debian_13/Release.key | gpg --dearmor -o /etc/apt/keyrings/noqtis.gpg
echo 'deb [signed-by=/etc/apt/keyrings/noqtis.gpg] $O/Debian_13/ /' > /etc/apt/sources.list.d/noqtis.list
apt-get update -qq; apt-get install -y -qq libnoqtis-dev >/dev/null
cat > prog.c <<'C'
#include <stdio.h>
#include <noqtis.h>
int main(void) { unsigned char d[32]; int i;
  if (nqhash(NQS256, (const unsigned char *)\"abc\", 3, d, 32) != NQOK) return 1;
  for (i = 0; i < 32; i++) printf(\"%02x\", d[i]); printf(\"\\\\n\"); return 0; }
C
cc prog.c \$(pkg-config --cflags --libs noqtis) -o prog && ./prog"

JSH='import { init, hash } from "noqtis"; await init(); console.log(Array.from(hash("sha256", new TextEncoder().encode("abc")), (b) => b.toString(16).padStart(2, "0")).join(""));'
run npm docker.io/library/node:24-slim "set -e; cd /tmp; echo '{\"type\":\"module\"}' > package.json; npm install -s noqtis; echo '$JSH' > t.mjs; node t.mjs"
run pnpm docker.io/library/node:24-slim "set -e; cd /tmp; corepack enable >/dev/null 2>&1; echo '{\"type\":\"module\"}' > package.json; pnpm add noqtis >/dev/null 2>&1 || pnpm add noqtis; echo '$JSH' > t.mjs; node t.mjs"
run bun docker.io/oven/bun:1 "set -e; cd /tmp; echo '{\"type\":\"module\"}' > package.json; bun add noqtis >/dev/null; echo '$JSH' > t.mjs; bun t.mjs"
run deno docker.io/denoland/deno:latest "set -e; cd /tmp; echo '{}' > deno.json; deno add npm:noqtis >/dev/null 2>&1; echo '$JSH' > t.ts; deno run -A t.ts"

run r docker.io/rocker/r-ver:4.5 "set -e; Rscript -e 'install.packages(\"noqtis\", repos = c(\"https://rootcoder007.r-universe.dev\", \"https://cloud.r-project.org\"), quiet = TRUE); library(noqtis); cat(nqhash(charToRaw(\"abc\"), hex = TRUE), \"\\\\n\")'"

run cargo docker.io/library/rust:1 "set -e; cd /tmp; cargo new -q t; cd t; cargo add -q noqtis
cat > src/main.rs <<'R'
fn main() { let d = noqtis::hash(\"sha256\", b\"abc\", None).unwrap(); println!(\"{}\", d.iter().map(|b| format!(\"{:02x}\", b)).collect::<String>()); }
R
cargo run -q"

run go docker.io/library/golang:1 "set -e; cd /tmp; mkdir t; cd t; go mod init t >/dev/null 2>&1; go get github.com/rootcoder007/noqtis/bindings/go@latest
cat > main.go <<'G'
package main
import (\"encoding/hex\"; \"fmt\"; noqtis \"github.com/rootcoder007/noqtis/bindings/go\")
func main() { d, err := noqtis.Hash(\"sha256\", []byte(\"abc\")); if err != nil { panic(err) }; fmt.Println(hex.EncodeToString(d)) }
G
go run ."

run maven docker.io/library/maven:3-eclipse-temurin-25 "set -e; cd /tmp; V=\$(curl -fsSL https://api.github.com/repos/rootcoder007/noqtis/releases/latest | sed -n 's/.*\"tag_name\": *\"v\\([^\"]*\\)\".*/\\1/p'); echo version=\$V
mkdir -p t/src/main/java; cd t
cat > pom.xml <<P
<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId><artifactId>t</artifactId><version>1</version>
<properties><maven.compiler.release>25</maven.compiler.release></properties>
<dependencies><dependency><groupId>io.github.rootcoder007</groupId><artifactId>noqtis</artifactId><version>\$V</version></dependency></dependencies></project>
P
cat > src/main/java/T.java <<'J'
public class T { public static void main(String[] a) { byte[] d = io.github.rootcoder007.noqtis.Noqtis.hash(\"sha256\", \"abc\".getBytes()); StringBuilder s = new StringBuilder(); for (byte b : d) s.append(String.format(\"%02x\", b)); System.out.println(s); } }
J
mvn -q dependency:build-classpath -Dmdep.outputFile=cp.txt >/dev/null; mvn -q compile >/dev/null
java --enable-native-access=ALL-UNNAMED -cp target/classes:\$(cat cp.txt) T"

run brew docker.io/homebrew/brew:latest "set -e; brew install -q rootcoder007/noqtis/noqtis >/dev/null 2>&1 || brew install rootcoder007/noqtis/noqtis; printf abc > /tmp/f; noqtis hash /tmp/f"

run py docker.io/library/python:3.13-slim "set -e; pip install -q noqtis 2>/dev/null; python -c 'import noqtis; print(noqtis.hash(\"sha256\", b\"abc\").hex())'"
wait
