# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#
# rmoriebricklayer's own capsule format, capsule_bundle.json (cpsbndl),
# is not noqtis's, so noqtis cannot check it as a capsule. Where the two
# overlap, noqtis can: the attestation's ML-DSA or SLH-DSA signature, made
# over the hex SHA-256 of the canonical attestation payload (mnfcanon)
# under the bundle's context, and the SHA-256 of each bundled file. This
# writes, for tcli:
#   <out>/files/...        the bundled files
#   <out>/capsule_bundle.json
#   <out>/attest.msg       the exact bytes the attestation signed
#   <out>/attest.sig       the raw signature
#   <out>/attest.pub       the public key, as a noqtis key file
#   <out>/attest.ctx       the context string
#   <out>/files.sha256     the bundle's file digests, sha256sum format
# Each is derived from the bundle with rmoriebricklayer's own functions,
# and the signature is verified with cpsvrf before anything is written.
#
#   Rscript blbndl.R <out> <alg>

args <- commandArgs(trailingOnly = TRUE)
if (length(args) != 2L) {
  cat("usage: Rscript blbndl.R <out> <alg>\n")
  quit(status = 2L)
}
if (!requireNamespace("rmoriebricklayer", quietly = TRUE)) {
  cat("blbndl: rmoriebricklayer is not installed\n")
  quit(status = 77L)
}
bl <- function(f) getExportedValue("rmoriebricklayer", f)
out <- args[[1L]]
alg <- args[[2L]]
ctx <- "noqtis-interop"
# base64 on one line (jsb64enc breaks long output into lines)
b64 <- function(r) gsub("[\r\n]", "", bl("jsb64enc")(r))
unhex <- function(h) {
  n <- nchar(h)
  as.raw(strtoi(substring(h, seq(1L, n, 2L), seq(2L, n, 2L)), 16L))
}

d <- file.path(out, "files")
dir.create(file.path(d, "data"), recursive = TRUE, showWarnings = FALSE)
writeBin(charToRaw("x,y\n1,2\n3,4\n"), file.path(d, "data", "table.csv"))
writeBin(charToRaw("sealed by rmoriebricklayer, checked by noqtis\n"),
         file.path(d, "readme.txt"))
k <- bl("fipskg")(alg)
m <- bl("mkmnf")(list(dataset = "noqtis interop"), env = FALSE)
b <- bl("cpsbndl")(d, m, k, ctx = ctx,
                   path = file.path(out, "capsule_bundle.json"))
stopifnot(isTRUE(bl("cpsbndlvrf")(file.path(out, "capsule_bundle.json"), d,
                                  man = m)$ok))

a <- b$attestation
pay <- a[c("digest", "scheme", "public", "context", "prehash", "note",
           "signed_utc")]
msg <- bl("csha256")(charToRaw(bl("mnfcanon")(pay)))
stopifnot(isTRUE(bl("cpsvrf")(msg, a$signature, bl("fipspubkey")(k),
                              ctx = ctx)))
writeBin(charToRaw(msg), file.path(out, "attest.msg"))
writeBin(unhex(a$signature$signature), file.path(out, "attest.sig"))
writeBin(charToRaw(ctx), file.path(out, "attest.ctx"))
pb <- b64(unhex(a$public))
lines <- substring(pb, seq(1L, nchar(pb), 64L),
                   pmin(seq(64L, nchar(pb) + 63L, 64L), nchar(pb)))
writeBin(charToRaw(paste0("noqtis-key-1 ", alg, " pub\n",
                          paste0(lines, "\n", collapse = ""))),
         file.path(out, "attest.pub"))
sums <- vapply(b$files, function(f) paste0(f$sha256, "  ", f$path), "")
writeBin(charToRaw(paste0(sums, "\n", collapse = "")),
         file.path(out, "files.sha256"))
cat(sprintf("blbndl: bundled %d files with %s (rmoriebricklayer %s)\n",
            length(b$files), alg,
            as.character(utils::packageVersion("rmoriebricklayer"))))
