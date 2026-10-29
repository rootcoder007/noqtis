# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#
# Seals a folder as a noqtis capsule with rmoriebricklayer's signatures:
# the key pair (fipskg), the SHA-256 of every file (sha256file) and of the
# manifest (csha256), and the ML-DSA or SLH-DSA signature over the exact
# bytes of noqtis.json under the context "noqtis-capsule-1" (cpssign).
# rmoriebricklayer has no SHA3-256 of data, so each file's sha3_256 is
# taken from `noqtis hash -a sha3-256`; the JSON is written here in the
# canonical form noqtis-capsule-1 needs (rmoriebricklayer's JSON is not
# RFC 8785). Writes <dir>/noqtis.json, <dir>/noqtis.sig and <pub>, a
# noqtis key file of the public key.
#
#   Rscript blseal.R <dir> <alg> <pub> <noqtis>
#
# The creation time is SOURCE_DATE_EPOCH when set. Exit 77 when
# rmoriebricklayer is not installed.

args <- commandArgs(trailingOnly = TRUE)
if (length(args) != 4L) {
  cat("usage: Rscript blseal.R <dir> <alg> <pub> <noqtis>\n")
  quit(status = 2L)
}
if (!requireNamespace("rmoriebricklayer", quietly = TRUE)) {
  cat("blseal: rmoriebricklayer is not installed\n")
  quit(status = 77L)
}
bl <- function(f) getExportedValue("rmoriebricklayer", f)
dir <- args[[1L]]
alg <- args[[2L]]

# a JSON string as RFC 8785 writes it: only ", \ and controls escaped
# (ASCII only here: enough for the fixtures, and no locale to get wrong)
jstr <- function(s) {
  b <- as.integer(charToRaw(s))
  if (any(b > 0x7fL)) stop("blseal: only ASCII paths: ", s, call. = FALSE)
  out <- vapply(b, function(c) {
    if (c == 0x22L) "\\\"" else if (c == 0x5cL) "\\\\"
    else if (c == 0x08L) "\\b" else if (c == 0x09L) "\\t"
    else if (c == 0x0aL) "\\n" else if (c == 0x0cL) "\\f"
    else if (c == 0x0dL) "\\r"
    else if (c < 0x20L) sprintf("\\u%04x", c)
    else rawToChar(as.raw(c))
  }, "")
  paste0("\"", paste(out, collapse = ""), "\"")
}
# base64 on one line (jsb64enc breaks long output into lines)
b64 <- function(r) gsub("[\r\n]", "", bl("jsb64enc")(r))
unhex <- function(h) {
  n <- nchar(h)
  as.raw(strtoi(substring(h, seq(1L, n, 2L), seq(2L, n, 2L)), 16L))
}

files <- list.files(dir, recursive = TRUE, all.files = TRUE, no.. = TRUE)
files <- setdiff(files, c("noqtis.json", "noqtis.sig"))
# paths sorted by their UTF-8 bytes, as the format requires
files <- files[order(vapply(files, function(p)
  paste(sprintf("%02x", as.integer(charToRaw(p))), collapse = ""),
  ""), method = "radix")]
ent <- vapply(files, function(p) {
  f <- file.path(dir, p)
  s3 <- system2(args[[4L]], c("hash", "-a", "sha3-256", shQuote(f)),
                stdout = TRUE)
  paste0("{\"path\":", jstr(p),
         ",\"sha256\":\"", bl("sha256file")(f),
         "\",\"sha3_256\":\"", substr(s3[[1L]], 1L, 64L),
         "\",\"size\":", format(file.size(f), scientific = FALSE), "}")
}, "")
t <- Sys.getenv("SOURCE_DATE_EPOCH")
t <- if (nzchar(t)) as.POSIXct(as.numeric(t), origin = "1970-01-01",
                               tz = "UTC") else Sys.time()
man <- paste0("{\"created\":\"", format(t, "%Y-%m-%dT%H:%M:%SZ", tz = "UTC"),
              "\",\"files\":[", paste(ent, collapse = ","),
              "],\"format\":\"noqtis-capsule-1\"}")
mraw <- charToRaw(man)

k <- bl("fipskg")(alg)
s <- bl("cpssign")(mraw, k, ctx = "noqtis-capsule-1")
stopifnot(bl("cpsvrf")(mraw, s, bl("fipspubkey")(k), ctx = "noqtis-capsule-1"))
pk <- unhex(k$public)
seal <- paste0("{\"alg\":", jstr(alg),
               ",\"context\":\"noqtis-capsule-1\",\"format\":\"noqtis-seal-1\"",
               ",\"manifest_sha256\":\"", bl("csha256")(mraw),
               "\",\"public_key\":\"", b64(pk),
               "\",\"signature\":\"", b64(unhex(s$signature)),
               "\"}")
writeBin(mraw, file.path(dir, "noqtis.json"))
writeBin(charToRaw(seal), file.path(dir, "noqtis.sig"))
b <- b64(pk)
lines <- substring(b, seq(1L, nchar(b), 64L),
                   pmin(seq(64L, nchar(b) + 63L, 64L), nchar(b)))
writeBin(charToRaw(paste0("noqtis-key-1 ", alg, " pub\n",
                          paste0(lines, "\n", collapse = ""))), args[[3L]])
cat(sprintf("blseal: sealed %s with %s (rmoriebricklayer %s)\n", dir, alg,
            as.character(utils::packageVersion("rmoriebricklayer"))))
