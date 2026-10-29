# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#
# Checks a noqtis capsule with rmoriebricklayer alone: no noqtis code runs.
#
#   Rscript blchk.R <dir> <key.pub> [<TSA anchor, DER>]
#
# <key.pub> is a noqtis key file, or - to accept the seal's own key. What rmoriebricklayer checks, one row
# each: the seal's fields; that its public key is the given one; the
# SHA-256 of noqtis.json; the ML-DSA or SLH-DSA signature over its exact
# bytes under the seal's context (cpsvrf); each listed file's size and
# SHA-256 (sha256file); that no file is unlisted; and the timestamp
# (tsvrf over the signature bytes, under the anchor). SHA3-256 is not
# checked: rmoriebricklayer has no SHA3-256 of data. As noqtis does, a
# timestamp without an anchor fails, and so does an anchor without one.
#
# Exit 0 when every row passes, 1 when one fails, 2 on a usage error,
# 77 when rmoriebricklayer is not installed (CTest's skip code).

args <- commandArgs(trailingOnly = TRUE)
if (length(args) < 2L || length(args) > 3L) {
  cat("usage: Rscript blchk.R <dir> <key.pub> [<anchor.der>]\n")
  quit(status = 2L)
}
if (!requireNamespace("rmoriebricklayer", quietly = TRUE)) {
  cat("blchk: rmoriebricklayer is not installed\n")
  quit(status = 77L)
}
bl <- function(f) getExportedValue("rmoriebricklayer", f)
dir <- args[[1L]]
bad <- 0L
row <- function(check, ok, detail = "") {
  cat(sprintf("%-4s  %-16s  %s\n", if (ok) "ok" else "FAIL", check, detail))
  if (!ok) bad <<- bad + 1L
  invisible(ok)
}
rd <- function(p) readBin(p, "raw", file.size(p))
hex <- function(r) paste(format(as.hexmode(as.integer(r)), width = 2L),
                         collapse = "")

# the key file: "noqtis-key-1 <alg> pub", then base64 lines; "-" accepts
# the seal's own key, as noqtis check without -p does
pin <- NULL
if (args[[2L]] != "-") {
  kl <- readLines(args[[2L]], warn = FALSE)
  kh <- strsplit(kl[[1L]], " ", fixed = TRUE)[[1L]]
  if (length(kh) != 3L || kh[[1L]] != "noqtis-key-1" || kh[[3L]] != "pub") {
    cat("blchk: ", args[[2L]], " is not a noqtis public key file\n",
        sep = "")
    quit(status = 2L)
  }
  pin <- bl("jsb64dec")(paste(kl[-1L], collapse = ""))
}

sg <- bl("fromjs")(rawToChar(rd(file.path(dir, "noqtis.sig"))),
                   simplifyVector = FALSE)
need <- c("alg", "context", "format", "manifest_sha256", "public_key",
          "signature")
row("seal.fields", all(need %in% names(sg)) &&
      all(names(sg) %in% c(need, "timestamp")),
    paste(sort(names(sg)), collapse = " "))
row("seal.format", identical(sg$format, "noqtis-seal-1"), sg$format)
alg <- sg$alg
pk <- bl("jsb64dec")(sg$public_key)
sig <- bl("jsb64dec")(sg$signature)
if (is.null(pin)) {
  row("key", TRUE, "not pinned: accepted the public key in the seal")
} else {
  row("key", identical(kh[[2L]], alg) && identical(pk, pin),
      sprintf("%s, %d-byte key", alg, length(pk)))
}

man <- rd(file.path(dir, "noqtis.json"))
row("manifest.digest", identical(bl("csha256")(man), sg$manifest_sha256),
    "SHA-256 of noqtis.json")
s <- structure(list(scheme = alg, signature = hex(sig), prehash = "none"),
               class = c("bricklayer_signature", "list"))
ok <- bl("cpsvrf")(man, s, bl("fipskey")(alg, pk), ctx = sg$context)
row("signature", isTRUE(ok),
    sprintf("%s over noqtis.json, context \"%s\"", alg, sg$context))

m <- bl("fromjs")(rawToChar(man), simplifyVector = FALSE)
row("manifest.format", identical(m$format, "noqtis-capsule-1"), m$format)
listed <- character()
for (f in m$files) {
  p <- file.path(dir, f$path)
  listed <- c(listed, f$path)
  if (!file.exists(p)) {
    row("file", FALSE, paste0(f$path, ": missing"))
  } else if (file.size(p) != f$size) {
    row("file", FALSE, paste0(f$path, ": size differs"))
  } else {
    row("file", identical(bl("sha256file")(p), f$sha256),
        paste0(f$path, ": size and SHA-256 (SHA3-256 not checked)"))
  }
}
have <- list.files(dir, recursive = TRUE, all.files = TRUE,
                   no.. = TRUE)
have <- setdiff(have, c("noqtis.json", "noqtis.sig"))
for (e in setdiff(have, listed)) row("extra", FALSE, paste0(e, ": not listed"))

if (!is.null(sg$timestamp)) {
  if (length(args) < 3L) {
    row("timestamp", FALSE, "not checked: no TSA anchor given")
  } else {
    t <- bl("tsvrf")(bl("jsb64dec")(sg$timestamp), data = sig,
                     trust = rd(args[[3L]]))
    row("timestamp", isTRUE(t$ok),
        paste("RFC 3161 token over the signature; genTime",
              format(t$time, "%Y-%m-%dT%H:%M:%SZ", tz = "UTC")))
    if (!isTRUE(t$ok)) print(t$checks[!t$checks$ok, ])
  }
} else if (length(args) == 3L) {
  row("timestamp", FALSE, "no timestamp in the seal, but an anchor given")
}

cat(sprintf("%s: %s (rmoriebricklayer %s)\n", dir,
            if (bad == 0L) "OK" else sprintf("FAILED (%d)", bad),
            as.character(utils::packageVersion("rmoriebricklayer"))))
quit(status = if (bad == 0L) 0L else 1L)
