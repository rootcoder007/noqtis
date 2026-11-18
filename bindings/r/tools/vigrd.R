# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Reads a package's help pages and writes, for each page, what a vignette
# generator needs: aliases, title, the first paragraph of the description and
# the example code as R CMD check runs it.
#   Rscript vigrd.R <package dir> <out.json>
a <- commandArgs(TRUE)
pkg <- a[1L]
out <- a[2L]
esc <- function(s) {
  s <- gsub("\\", "\\\\", s, fixed = TRUE)
  s <- gsub("\"", "\\\"", s, fixed = TRUE)
  s <- gsub("\t", "\\t", s, fixed = TRUE)
  s <- gsub("\r", "", s, fixed = TRUE)
  gsub("\n", "\\n", s, fixed = TRUE)
}
txt <- function(rd, tag) {
  i <- which(vapply(rd, function(x) identical(attr(x, "Rd_tag"), tag), NA))
  if (!length(i)) return("")
  tf <- tempfile()
  on.exit(unlink(tf))
  x <- rd[[i[1L]]]
  s <- paste(utils::capture.output(tools::Rd2txt(
    structure(list(x), class = "Rd"), fragment = TRUE,
    options = list(underline_titles = FALSE, width = 10000L,
                   code_quote = TRUE, itemBullet = "* "))), collapse = "\n")
  s
}
fs <- sort(list.files(file.path(pkg, "man"), pattern = "[.]Rd$", full.names = TRUE))
rows <- character(0)
for (f in fs) {
  rd <- tools::parse_Rd(f, permissive = TRUE)
  tags <- vapply(rd, function(x) attr(x, "Rd_tag"), "")
  al <- vapply(rd[tags == "\\alias"], function(x) paste(unlist(x), collapse = ""), "")
  kw <- vapply(rd[tags == "\\keyword"], function(x) paste(unlist(x), collapse = ""), "")
  if ("internal" %in% kw) next
  ti <- gsub("\\s+", " ", trimws(paste(unlist(rd[tags == "\\title"]), collapse = "")))
  de <- txt(rd, "\\description")
  de <- trimws(strsplit(sub("^Description:\\s*", "", de), "\n[ \t]*\n")[[1L]])
  de <- de[nzchar(de) & !grepl("^Description:$", de)]
  de <- if (length(de)) gsub("\\s+", " ", de[1L]) else ""
  ex <- ""
  if ("\\examples" %in% tags) {
    tf <- tempfile(fileext = ".R")
    tools::Rd2ex(rd, tf, commentDontrun = TRUE, commentDonttest = FALSE)
    if (file.exists(tf)) {
      l <- readLines(tf, warn = FALSE)
      k <- grep("^### \\*\\* Examples", l)
      if (length(k)) l <- l[-seq_len(k[1L])]
      l <- l[!grepl("^## (No test|End\\(No test\\)|Don't show|End\\(Don't show\\))", l)]
      while (length(l) && !nzchar(trimws(l[1L]))) l <- l[-1L]
      while (length(l) && !nzchar(trimws(l[length(l)]))) l <- l[-length(l)]
      ex <- paste(l, collapse = "\n")
      unlink(tf)
    }
  }
  rows[length(rows) + 1L] <- sprintf(
    "{\"file\":\"%s\",\"aliases\":[%s],\"title\":\"%s\",\"desc\":\"%s\",\"ex\":\"%s\"}",
    esc(basename(f)), paste(sprintf("\"%s\"", esc(al)), collapse = ","),
    esc(ti), esc(de), esc(ex))
}
writeLines(c("[", paste(rows, collapse = ",\n"), "]"), out, useBytes = TRUE)
cat(length(rows), "pages ->", out, "\n")
