# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# The mdoc manual pages in man/, installed with the library so that
# `man noqtis`, `man nqsign` and `man nqvrfy` work offline. A page that
# documents several functions is also installed under each other name.
set(NQMANDIR ${PROJECT_SOURCE_DIR}/man)

file(GLOB NQMAN1 ${NQMANDIR}/*.1)
file(GLOB NQMAN3 ${NQMANDIR}/*.3)
file(GLOB NQMAN5 ${NQMANDIR}/*.5)
install(FILES ${NQMAN1} DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)
install(FILES ${NQMAN3} DESTINATION ${CMAKE_INSTALL_MANDIR}/man3)
install(FILES ${NQMAN5} DESTINATION ${CMAKE_INSTALL_MANDIR}/man5)

# page:other names
set(NQMANAKA
  "nqsign:nqsignd,nqvrfy,nqskg,nqskgd,nqssize,nqsname,nqsfind"
  "nqenc:nqencd,nqdec,nqkkg,nqkkgd,nqksize,nqkname,nqkfind"
  "nqhash:nqhini,nqhupd,nqhfin,nqhlen,nqhmac"
  "nqrep:nqrepn,nqrepi,nqrepfree"
  "nqtsput:nqtsreq"
  "nqprove:nqchkp"
  "nqseal2:nqcapid"
  "nqerr:nqver")
foreach(e ${NQMANAKA})
  string(REPLACE ":" ";" e "${e}")
  list(GET e 0 page)
  list(GET e 1 names)
  string(REPLACE "," ";" names "${names}")
  foreach(n ${names})
    install(FILES ${NQMANDIR}/${page}.3 DESTINATION
            ${CMAKE_INSTALL_MANDIR}/man3 RENAME ${n}.3)
  endforeach()
endforeach()
