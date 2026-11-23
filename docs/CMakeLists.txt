# SPDX-License-Identifier: LGPL-3.0-or-later
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
  "nqsignmu:nqsmu,nqvrfymu"
  "nqsini:nqvini,nqsupd,nqsfin,nqvfin"
  "nqpwenc:nqpwdec,nqpwenc2,nqpbkdf2"
  "nqkseal:nqkopen"
  "nqkfeini:nqkfeupd,nqkfefin,nqkfdini,nqkfdupd,nqkfdfin"
  "nqrep:nqrepn,nqrepi,nqrepfree"
  "nqtsput:nqtsreq"
  "nqinsp:nqfiles"
  "nqdsse:nqdssevrfy"
  "nqcard:nqcardvrfy"
  "nqprove:nqchkp"
  "nqseal2:nqcapid,nqseal3"
  "nqerr:nqver"
  "nqarmenc:nqarmlen,nqarmdec"
  "nqcmssign:nqcmsvrfy,nqcmsenc,nqcmsdec"
  "nqersput:nqersreq"
  "nqkmeini:nqkmhlen,nqkmpeek,nqkmeupd,nqkmefin,nqkmdini,nqkmdupd,nqkmdfin"
  "nqksadd:nqkslist,nqksget,nqkscert,nqkscput,nqkstrust,nqksdel,nqksexp,nqksimp,nqksurl"
  "nqkstmt:nqkexp"
  "nqkt:nqktini,nqktupd,nqktfin"
  "nqp11open:nqp11close,nqp11why,nqp11toks,nqp11login,nqp11keys,nqp11pub,nqp11sign,nqp11dec,nqp11gen,nqp11seal"
  "nqpgpgen:nqpgpinfo,nqpgpsign,nqpgpvrfy,nqpgpenc,nqpgpdec,nqpgparm,nqpgpdearm"
  "nqrand:nqsetrng"
  "nqseal:nqsealwhy"
  "nqsivenc:nqsivdec,nqgsivenc,nqgsivdec,nqcha20"
  "nqsmsign:nqsmvrfy,nqsmenc,nqsmdec"
  "nqx5self:nqx5kem,nqx5info"
  "nqtlnew:nqtlct,nqtlhs,nqtlwr,nqtlrd,nqtlend,nqtlwhy,nqtlfree"
  "nqdnew:nqdparse,nqdload,nqdjson,nqdsave,nqdrfree,nqdlen,nqdat,nqdkey,nqdput,nqdset,nqddel,nqdsrc,nqdsha"
  "nqdchk:nqdrepn,nqdrepi,nqdrepj,nqdrepfree"
  "nqdinfer:nqdschk"
  "nqdstats:nqddrift,nqddriftat,nqddcal"
  "nqdcommit:nqdreveal,nqdcite"
  "nqdpack:nqdunpack"
  "nqdchunk:nqdpiece,nqdpieceat"
  "nqdaddr:nqdvrfy,nqdfld,nqdrslv,nqdrsp,nqdwb"
  "nqsetal:nqdsetal"
  "nqsettmp:nqdsettmp")
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
