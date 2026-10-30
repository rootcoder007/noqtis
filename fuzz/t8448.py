import re,sys
t=open(sys.argv[1]).read()
def sect(a,b):
    i=t.index("\n"+a)
    j=t.index("\n"+b,i)
    return t[i:j]
def blob(s, head, k, label):
    i=0
    for _ in range(k):
        i=s.index(head,i)+len(head)
    i=s.index(label+" (",i)
    m=re.match(r"(\d+) octets\):",s[i+len(label)+2:])
    n=int(m.group(1))
    i=s.index("octets):",i)+8
    out=[]
    for line in s[i:].split("\n"):
        st=line.strip()
        if st.startswith("Thomson") or st.startswith("RFC 8448") or st=="" or st=="\f":
            if len(out)>=n: break
            continue
        for tok in st.split():
            if len(out)>=n: break
            if not re.fullmatch(r"[0-9a-f]{2}",tok): raise Exception((label,tok))
            out.append(int(tok,16))
        if len(out)>=n: break
    assert len(out)==n,(label,len(out),n)
    return bytes(out)
s=sect("3.  Simple 1-RTT","4.  Resumed")
v={}
v["ch"]=blob(s,"{client}  construct a ClientHello",1,"ClientHello")
v["xsk"]=blob(s,"{client}  create an ephemeral x25519",1,"private key")
v["sh"]=blob(s,"{server}  send handshake record:",1,"complete record")
v["hkey"]=blob(s,"{server}  derive write traffic keys for handshake data:",1,"key expanded")
v["hiv"]=blob(s,"{server}  derive write traffic keys for handshake data:",1,"iv expanded")
v["akey"]=blob(s,"{server}  derive write traffic keys for application data:",1,"key expanded")
v["aiv"]=blob(s,"{server}  derive write traffic keys for application data:",1,"iv expanded")
fl=blob(s,"{server}  send handshake record:",2,"payload")
nst=blob(s,"{server}  send handshake record:",3,"payload")
app=blob(s,"{server}  send application_data record:",1,"payload")
o=open(sys.argv[2],"w")
o.write("""/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* RFC 8448 section 3, taken from tests/vectors/tls/rfc8448.txt by
 * fuzz/t8448.py: the client's ClientHello and X25519 key, the server's
 * ServerHello record and its write keys, for fuzz/ftls.c. */
#ifndef NQT8448_H
#define NQT8448_H

#include <stdint.h>

""")
for k in ["ch","xsk","sh","hkey","hiv","akey","aiv"]:
    b=v[k]
    o.write("static const uint8_t r8%s[%d] = {\n" % (k,len(b)))
    for i in range(0,len(b),12):
        o.write("    "+", ".join("0x%02x"%x for x in b[i:i+12])+",\n")
    o.write("};\n\n")
o.write("#endif /* NQT8448_H */\n")
o.close()
# seeds: mode, then pieces (key byte, type byte, length, bytes)
def piece(key,ty,b): return bytes([key,ty,len(b)>>8,len(b)&255])+b
import os
d=sys.argv[3]; os.makedirs(d,exist_ok=True)
open(d+"/trace","wb").write(bytes([2])+piece(0,22,fl)+piece(1,22,nst)+piece(1,23,app)+piece(1,21,b"\x01\x00"))
# the flight cut into one record per message
msgs=[]; i=0
while i<len(fl):
    n=(fl[i+1]<<16)|(fl[i+2]<<8)|fl[i+3]; msgs.append(fl[i:i+4+n]); i+=4+n
open(d+"/split","wb").write(bytes([2])+b"".join(piece(0,22,m) for m in msgs)+piece(1,23,app))
open(d+"/bytes","wb").write(bytes([2])+b"".join(piece(0,22,fl[j:j+5]) for j in range(0,len(fl),5)))
