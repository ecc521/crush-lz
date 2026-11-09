# Decode Apple's encoding of corpus files with meshdec.py:
#   python3 check_corpus.py FIRST LAST MAXBYTES
# CORPUS overrides the corpus directory.
from meshdec import *
from blk import blocks
from ap import enc
import os, sys, struct, time
from collections import Counter
D=os.environ.get('CORPUS', os.path.join(os.path.dirname(os.path.abspath(__file__)), '../../../corpus/segments/main'))
files=sorted(os.listdir(D))
tot=Counter()
for fn in files[int(sys.argv[1]):int(sys.argv[2])]:
    s=open(os.path.join(D,fn),'rb').read()[:int(sys.argv[3])]
    out=b''; st={}; ok=True; nb=0; t=time.time(); info=[]
    for b in blocks(enc(s)):
        if b[0]=='raw': out+=s[len(out):len(out)+b[1]]; continue
        if b[0]!='comp': continue
        u,s1,s2,pl,_=b[1:]; nb+=1
        nops,nex,nl=struct.unpack('<HHH',pl[-7:-1])
        info.append((u,nops,pl[-1],hex(pl[-9]|pl[-8]<<8)))
        try: d=decode_block(pl,s1,u,out,st)
        except Exception as e: d=repr(e)
        want=s[len(out):len(out)+u]
        if d!=want: ok=False; print(fn,'block',nb,info[-1],d if isinstance(d,str) else 'mismatch'); break
        out+=want
    print(fn[:40],len(s),ok,nb,info[:3],'%.1fs'%(time.time()-t)); tot[ok]+=1
print(tot)
