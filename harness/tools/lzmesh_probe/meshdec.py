# Reference LZMESH block decoder (black-box derived). Handles coded blocks.
import struct
from pydec import BR, bitsof, canon, hsym, lane_geom
from tok import rdex
def table(brs):
    h=brs[0]
    cl={v:h.lsb(3) for v in range(11)}; cls=[h.msb(2) for _ in range(16)]
    syms=[]
    for hi in range(16):
        if cls[hi]&2: syms+=[hi*16+lo for lo in range(8)]
        if cls[hi]&1: syms+=[hi*16+lo for lo in range(8,16)]
    ctab=canon(cl); lens={sym:hsym(brs[j%8],ctab) for j,sym in enumerate(syms)}
    return canon(lens)
def streams(pl,s1):
    modes=pl[-9]|pl[-8]<<8
    nops,nex,nlits=struct.unpack('<HHH',pl[-7:-1]); nd=pl[-1]
    counts=[nlits,nops,nex,nd]; m=[(modes>>(3*i))&7 for i in range(4)]
    # The u8 dist count is only the low byte; the real count comes from the ops.
    out=[None]*4; R=s1-9; brs=None
    if R < len(pl)-9:
        starts,ends,tr=lane_geom(pl,R)
        brs=[BR(bitsof(pl[a:c])) for a,c in zip(starts,ends)]
    p=0
    for i in range(4):
        if i==3:
            counts[3]=sum(1 for o in out[1] if (o&63)>=32)
            assert counts[3]&255==nd
        if m[i]==0: out[i]=list(pl[p:p+counts[i]]); p+=counts[i]
        elif m[i]==1: out[i]=[pl[p]]*counts[i]; p+=1
        else:
            tab=table(brs); out[i]=[hsym(brs[j%8],tab) for j in range(counts[i])]
    assert p==R, (p,R,m)
    return out,brs,m
def decode_block(pl,s1,usize,prev=b'',st=None):
    (lits,ops,exs,dists),brs,m=streams(pl,s1)
    exs=bytes(exs)
    out=bytearray(prev); base=len(prev); li=ei=di=0; reps=st['reps'] if st and 'reps' in st else [1,1,1,1]; j=0
    for n,op in enumerate(ops):
        lc=op>>6; mc=op&63
        if lc==3: v,ei=rdex(exs,ei); nl=(4 if n==0 and not base else 3)+v
        else: nl=lc+(1 if n==0 and not base else 0)
        out+=bytes(lits[li:li+nl]); li+=nl
        if mc<32:
            l=mc&7
            if l==7: v,ei=rdex(exs,ei); ml=9+v
            else: ml=l+2
            r=mc>>3; D=reps[r]; reps=[D]+reps[:r]+reps[r+1:]
        else:
            if mc==63: v,ei=rdex(exs,ei); ml=33+v
            else: ml=mc-30
            bb=dists[di]; di+=1; k=bb>>3; low=bb&7
            if k==0: D=low+1
            else: a=brs[j%8].lsb(k)|(1<<k); D=((a-1)<<3|low)+1
            j+=1
            reps=[D]+reps[:3]
        for i in range(ml): out.append(out[-D])
        if len(out)-base>=usize: break
    if st is not None: st['reps']=reps
    return bytes(out[base:base+usize])
