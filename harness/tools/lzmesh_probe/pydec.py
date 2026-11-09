# Bit reader, canonical Huffman and lane geometry helpers for meshdec.py
import struct
from tok import tokens
def bitsof(pl): return ''.join(format(x,'08b')[::-1] for x in pl)
class BR:
    def __init__(s,bits,p=0): s.b=bits; s.p=p
    def msb(s,n): v=int(s.b[s.p:s.p+n],2) if n else 0; s.p+=n; return v
    def lsb(s,n): v=int(s.b[s.p:s.p+n][::-1],2) if n else 0; s.p+=n; return v
def canon(lens):
    # lens: {sym: len}; returns decode dict code-string -> sym
    out={}; code=0; prev=0
    for sym in sorted((k for k in lens if lens[k]), key=lambda k:(lens[k],k)):
        code<<=lens[sym]-prev; prev=lens[sym]
        out[format(code,'0%db'%prev)]=sym; code+=1
    return out
def hsym(br,tab):
    for l in range(1,17):
        k=br.b[br.p:br.p+l]
        if k in tab: br.p+=l; return tab[k]
    raise ValueError('bad code at %d'%br.p)
def lane_geom(pl,lane0):
    E=len(pl)-9; w=pl[E-1]>>3; st=E-max(4,(7*w+5+7)//8)
    br=BR(bitsof(pl[st:E])); f=[br.lsb(w) for _ in range(7)]
    starts=[lane0]; pos=lane0+f[0]
    for k in range(1,7): starts.append(pos); pos+=f[k]
    starts.append(pos)
    return starts, starts[1:]+[st], st
def lanes(pl,lane0,nlits,dbg=None):
    starts,ends,tr=lane_geom(pl,lane0)
    brs=[BR(bitsof(pl[a:b])) for a,b in zip(starts,ends)]
    h=brs[0]
    cl={v:h.lsb(3) for v in range(11)}
    cls=[h.msb(2) for _ in range(16)]
    syms=[]
    for hi in range(16):
        if cls[hi]&2: syms+=[hi*16+lo for lo in range(8)]
        if cls[hi]&1: syms+=[hi*16+lo for lo in range(8,16)]
    ctab=canon(cl)
    lens={sym:hsym(brs[j%8],ctab) for j,sym in enumerate(syms)}
    tab=canon(lens)
    if dbg is not None: dbg.update(cl=cl,cls=cls,lens=lens)
    return [hsym(brs[i%8],tab) for i in range(nlits)]
