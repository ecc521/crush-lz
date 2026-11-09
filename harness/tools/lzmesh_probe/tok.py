# Token parser for raw op/extra streams (flag 0); returns literal positions in output order
def rdex(ex, i):
    b=ex[i]; i+=1
    if b==0xff:
        v=int.from_bytes(ex[i:i+4],'little'); i+=4; return v,i
    return b,i
def tokens(ops, ex, dists=None):
    ei=0; out=[]
    for n,op in enumerate(ops):
        lc=op>>6; mc=op&63
        if lc==3:
            v,ei=rdex(ex,ei); nl=(4 if n==0 else 3)+v
        else: nl=lc+(1 if n==0 else 0)
        if mc<32:
            kind=mc>>3; l=mc&7
            if l==7: v,ei=rdex(ex,ei); ml=9+v
            else: ml=l+2
            out.append((nl,'rep',kind,ml))
        elif mc==63:
            v,ei=rdex(ex,ei); out.append((nl,'new',None,33+v))
        else: out.append((nl,'new',None,mc-30))
    return out
def litpos(ops, ex, usize):
    pos=0; lp=[]
    for nl,t,k,ml in tokens(ops,ex):
        lp+=list(range(pos,min(pos+nl,usize))); pos+=nl+ml
    return lp
