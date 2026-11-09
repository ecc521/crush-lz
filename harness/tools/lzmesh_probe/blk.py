import struct
def blocks(c):
    p=0; out=[]
    while p<len(c):
        t=c[p]
        if t==0xff: out.append(('eos',p)); p+=1; break
        if t==0:
            u=struct.unpack_from('<I',c,p+1)[0]; out.append(('raw',u)); p+=5+u
        elif t==1:
            u,s1,s2=struct.unpack_from('<IHH',c,p+1)
            pl=c[p+9:p+9+s2]; tail=c[p+9+s2]
            out.append(('comp',u,s1,s2,pl,tail)); p+=9+s2+1
        else: out.append(('?',t,p)); break
    out.append(('end',p,len(c)))
    return out
def show(c):
    for b in blocks(c):
        if b[0]=='comp':
            u,s1,s2,pl,tail=b[1:]
            print(f' comp usize={u} s1={s1} s2={s2} tail={tail:02x}')
            print('  [0:s1]  ',pl[:s1].hex(' '))
            print('  [s1:s2] ',pl[s1:].hex(' '))
        else: print(' ',b)
