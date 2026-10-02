import json, socket, struct, sys, zlib, uuid
HOST, PORT, NAME = sys.argv[1], int(sys.argv[2]), sys.argv[3]
def wv(n):
    n &= 0xFFFFFFFF; o=b''
    while True:
        b=n&0x7F; n>>=7; o+=bytes([b|(0x80 if n else 0)])
        if not n: return o
def rd(s):
    num=0; sh=0
    while True:
        b=s.recv(1)
        if not b: raise EOFError("closed")
        b=b[0]; num|=(b&0x7F)<<sh
        if not (b&0x80): return num
        sh+=7
s = socket.create_connection((HOST,PORT), timeout=15)
hb = HOST.encode()
hs = b'\x00'+wv(767)+wv(len(hb))+hb+struct.pack('>H',PORT)+wv(2)
s.sendall(wv(len(hs))+hs)
nm = NAME.encode()
ls = b'\x00'+wv(len(nm))+nm+uuid.uuid4().bytes
s.sendall(wv(len(ls))+ls)
comp=False
for step in range(4):
    ln = rd(s); raw=b''
    while len(raw)<ln:
        c=s.recv(ln-len(raw))
        if not c: raise EOFError("closed mid-packet")
        raw+=c
    if comp:
        dlen = rd_bytes = raw
        # parse data length varint from raw
        num=0; sh=0; i=0
        while True:
            b=raw[i]; num|=(b&0x7F)<<sh; i+=1
            if not (b&0x80): break
            sh+=7
        payload = zlib.decompress(raw[i:]) if num>0 else raw[i:]
    else:
        payload = raw
    num=0; sh=0; i=0
    while True:
        b=payload[i]; num|=(b&0x7F)<<sh; i+=1
        if not (b&0x80): break
        sh+=7
    pid=num; body=payload[i:]
    if pid==0x03:
        th=body[0]; print("  [%s] Set Compression threshold=%d" % (NAME,th)); comp=True; continue
    if pid==0x00:
        slen=0; sh2=0; k=0
        while True:
            b=body[k]; slen|=(b&0x7F)<<sh2; k+=1
            if not (b&0x80): break
            sh2+=7
        reason=body[k:k+slen].decode('utf-8','replace')
        print("  [%s] DISCONNECT -> %s" % (NAME, reason))
        try:
            j=json.loads(reason)
            if isinstance(j,dict) and 'translate' in j: print("  [%s]   translate=%s" % (NAME,j['translate']))
        except Exception: pass
        break
    if pid==0x02:
        print("  [%s] LOGIN SUCCESS (服务端接受登录，白名单通过)" % NAME)
        break
s.close()
