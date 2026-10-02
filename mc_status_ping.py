import json, socket, struct, sys, time

HOST = sys.argv[1]; PORT = int(sys.argv[2])

def varint(n):
    n &= 0xFFFFFFFF
    out = b''
    while True:
        b = n & 0x7F; n >>= 7
        out += bytes([b | (0x80 if n else 0)])
        if not n: return out

def read_varint(sock):
    num = 0; shift = 0
    while True:
        b = sock.recv(1)
        if not b: raise EOFError("closed")
        b = b[0]
        num |= (b & 0x7F) << shift
        if not (b & 0x80): return num
        shift += 7

def read_exact(sock, n):
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk: raise EOFError("closed")
        buf += chunk
    return buf

t0 = time.time()
s = socket.create_connection((HOST, PORT), timeout=12)
t_conn = time.time()
print("TCP connect   : OK  %.0f ms  ->  %s:%d" % ((t_conn-t0)*1000, HOST, PORT))

host_b = HOST.encode()
hs = (b'\x00' + varint(767) + varint(len(host_b)) + host_b +
      struct.pack('>H', PORT) + varint(1))
s.sendall(varint(len(hs)) + hs)
s.sendall(varint(1) + b'\x00')

length = read_varint(s)
pid = read_varint(s)
slen = read_varint(s)
data = read_exact(s, slen)
t_resp = time.time()
print("status RTT    : %.0f ms" % ((t_resp - t0)*1000))
j = json.loads(data.decode('utf-8'))
print("--- raw status JSON ---")
print(json.dumps(j, ensure_ascii=False, indent=2))
print("--- assertions ---")
print("version.name      = %r   contains 1.21.1 -> %s" % (j['version']['name'], '1.21.1' in j['version']['name']))
print("version.protocol  = %s" % j['version']['protocol'])
print("players.online    = %s" % j['players']['online'])
print("players.max       = %s   ==32 -> %s" % (j['players']['max'], j['players']['max'] == 32))
desc = j.get('description')
if isinstance(desc, dict):
    txt = desc.get('text','') + ''.join(e.get('text','') for e in desc.get('extra',[]))
else:
    txt = str(desc)
print("description       = %r" % txt)
print("desc 非空         -> %s" % (bool(txt.strip()),))
s.close()
