#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wss_mc_probe · 经 WebSocket 打 Minecraft 协议的最小客户端探针

链路：本机 -> [可选 CONNECT 代理] -> TLS -> wss:// -> WebSocket 二进制帧 -> MC 协议字节流

支持两种模式：
  status  MC handshake(next=1) + status request  -> 期望收到 1.21.1 的 status JSON
  login   MC handshake(next=2) + login start     -> 期望 LOGIN SUCCESS 或 DISCONNECT<原因>

用法：
  python3 wss_mc_probe.py status <host> <port> [--tls] [--proxy http://h:p] [--host-header H]
  python3 wss_mc_probe.py login  <host> <port> <name> [--tls] [--proxy http://h:p]

纯标准库（socket / ssl / base64 / hashlib / struct / json / uuid / zlib）。
"""
import base64
import hashlib
import json
import os
import socket
import ssl
import struct
import sys
import uuid
import zlib

GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
OP_BIN = 0x2
OP_CLOSE = 0x8
OP_PING = 0x9
OP_PONG = 0xA


def wv(n):
    n &= 0xFFFFFFFF
    o = b''
    while True:
        b = n & 0x7F
        n >>= 7
        o += bytes([b | (0x80 if n else 0)])
        if not n:
            return o


def read_varint(buf, i):
    num = 0
    sh = 0
    while True:
        b = buf[i]
        i += 1
        num |= (b & 0x7F) << sh
        if not (b & 0x80):
            return num, i
        sh += 7


class WsMcError(Exception):
    pass


class WsMcClient:
    """把 WebSocket 二进制帧抽象成一条字节流，并在其上跑 MC 协议。"""

    def __init__(self, host, port, tls=False, proxy=None, host_header=None, timeout=20):
        self.host = host
        self.port = port
        self.tls = tls
        self.timeout = timeout
        self.buf = b''            # MC 字节流缓冲（跨帧重组）
        self.frames_total = 0
        self.bytes_total = 0
        self.ws_accept = None
        self.tls_info = None
        self.host_header = host_header or ("%s:%d" % (host, port))

        raw = socket.create_connection(self._connect_target(proxy), timeout=timeout)

        if proxy:
            self._do_connect(raw, host, port)
        if tls:
            ctx = ssl.create_default_context()
            raw = ctx.wrap_socket(raw, server_hostname=host)
            self.tls_info = {
                "version": raw.version(),
                "cipher": raw.cipher()[0] if raw.cipher() else None,
                "peer_cn": (raw.getpeercert() or {}).get("subject"),
            }
        self.sock = raw
        self._ws_handshake()

    # ------ 底层连接 ------
    def _connect_target(self, proxy):
        if not proxy:
            return (self.host, self.port)
        # proxy 形如 http://host:port
        p = proxy.split("://", 1)[-1]
        ph, _, pp = p.rpartition(":")
        return (ph, int(pp))

    def _do_connect(self, sock, host, port):
        req = ("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n"
               "Proxy-Connection: keep-alive\r\n\r\n" % (host, port, host, port))
        sock.sendall(req.encode())
        data = b''
        while b"\r\n\r\n" not in data:
            c = sock.recv(4096)
            if not c:
                raise WsMcError("CONNECT 阶段连接被关闭")
            data += c
        line = data.split(b"\r\n", 1)[0].decode("latin-1")
        if " 200" not in line:
            raise WsMcError("CONNECT 被代理拒绝: %s" % line)
        self.connect_line = line

    # ------ WS 握手 ------
    def _ws_handshake(self):
        key = base64.b64encode(os.urandom(16)).decode()
        self.ws_key = key
        req = ("GET / HTTP/1.1\r\n"
               "Host: %s\r\n"
               "Upgrade: websocket\r\n"
               "Connection: Upgrade\r\n"
               "Sec-WebSocket-Key: %s\r\n"
               "Sec-WebSocket-Version: 13\r\n"
               "\r\n" % (self.host_header, key))
        self.sock.sendall(req.encode())
        data = b''
        while b"\r\n\r\n" not in data:
            c = self.sock.recv(4096)
            if not c:
                raise WsMcError("WS 握手阶段连接被关闭")
            data += c
        head, _, rest = data.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        status = lines[0].decode("latin-1")
        self.ws_status_line = status
        if " 101" not in status:
            raise WsMcError("WS 升级失败: %s" % status)
        self.ws_headers = {}
        for ln in lines[1:]:
            if b":" in ln:
                k, _, v = ln.partition(b":")
                self.ws_headers[k.strip().lower().decode()] = v.strip().decode()
        expect = base64.b64encode(hashlib.sha1(key.encode() + GUID).digest()).decode()
        got = self.ws_headers.get("sec-websocket-accept")
        if got != expect:
            raise WsMcError("Sec-WebSocket-Accept 校验失败 got=%r expect=%r" % (got, expect))
        self.ws_accept = got
        self.buf = rest

    # ------ 帧读写 ------
    def _recv_exact(self, n):
        out = b''
        while len(out) < n:
            c = self.sock.recv(n - len(out))
            if not c:
                raise WsMcError("字节流结束")
            out += c
        return out

    def _read_frame(self):
        hdr = self._recv_exact(2)
        b0, b1 = hdr[0], hdr[1]
        op = b0 & 0x0F
        masked = b1 & 0x80
        ln = b1 & 0x7F
        if ln == 126:
            ln = struct.unpack(">H", self._recv_exact(2))[0]
        elif ln == 127:
            ln = struct.unpack(">Q", self._recv_exact(8))[0]
        mask = self._recv_exact(4) if masked else None
        payload = self._recv_exact(ln) if ln else b''
        if mask:
            payload = bytes(payload[i] ^ mask[i & 3] for i in range(len(payload)))
        return op, payload

    def _send_frame(self, op, payload):
        n = len(payload)
        hdr = bytearray([0x80 | op])
        # 客户端帧必须带掩码，长度字节的高位要置 1（RFC6455 §5.2）
        if n < 126:
            hdr.append(0x80 | n)
        elif n < 65536:
            hdr.append(0x80 | 126)
            hdr += struct.pack(">H", n)
        else:
            hdr.append(0x80 | 127)
            hdr += struct.pack(">Q", n)
        # 客户端帧必须带掩码（RFC6455 §5.1）
        mask = os.urandom(4)
        hdr += mask
        masked = bytes(payload[i] ^ mask[i & 3] for i in range(n))
        self.sock.sendall(bytes(hdr) + masked)

    def send_mc(self, data):
        self._send_frame(OP_BIN, data)

    def recv_mc_exact(self, n):
        """从 WS 帧流里凑满 n 字节 MC 数据。"""
        while len(self.buf) < n:
            op, payload = self._read_frame()
            if op == OP_PING:
                self._send_frame(OP_PONG, payload)
                continue
            if op == OP_PONG:
                continue
            if op == OP_CLOSE:
                raise WsMcError("收到 WS close 帧")
            self.frames_total += 1
            self.bytes_total += len(payload)
            self.buf += payload
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def recv_mc_packet(self):
        """按 MC 的 VarInt 长度前缀读一个包，返回 (包长, 包体)。"""
        hdr = b''
        while True:
            hdr += self.recv_mc_exact(1)
            if not (hdr[-1] & 0x80):
                break
        ln, _ = read_varint(hdr, 0)
        body = self.recv_mc_exact(ln) if ln else b''
        return ln, body


def mc_handshake(host, port, state):
    hb = host.encode()
    return b'\x00' + wv(767) + wv(len(hb)) + hb + struct.pack('>H', port) + wv(state)


def main():
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    flags = [a for a in sys.argv[1:] if a.startswith('--')]
    if len(args) < 3:
        print(__doc__)
        return 2
    mode, host, port = args[0], args[1], int(args[2])
    name = args[3] if len(args) > 3 else None

    usetls = '--tls' in flags
    proxy = None
    host_header = None
    for f in flags:
        if f.startswith('--proxy='):
            proxy = f.split('=', 1)[1]
        if f.startswith('--host-header='):
            host_header = f.split('=', 1)[1]

    print("=== ws-bridge MC 探针 · 模式=%s ===" % mode)
    print("目标   : %s:%d%s" % (host, port, "  (TLS)" if usetls else "  (明文)"))
    print("代理   : %s" % (proxy or "(直连，无 CONNECT)"))
    print()

    c = WsMcClient(host, port, tls=usetls, proxy=proxy, host_header=host_header)
    if proxy:
        print("[1] CONNECT   : %s" % c.connect_line)
    print("[%d] WS 握手   : %s" % (2 if proxy else 1, c.ws_status_line))
    print("     Upgrade      : %s" % c.ws_headers.get('upgrade'))
    print("     Connection   : %s" % c.ws_headers.get('connection'))
    print("     Sec-WS-Accept: %s  (校验通过)" % c.ws_accept)
    if c.tls_info:
        print("     TLS          : %s / %s" % (c.tls_info['version'], c.tls_info['cipher']))
        print("     TLS 对端证书 : %s" % (c.tls_info['peer_cn'],))
    print()

    if mode == 'status':
        c.send_mc(wv(len(mc_handshake(host, port, 1))) + mc_handshake(host, port, 1))
        c.send_mc(wv(1) + b'\x00')          # status request
        print("[3] 已发送 MC handshake(next=1) + status request（封装在 WS 二进制帧里）")
        ln, body = c.recv_mc_packet()
        pid, i = read_varint(body, 0)
        slen, i = read_varint(body, i)
        js = body[i:i + slen].decode('utf-8', 'replace')
        print("[4] 收到 MC status 响应帧（包长=%d, id=0x%02x）" % (ln, pid))
        print()
        print("--- raw status JSON ---")
        try:
            print(json.dumps(json.loads(js), ensure_ascii=False, indent=2))
        except Exception:
            print(js)
        print("--- assertions ---")
        try:
            d = json.loads(js)
            print("version.name     = %r  contains 1.21.1 -> %s"
                  % (d['version']['name'], '1.21.1' in d['version']['name']))
            print("version.protocol = %s" % d['version']['protocol'])
            print("players.max      = %s" % d['players']['max'])
            print("description      = %r" % d.get('description'))
        except Exception as e:
            print("解析失败:", e)
        print()
        print("[5] WS 帧统计: 收到 %d 帧 / %d 字节" % (c.frames_total, c.bytes_total))

    elif mode == 'login':
        if not name:
            print("login 模式需要 <name>"); return 2
        c.send_mc(wv(len(mc_handshake(host, port, 2))) + mc_handshake(host, port, 2))
        nm = name.encode()
        ls = b'\x00' + wv(len(nm)) + nm + uuid.uuid4().bytes
        c.send_mc(wv(len(ls)) + ls)
        print("[3] 已发送 MC handshake(next=2) + login start(name=%s)" % name)
        comp = False
        for step in range(5):
            ln, raw = c.recv_mc_packet()
            if comp:
                num, i = read_varint(raw, 0)
                payload = zlib.decompress(raw[i:]) if num > 0 else raw[i:]
            else:
                payload = raw
            pid, i = read_varint(payload, 0)
            body = payload[i:]
            if pid == 0x03:
                th = body[0]
                print("[4] Set Compression threshold=%d" % th)
                comp = True
                continue
            if pid == 0x00:
                slen, k = read_varint(body, 0)
                reason = body[k:k + slen].decode('utf-8', 'replace')
                print("[4] DISCONNECT -> %s" % reason)
                try:
                    j = json.loads(reason)
                    if isinstance(j, dict) and 'translate' in j:
                        print("     translate=%s" % j['translate'])
                except Exception:
                    pass
                break
            if pid == 0x02:
                print("[4] LOGIN SUCCESS (服务端接受登录，白名单通过) ★")
                break
        print()
        print("[5] WS 帧统计: 收到 %d 帧 / %d 字节" % (c.frames_total, c.bytes_total))
    else:
        print("未知模式:", mode)
        return 2

    try:
        c.sock.close()
    except Exception:
        pass
    return 0


if __name__ == '__main__':
    sys.exit(main())
