#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ws-bridge · WebSocket(RFC6455) ↔ TCP 双向桥（**服务端组件**）

用途：放在**你自己服务器**上的那一半 —— 把被 HTTP 反向代转发过来的 WebSocket
      二进制帧，还原成裸 TCP 字节流，再送去真正的服务（例如 Minecraft 服务端）。

    [公网入口：真证书 + HTTP 反向代理]      <- 这一层怎么搭见 README 的服务端部署章
            |  WebSocket 二进制帧（wss）
            v
    [ws-bridge 本进程]  --裸 TCP-->  [你的服务，例如 Minecraft 服务端]

    客户端那一半是本包里的 relay.py：本地裸 TCP 客户端 -> relay -> wss 入口。

设计要点
--------
* 纯 Python3 标准库，零第三方依赖，单文件。
* 服务端侧 RFC6455 实现：
    - HTTP Upgrade 握手（Sec-WebSocket-Key -> Sec-WebSocket-Accept，RFC6455 §4.2.2）
    - 帧编解码：基本帧头 + 7/16/64 位扩展长度
    - 客户端→服务端帧**必须**带掩码，收到即解掩码（RFC6455 §5.1/§5.3）
    - 服务端→客户端帧**不得**带掩码（RFC6455 §5.1）
    - 分片（continuation, opcode 0x0）拼接
    - ping(0x9) -> 自动回 pong(0xA)；pong(0xA) 忽略
    - close(0x8) -> 回 close 并结束该连接
* 字节流语义：上层协议通常自带长度前缀，因此 ws 帧的切分边界不影响正确性，
  桥只需保证**字节顺序**不变。
* 每条 ws 连接：一条线程读 ws→写 TCP，一条线程读 TCP→写 ws；
  ws 发送侧加锁，避免两线程交错写坏帧。
* 连接级异常只终止该连接，主循环不受影响。

配置（优先级：**命令行参数 > 环境变量 > 内置默认**）
--------
    --listen / LISTEN_ADDR     本进程监听地址，默认 127.0.0.1:25566
                               （反代就转发到这里；只监听回环，不直接对外暴露）
    --target / MC_TARGET       转发目标，默认 127.0.0.1:25565
                               **改成你自己的服务地址**，例如 127.0.0.1:25565（本机 MC）、
                               192.0.2.5:25565（同网段另一台）、或 unix 外的任意 host:port
    --connect-timeout / CONNECT_TIMEOUT   连目标超时秒数，默认 10
    --recv-chunk / RECV_CHUNK             单次读 TCP 的字节上限，默认 32768

例：
    python3 ws-bridge.py --listen 127.0.0.1:25566 --target 127.0.0.1:25565
    MC_TARGET=192.0.2.5:25565 python3 ws-bridge.py
"""

import base64
import hashlib
import os
import socket
import struct
import sys
import threading
import time
import traceback

GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

OP_CONT = 0x0
OP_TEXT = 0x1
OP_BIN = 0x2
OP_CLOSE = 0x8
OP_PING = 0x9
OP_PONG = 0xA

MAX_PAYLOAD = 16 * 1024 * 1024  # 单帧上限，防异常大帧撑爆内存

_lock_out = threading.Lock()


# ---------------------------------------------------------------- 日志

def log(level, msg):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    sys.stdout.write("[%s] [%s] %s\n" % (ts, level, msg))
    sys.stdout.flush()


def logerr(level, msg):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    sys.stderr.write("[%s] [%s] %s\n" % (ts, level, msg))
    sys.stderr.flush()


# ---------------------------------------------------------------- 工具

def parse_addr(s, default_port):
    s = (s or "").strip()
    if not s:
        return None
    if ":" in s:
        h, _, p = s.rpartition(":")
        return (h, int(p))
    return (s, default_port)


def recv_exact(sock, n):
    """读满 n 字节；对端关闭返回 None。"""
    buf = b""
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except (ConnectionResetError, OSError):
            return None
        if not chunk:
            return None
        buf += chunk
    return buf


# ---------------------------------------------------------------- 握手

def do_handshake(conn, peer):
    """读 HTTP 请求，校验 WebSocket Upgrade，回 101。成功返回 True。"""
    conn.settimeout(15)
    data = b""
    while b"\r\n\r\n" not in data:
        try:
            chunk = conn.recv(4096)
        except (socket.timeout, OSError):
            chunk = b""
        if not chunk:
            log("WARN", "  [%s] 握手阶段连接中断" % peer)
            return False
        data += chunk
        if len(data) > 64 * 1024:
            log("WARN", "  [%s] 请求头过大，拒绝" % peer)
            return False

    head, _, _rest = data.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    if not lines:
        return False
    try:
        method, path, _ver = lines[0].decode("latin-1").split(" ", 2)
    except ValueError:
        log("WARN", "  [%s] 请求行无法解析" % peer)
        return False

    headers = {}
    for ln in lines[1:]:
        if b":" not in ln:
            continue
        k, _, v = ln.partition(b":")
        headers[k.strip().lower().decode("latin-1")] = v.strip().decode("latin-1")

    upgrade = headers.get("upgrade", "").lower()
    connection = headers.get("connection", "").lower()
    key = headers.get("sec-websocket-key", "")
    version = headers.get("sec-websocket-version", "")

    if upgrade != "websocket" or "upgrade" not in connection:
        log("WARN", "  [%s] 非 WebSocket 升级请求（Upgrade=%r Connection=%r）"
            % (peer, upgrade, connection))
        body = b"ws-bridge: this endpoint only speaks WebSocket\n"
        conn.sendall(b"HTTP/1.1 400 Bad Request\r\n"
                     b"Content-Type: text/plain\r\n"
                     b"Content-Length: %d\r\nConnection: close\r\n\r\n" % len(body) + body)
        return False
    if not key:
        log("WARN", "  [%s] 缺少 Sec-WebSocket-Key" % peer)
        conn.sendall(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n"
                     b"Content-Length: 0\r\n\r\n")
        return False

    accept = base64.b64encode(
        hashlib.sha1(key.encode("latin-1") + GUID).digest()).decode("ascii")

    resp = ("HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Accept: %s\r\n"
            "Sec-WebSocket-Version: %s\r\n"
            "\r\n" % (accept, version or "13"))
    conn.sendall(resp.encode("latin-1"))
    log("INFO", "  [%s] 握手完成：%s %s (Sec-WebSocket-Version=%s)"
        % (peer, method, path, version or "13"))
    return True


# ---------------------------------------------------------------- 帧读

class WsClosed(Exception):
    pass


def read_frame(conn):
    """读一帧，返回 (fin, opcode, payload)。对端正常关闭 / 出错抛 WsClosed。"""
    hdr = recv_exact(conn, 2)
    if hdr is None:
        raise WsClosed("连接结束")
    b0, b1 = hdr[0], hdr[1]
    fin = bool(b0 & 0x80)
    opcode = b0 & 0x0F
    masked = bool(b1 & 0x80)
    length = b1 & 0x7F

    if length == 126:
        ext = recv_exact(conn, 2)
        if ext is None:
            raise WsClosed("长度字段中断")
        length = struct.unpack(">H", ext)[0]
    elif length == 127:
        ext = recv_exact(conn, 8)
        if ext is None:
            raise WsClosed("长度字段中断")
        length = struct.unpack(">Q", ext)[0]

    if length > MAX_PAYLOAD:
        raise WsClosed("帧过大 %d" % length)

    mask = None
    if masked:
        mask = recv_exact(conn, 4)
        if mask is None:
            raise WsClosed("掩码字段中断")

    payload = b""
    if length:
        payload = recv_exact(conn, length)
        if payload is None:
            raise WsClosed("负载中断")

    if masked and payload:
        payload = bytes(payload[i] ^ mask[i & 3] for i in range(len(payload)))

    return fin, opcode, masked, payload


# ---------------------------------------------------------------- 帧写

def send_frame(conn, opcode, payload=b""):
    """服务端→客户端：不加掩码（RFC6455 §5.1）。加锁保证帧不被交错。"""
    n = len(payload)
    hdr = bytearray()
    hdr.append(0x80 | opcode)
    if n < 126:
        hdr.append(n)
    elif n < 65536:
        hdr.append(126)
        hdr += struct.pack(">H", n)
    else:
        hdr.append(127)
        hdr += struct.pack(">Q", n)
    with _lock_out:
        conn.sendall(bytes(hdr) + payload)


# ---------------------------------------------------------------- 单连接

def handle(conn, peer, cid, target):
    conn.settimeout(None)
    try:
        if not do_handshake(conn, peer):
            return
    except Exception as e:
        log("ERROR", "  [%s] 握手异常: %s: %s" % (peer, type(e).__name__, e))
        return

    # 连目标
    try:
        upstream = socket.create_connection(target, timeout=CONNECT_TIMEOUT)
    except Exception as e:
        logerr("ERROR", "[#%d] 连接目标 %s:%d 失败: %s: %s"
               % (cid, target[0], target[1], type(e).__name__, e))
        try:
            send_frame(conn, OP_CLOSE, struct.pack(">H", 1011) + b"upstream unreachable")
        except Exception:
            pass
        return
    upstream.settimeout(None)
    log("INFO", "  目标已连接: %s:%d" % target)

    up_bytes = [0]
    down_bytes = [0]
    stop = threading.Event()

    def close_all():
        for s in (conn, upstream):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                s.close()
            except Exception:
                pass

    def ws_to_tcp():
        """ws 二进制帧 -> TCP 字节。同时处理 ping/close/分片。"""
        frag = bytearray()
        frag_op = None
        try:
            while not stop.is_set():
                fin, op, _masked, payload = read_frame(conn)

                if op == OP_CLOSE:
                    log("INFO", "  收到 close 帧")
                    try:
                        send_frame(conn, OP_CLOSE, payload[:125])
                    except Exception:
                        pass
                    break
                if op == OP_PING:
                    send_frame(conn, OP_PONG, payload)
                    log("INFO", "  收到 ping(%dB) -> 回 pong" % len(payload))
                    continue
                if op == OP_PONG:
                    continue

                if op == OP_CONT:
                    frag += payload
                elif op in (OP_BIN, OP_TEXT):
                    frag = bytearray(payload)
                    frag_op = op
                else:
                    continue

                if fin:
                    data = bytes(frag)
                    frag = bytearray()
                    if data:
                        upstream.sendall(data)
                        up_bytes[0] += len(data)
        except WsClosed as e:
            log("INFO", "  ws 侧结束: %s" % e)
        except Exception as e:
            if not stop.is_set():
                logerr("WARN", "[#%d] ws->tcp 中断: %s: %s" % (cid, type(e).__name__, e))
        finally:
            stop.set()
            close_all()

    t = threading.Thread(target=ws_to_tcp, name="ws2tcp", daemon=True)
    t.start()

    # 主线程：TCP -> ws
    try:
        while not stop.is_set():
            data = upstream.recv(RECV_CHUNK)
            if not data:
                log("INFO", "  目标侧 EOF")
                break
            down_bytes[0] += len(data)
            send_frame(conn, OP_BIN, data)
    except Exception as e:
        if not stop.is_set():
            logerr("WARN", "[#%d] tcp->ws 中断: %s: %s" % (cid, type(e).__name__, e))
    finally:
        stop.set()
        try:
            send_frame(conn, OP_CLOSE, struct.pack(">H", 1000))
        except Exception:
            pass
        close_all()
        t.join(timeout=3)
        log("INFO", "[#%d] 连接关闭 上行=%d B 下行=%d B" % (cid, up_bytes[0], down_bytes[0]))


# ---------------------------------------------------------------- 配置与主循环

DEFAULT_LISTEN_ADDR = "127.0.0.1:25566"
DEFAULT_MC_TARGET = "127.0.0.1:25565"     # 通用默认：指向本机的服务；请按实际改成你的地址
DEFAULT_CONNECT_TIMEOUT = 10.0
DEFAULT_RECV_CHUNK = 32768

CONNECT_TIMEOUT = DEFAULT_CONNECT_TIMEOUT  # 运行时由 main() 按 参数 > 环境变量 > 默认 覆盖
RECV_CHUNK = DEFAULT_RECV_CHUNK


def parse_args(argv):
    """命令行参数：--listen / --target / --connect-timeout / --recv-chunk（另有 --help）。"""
    options = {}
    index = 0
    while index < len(argv):
        arg = argv[index]
        if arg in ("-h", "--help"):
            print(__doc__)
            raise SystemExit(0)
        if arg in ("--listen", "--target", "--connect-timeout", "--recv-chunk"):
            if index + 1 >= len(argv):
                raise SystemExit("参数 %s 后面缺少取值" % arg)
            options[arg.lstrip("-").replace("-", "_")] = argv[index + 1]
            index += 2
            continue
        if arg.startswith("--") and "=" in arg:
            name, _, value = arg[2:].partition("=")
            options[name.replace("-", "_")] = value
            index += 1
            continue
        raise SystemExit("无法识别的参数: %s（用 --help 看用法）" % arg)
    return options


def pick(options, key, env_name, default, cast=None):
    """取配置：命令行参数 > 环境变量 > 默认。"""
    raw = options.get(key)
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        raw = os.environ.get(env_name)
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        raw = default
    if cast is None:
        return raw
    try:
        return cast(raw)
    except (TypeError, ValueError):
        raise SystemExit("%s 取值不合法: %r" % (env_name, raw))


def main(argv=None):
    options = parse_args(list(sys.argv[1:] if argv is None else argv))

    listen_text = pick(options, "listen", "LISTEN_ADDR", DEFAULT_LISTEN_ADDR)
    target_text = pick(options, "target", "MC_TARGET", DEFAULT_MC_TARGET)
    connect_timeout = pick(options, "connect_timeout", "CONNECT_TIMEOUT",
                           DEFAULT_CONNECT_TIMEOUT, float)
    recv_chunk = pick(options, "recv_chunk", "RECV_CHUNK", DEFAULT_RECV_CHUNK, int)

    listen = parse_addr(listen_text, 25566)
    target = parse_addr(target_text, 25565)
    if not listen or not target:
        logerr("ERROR", "地址配置无效 --listen=%r --target=%r" % (listen_text, target_text))
        return 2
    if connect_timeout <= 0 or recv_chunk <= 0:
        logerr("ERROR", "超时与分块必须是正数 (connect_timeout=%r recv_chunk=%r)"
               % (connect_timeout, recv_chunk))
        return 2

    global CONNECT_TIMEOUT, RECV_CHUNK
    CONNECT_TIMEOUT = connect_timeout
    RECV_CHUNK = recv_chunk

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(listen)
    srv.listen(64)

    log("INFO", "ws-bridge 启动：监听 %s:%d -> 目标 %s:%d (RFC6455 服务端 / 二进制帧桥接)"
        % (listen[0], listen[1], target[0], target[1]))

    import signal

    def on_sig(signum, _frame):
        log("INFO", "收到信号 %d，停止监听" % signum)
        try:
            srv.close()
        except Exception:
            pass
        log("INFO", "ws-bridge 已停止")
        os._exit(0)

    signal.signal(signal.SIGTERM, on_sig)
    signal.signal(signal.SIGINT, on_sig)

    cid = 0
    while True:
        try:
            conn, addr = srv.accept()
        except OSError:
            break
        cid += 1
        peer = "%s:%d" % (addr[0], addr[1])
        log("INFO", "[#%d] 新连接 <- %s" % (cid, peer))
        th = threading.Thread(target=handle, args=(conn, peer, cid, target), daemon=True)
        th.start()

    log("INFO", "ws-bridge 已停止")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception:
        traceback.print_exc()
        sys.exit(1)
