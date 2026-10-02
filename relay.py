#!/usr/bin/env python3
"""
mc-relay —— 任意 TCP 流量的本地中继桥（Minecraft 是实测案例）

作用：把只会说**裸 TCP** 的本地客户端，接到远端的 **wss** 服务上。

  MC_MODE=ws （默认）—— 远端是 wss 端点（HTTP 反代 -> ws 桥 -> 目标服务）：

    本地客户端 --裸 TCP--> relay(127.0.0.1:25565)
        --[可选 CONNECT]--> TLS --> WebSocket Upgrade(101) --> 二进制帧 <-> 目标字节流

  MC_MODE=tls —— 旧路径：远端是裸 TCP + TLS 直通（保留作回归对照）：

    本地客户端 --裸 TCP--> relay(127.0.0.1:25565)
        --[可选 CONNECT]--> TLS --> 裸字节流

设计约束（可逐行审计）：
  * 仅使用 Python3 标准库，不引入第三方依赖；
  * TLS 证书校验**始终开启**（系统根证书链 + 主机名 SNI 校验），代码里不存在关闭校验的分支；
  * 代理路径必须先 `CONNECT host:port` 并**校验 200** 才继续；
  * ws 模式：客户端帧**必须加掩码**（随机 4 字节掩码 + 长度字节最高位置 1，RFC6455 §5.1/§5.2），
    服务端帧按无掩码读（带了掩码也照样解），支持 7/16/64 位扩展长度、分片合并、ping->pong、close；
  * 每条连接一条线程，连接内用 select 单线程泵双向字节：
    **同一个 TLS socket 在任何时刻只被一条线程触碰**（并发读写同一 SSL 对象会让 OpenSSL 的
    BIO 状态竞争而崩溃，实测出现过 SIGSEGV）；
  * 连接级异常只影响该条连接，主循环不受影响；已建立的会话不做读超时。

配置来源（优先级：**环境变量 > relay.conf > 内置默认**）：
    MC_TARGET       远端目标 "host:port" —— **没有内置默认，必须由环境变量或 relay.conf 提供**
    MC_MODE         ws（默认）| tls（旧路径对照）
    MC_WS_PATH      ws 模式的 HTTP 请求路径，默认 /
    LISTEN_ADDR     监听地址 "host:port"，默认 127.0.0.1:25565
    CONNECT_TIMEOUT 建连 / CONNECT / TLS / ws 握手超时秒数，默认 15（已建立的会话不做读超时）
    HTTPS_PROXY     可选，形如 http://127.0.0.1:7890；设置后走 CONNECT（代理只从环境变量取）
    https_proxy     同上（小写别名，大写的优先）

配置文件：默认读脚本同目录下的 relay.conf（KEY=VALUE，# 开头为注释，空行忽略）；
          可用环境变量 RELAY_CONFIG 指定别的路径。典型用法是复制 relay.conf.example 后填写。
"""

import base64
import hashlib
import os
import select
import signal
import socket
import ssl
import struct
import sys
import threading
import time

DEFAULT_LISTEN_ADDR = "127.0.0.1:25565"
DEFAULT_MODE = "ws"
DEFAULT_WS_PATH = "/"
DEFAULT_CONNECT_TIMEOUT = 15.0
CONNECT_TIMEOUT = DEFAULT_CONNECT_TIMEOUT   # 启动时按 环境变量 > relay.conf > 默认 重设
CONFIG_FILENAME = "relay.conf"
CONFIG_KEYS = ("MC_TARGET", "MC_MODE", "MC_WS_PATH", "LISTEN_ADDR", "CONNECT_TIMEOUT")
_config = {}                                # relay.conf 的解析结果（启动时装载）
BUFSIZE = 65536
MAX_HTTP_HEADER = 65536
WS_MAX_PAYLOAD = 16 * 1024 * 1024   # 单帧上限，防异常大帧撑爆内存
SHUTDOWN_JOIN_TIMEOUT = 2.0

# RFC6455 opcode
WS_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
OP_CONT = 0x0
OP_TEXT = 0x1
OP_BIN = 0x2
OP_CLOSE = 0x8
OP_PING = 0x9
OP_PONG = 0xA

_stop = threading.Event()          # 置位后主循环退出（SIGINT / SIGTERM）
_active = set()                    # 活跃连接线程，用于退出时短暂收敛
_active_lock = threading.Lock()


# ---------------------------------------------------------------- 通用

def log(level, message):
    """分级日志：时间 + 级别 + 内容，立即刷出。"""
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    print("[%s] [%s] %s" % (stamp, level, message), flush=True)


def parse_hostport(value, default_port=None, what="address"):
    """解析 "host:port" / "[v6]:port" / "host"（用 default_port）。"""
    text = (value or "").strip()
    if not text:
        raise ValueError("%s 为空" % what)
    if text.startswith("["):                      # [::1]:25565
        host, _, rest = text[1:].partition("]")
        port_text = rest.lstrip(":")
    elif text.count(":") == 1:                    # host:port
        host, _, port_text = text.partition(":")
    elif ":" in text:                             # 裸 IPv6，无端口
        host, port_text = text, ""
    else:                                         # host
        host, port_text = text, ""
    if not port_text:
        if default_port is None:
            raise ValueError("%s 缺少端口: %r" % (what, value))
        port_text = str(default_port)
    if not host:
        raise ValueError("%s 缺少主机名: %r" % (what, value))
    try:
        port = int(port_text)
    except ValueError:
        raise ValueError("%s 端口不是整数: %r" % (what, port_text))
    if not (0 < port < 65536):
        raise ValueError("%s 端口超出范围: %d" % (what, port))
    return host, port


def config_path():
    """relay.conf 的位置：RELAY_CONFIG 环境变量优先，否则脚本同目录。"""
    override = (os.environ.get("RELAY_CONFIG") or "").strip()
    if override:
        return override
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), CONFIG_FILENAME)


def parse_config_text(text, origin):
    """解析 KEY=VALUE 配置文本，返回 dict；未知键只警告不报错（便于发现拼写错误）。"""
    parsed = {}
    for lineno, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError("%s 第 %d 行不是 KEY=VALUE 格式: %r" % (origin, lineno, raw_line))
        key, _, value = line.partition("=")
        key = key.strip().upper()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1].strip()       # 允许整体加引号，避免值里有空格时产生歧义
        if not key:
            raise ValueError("%s 第 %d 行键名为空" % (origin, lineno))
        if key not in CONFIG_KEYS:
            log("WARN", "%s 第 %d 行未知键 %r（已忽略；可用键：%s）"
                % (origin, lineno, key, ", ".join(CONFIG_KEYS)))
            continue
        parsed[key] = value
    return parsed


def load_config():
    """装载 relay.conf；文件不存在则跳过（此时只能靠环境变量）。"""
    path = config_path()
    if not os.path.exists(path):
        log("INFO", "配置文件未找到（跳过）: %s" % path)
        return {}
    with open(path, "r", encoding="utf-8") as handle:
        parsed = parse_config_text(handle.read(), path)
    log("INFO", "已装载配置: %s（%s）" % (path, ", ".join(sorted(parsed)) or "无有效键"))
    return parsed


def get_setting(name, default=None):
    """取配置：环境变量 > relay.conf > default；空串一律视为未设置。"""
    env_value = os.environ.get(name)
    if env_value is not None and env_value.strip():
        return env_value.strip()
    conf_value = _config.get(name)
    if conf_value is not None and conf_value.strip():
        return conf_value.strip()
    return default


def proxy_from_env():
    """读 HTTPS_PROXY / https_proxy；空串表示直连。（代理只从环境变量取，不写进配置文件）"""
    return (os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy") or "").strip()


def parse_proxy_url(value):
    """把 http://host:port 形式的代理地址拆成 (host, port)。"""
    text = value.strip()
    lowered = text.lower()
    for scheme in ("http://", "https://"):
        if lowered.startswith(scheme):
            text = text[len(scheme):]
            break
    text = text.rstrip("/")
    if "@" in text:
        raise ValueError("代理地址含凭据（user:pass@），本中继不支持代理认证")
    return parse_hostport(text, default_port=8080, what="HTTPS_PROXY")


def ssl_pending(sock):
    """SSL 层可能已缓冲解密后的数据，select 不会报告这类可读，需显式检查。"""
    pending = getattr(sock, "pending", None)
    if pending is None:
        return 0
    try:
        return pending()
    except (OSError, ValueError):
        return 0


def recv_exact(sock, n):
    """读满 n 字节；对端先关闭时抛 WsClosed（按 EOF 语义处理）。"""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise WsClosed("字节流在读到 %d/%d 字节时结束" % (len(buf), n))
        buf += chunk
    return buf


# ---------------------------------------------------------------- 建链

def open_via_proxy(proxy_host, proxy_port, target_host, target_port):
    """TCP 连代理 -> 发 CONNECT -> 校验 200 -> 返回已建立的裸 socket。"""
    sock = socket.create_connection((proxy_host, proxy_port), timeout=CONNECT_TIMEOUT)
    request = (
        "CONNECT %s:%d HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Proxy-Connection: keep-alive\r\n"
        "\r\n" % (target_host, target_port, target_host, target_port)
    )
    sock.sendall(request.encode("ascii"))

    buffered = b""
    while b"\r\n\r\n" not in buffered:
        chunk = sock.recv(4096)
        if not chunk:
            sock.close()
            raise ConnectionError("代理在建连响应前关闭连接")
        buffered += chunk
        if len(buffered) > MAX_HTTP_HEADER:
            sock.close()
            raise ConnectionError("代理响应头超过 %d 字节" % MAX_HTTP_HEADER)

    head, _, leftover = buffered.partition(b"\r\n\r\n")
    status_line = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    parts = status_line.split(" ")
    code = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    if code != 200:
        sock.close()
        raise ConnectionError("CONNECT 被代理拒绝: %s" % status_line)
    if leftover:
        # CONNECT 刚建立时代理不应向客户端推数据（我方尚未发出任何请求）。
        # 多出来的字节若直接丢弃会损坏后续 TLS 会话，故显式报错而不是静默吞掉。
        sock.close()
        raise ConnectionError("CONNECT 200 之后代理仍推送了 %d 字节，协议异常" % len(leftover))
    log("INFO", "  CONNECT 通过: %s:%d -> %s:%d (%s)"
        % (proxy_host, proxy_port, target_host, target_port, status_line))
    return sock


def open_direct(target_host, target_port):
    """无代理直连目标（本地演练档）。"""
    sock = socket.create_connection((target_host, target_port), timeout=CONNECT_TIMEOUT)
    log("INFO", "  直连目标: %s:%d" % (target_host, target_port))
    return sock


def wrap_tls(raw_sock, target_host):
    """在裸 socket 上做 TLS，证书链与主机名校验全开。"""
    context = ssl.create_default_context()
    tls = context.wrap_socket(raw_sock, server_hostname=target_host)
    cert = tls.getpeercert()
    subject = dict(x[0] for x in cert.get("subject", []))
    issuer = dict(x[0] for x in cert.get("issuer", []))
    log("INFO", "  TLS 已建立: %s / %s" % (tls.version(), tls.cipher()[0]))
    log("INFO", "  证书 subject=%s issuer=%s 有效期至 %s"
        % (subject.get("commonName"), issuer.get("commonName"), cert.get("notAfter")))
    return tls


# ---------------------------------------------------------------- WebSocket 客户端

class WsClosed(ConnectionError):
    """ws 侧的干净关闭（对端 close 帧 / TCP 结束）——按 EOF 处理，不算错误。"""


class WsError(ConnectionError):
    """ws 协议错误——按连接级错误处理。"""


def ws_client_handshake(sock, target_host, target_port, path):
    """
    RFC6455 客户端 Upgrade 握手（§4.1）。
    校验三件事：HTTP 101、Upgrade: websocket、
    Sec-WebSocket-Accept == base64(sha1(Sec-WebSocket-Key + GUID))。
    返回响应头之后的残余字节（正常情况下为空），交给调用方喂进帧解码器。
    """
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    host_header = "%s:%d" % (target_host, target_port)
    request = (
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n" % (path, host_header, key)
    )
    sock.sendall(request.encode("ascii"))

    buffered = b""
    while b"\r\n\r\n" not in buffered:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("WS 握手阶段连接被关闭（未收到 HTTP 响应）")
        buffered += chunk
        if len(buffered) > MAX_HTTP_HEADER:
            raise ConnectionError("WS 握手响应头超过 %d 字节" % MAX_HTTP_HEADER)

    head, _, leftover = buffered.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status_line = lines[0].decode("latin-1", "replace")
    parts = status_line.split(" ")
    code = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0

    headers = {}
    for line in lines[1:]:
        if b":" in line:
            name, _, value = line.partition(b":")
            headers[name.strip().lower().decode("latin-1")] = value.strip().decode("latin-1")

    if code != 101:
        raise ConnectionError("WS 升级被拒绝: %s" % status_line)
    if headers.get("upgrade", "").lower() != "websocket":
        raise ConnectionError("WS 升级响应缺少 Upgrade: websocket（got=%r）"
                              % headers.get("upgrade"))
    expected = base64.b64encode(
        hashlib.sha1(key.encode("ascii") + WS_GUID).digest()).decode("ascii")
    got = headers.get("sec-websocket-accept", "")
    if got != expected:
        raise ConnectionError("Sec-WebSocket-Accept 校验失败: got=%r expect=%r" % (got, expected))

    log("INFO", "  WS 升级: %s (path=%s, Sec-WebSocket-Accept 校验通过)" % (status_line, path))
    return leftover


def ws_send_frame(sock, opcode, payload, stats):
    """
    发一帧。RFC6455 §5.1/§5.2：客户端帧**必须**带掩码，
    因此长度字节的最高位固定置 1，随后紧跟 4 字节随机掩码，负载逐字节 XOR。
    """
    length = len(payload)
    header = bytearray([0x80 | opcode])          # FIN=1 + opcode
    if length < 126:
        header.append(0x80 | length)             # 0x80 = MASK 位（漏置它服务端会直接断连）
    elif length < 65536:
        header.append(0x80 | 126)
        header += struct.pack(">H", length)
    else:
        header.append(0x80 | 127)
        header += struct.pack(">Q", length)
    mask = os.urandom(4)
    header += mask
    masked = bytes(b ^ mask[i & 3] for i, b in enumerate(payload))
    sock.sendall(bytes(header) + masked)
    stats["frames_out"] += 1
    stats["bytes_out"] += length


def ws_read_frame(sock, stats):
    """读一整帧，返回 (fin, opcode, payload)。对端正常关闭 / 协议错分别抛 WsClosed / WsError。"""
    head = recv_exact(sock, 2)
    b0, b1 = head[0], head[1]
    fin = bool(b0 & 0x80)
    opcode = b0 & 0x0F
    masked = bool(b1 & 0x80)
    length = b1 & 0x7F

    if length == 126:
        length = struct.unpack(">H", recv_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack(">Q", recv_exact(sock, 8))[0]
    if length > WS_MAX_PAYLOAD:
        raise WsError("帧过大 %d 字节（上限 %d）" % (length, WS_MAX_PAYLOAD))

    mask = recv_exact(sock, 4) if masked else None   # 服务端帧不该带掩码，带了也照样解
    payload = recv_exact(sock, length) if length else b""
    if mask:
        payload = bytes(b ^ mask[i & 3] for i, b in enumerate(payload))

    stats["frames_in"] += 1
    stats["bytes_in"] += length
    return fin, opcode, payload


# ---------------------------------------------------------------- 双向搬运的端点抽象

class RawEndpoint(object):
    """裸 socket（客户端侧，或 tls 模式下的服务端侧）：就是字节流。"""

    def __init__(self, sock):
        self.sock = sock

    def fileno(self):
        return self.sock.fileno()

    def has_buffered(self):
        return ssl_pending(self.sock) > 0

    def read_chunk(self):
        return self.sock.recv(BUFSIZE)

    def write(self, data):
        self.sock.sendall(data)

    def half_close(self):
        try:
            self.sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass

    def stats_text(self):
        return ""


class WsEndpoint(object):
    """
    ws 模式的（服务端侧）端点：把 WebSocket 二进制帧流转成 MC 字节流。

    * 服务端帧无掩码直接读，分片按 continuation 合并到 FIN=1 才交给上层；
    * ping 自动回 pong，pong 忽略，close 视为 EOF；
    * 发送侧一律用带掩码的二进制帧；
    * read_chunk() 只在真的读到数据或 EOF 时返回，内部吃掉控制帧。
    """

    def __init__(self, sock, leftover=b""):
        self.sock = sock
        self.buf = bytearray(leftover)      # 已解出的 MC 字节（跨帧重组）
        self.frag = bytearray()             # 分片合并缓冲
        self.frag_opcode = None
        self.peer_closed = False
        self.send_closed = False
        self.stats = {"frames_in": 0, "frames_out": 0, "bytes_in": 0, "bytes_out": 0,
                      "ping": 0, "pong": 0, "close": 0, "frag": 0}

    def fileno(self):
        return self.sock.fileno()

    def has_buffered(self):
        return bool(self.buf) or ssl_pending(self.sock) > 0

    def read_chunk(self):
        if self.buf:
            out = bytes(self.buf[:BUFSIZE])
            del self.buf[:len(out)]
            return out
        if self.peer_closed:
            return b""

        while True:
            try:
                fin, opcode, payload = ws_read_frame(self.sock, self.stats)
            except WsClosed as exc:
                log("INFO", "  ws 侧结束: %s" % exc)
                self.peer_closed = True
                return b""

            if opcode == OP_CLOSE:
                self.stats["close"] += 1
                log("INFO", "  收到 ws close 帧（%d 字节）" % len(payload))
                self.send_close(1000)
                self.peer_closed = True
                return b""
            if opcode == OP_PING:
                self.stats["ping"] += 1
                ws_send_frame(self.sock, OP_PONG, payload, self.stats)
                self.stats["pong"] += 1
                log("INFO", "  收到 ws ping(%d B) -> 已回 pong" % len(payload))
                continue
            if opcode == OP_PONG:
                self.stats["pong"] += 1
                continue
            if opcode == OP_CONT:
                if self.frag_opcode is None:
                    raise WsError("收到 continuation 帧但没有起始帧")
                self.stats["frag"] += 1
                self.frag += payload
            elif opcode in (OP_BIN, OP_TEXT):
                self.frag = bytearray(payload)
                self.frag_opcode = opcode
            else:
                log("WARN", "  跳过未知 opcode=0x%x（%d 字节）" % (opcode, len(payload)))
                continue

            if not fin:
                continue                     # 还没收完，继续等后续 continuation
            data = bytes(self.frag)
            self.frag = bytearray()
            self.frag_opcode = None
            if not data:
                continue                     # 空帧，继续等真数据
            self.buf = bytearray(data)
            out = bytes(self.buf[:BUFSIZE])
            del self.buf[:len(out)]
            return out

    def write(self, data):
        if self.send_closed or self.peer_closed:
            raise WsError("ws 连接已关闭，无法发送")
        ws_send_frame(self.sock, OP_BIN, data, self.stats)

    def send_close(self, code):
        """发一次 close 帧（幂等）。"""
        if self.send_closed or self.sock is None:
            return
        self.send_closed = True
        try:
            ws_send_frame(self.sock, OP_CLOSE, struct.pack(">H", code), self.stats)
        except OSError:
            pass

    def half_close(self):
        """本方向不再发数据：按 RFC 发 close 帧告知对端（读方向不受影响）。"""
        self.send_close(1000)

    def stats_text(self):
        s = self.stats
        return (" | ws 帧: 收 %d / 发 %d（帧内字节 收 %d / 发 %d；ping %d, close %d, 分片 %d）"
                % (s["frames_in"], s["frames_out"], s["bytes_in"], s["bytes_out"],
                   s["ping"], s["close"], s["frag"]))


# ---------------------------------------------------------------- 双向搬运

def label_of(direction):
    return "上行(客户端->服务端)" if direction == "client" else "下行(服务端->客户端)"


def move_bytes(direction, src, dst, counter, slot, open_dir):
    """
    从 src 读一块、转发给 dst，返回 True 表示搬到了数据。
    EOF 或读写错误时：对 dst 半关闭，并停止本方向的继续读取。
    """
    try:
        chunk = src.read_chunk()
    except OSError as exc:
        log("WARN", "  %s 读取中断: %s: %s" % (label_of(direction), type(exc).__name__, exc))
        return stop_direction(direction, dst, open_dir)
    if not chunk:
        log("INFO", "  %s 侧 EOF" % label_of(direction))
        return stop_direction(direction, dst, open_dir)
    try:
        dst.write(chunk)
    except OSError as exc:
        log("WARN", "  %s 写出中断: %s: %s" % (label_of(direction), type(exc).__name__, exc))
        return stop_direction(direction, dst, open_dir)
    counter[slot] += len(chunk)
    return True


def stop_direction(direction, dst, open_dir):
    """本方向结束：对目的端半关闭，并停止继续读源端。"""
    open_dir[direction] = False
    dst.half_close()
    return False


def pump(client_ep, upstream_ep, counter):
    """
    双向泵：select 单线程循环，任一时刻只有本线程在操作这两个端点。

    counter[0] 记 客户端->服务端，counter[1] 记 服务端->客户端。
    任一方向 EOF 时只对目的端半关闭，另一方向继续直到也 EOF。
    """
    lanes = [("client", client_ep, upstream_ep, 0),
             ("upstream", upstream_ep, client_ep, 1)]
    open_dir = {"client": True, "upstream": True}

    while open_dir["client"] or open_dir["upstream"]:
        live = [lane for lane in lanes if open_dir[lane[0]]]
        if not live:
            break

        # 先排空端点自带缓冲（SSL 已解密数据 / ws 已解帧数据），select 不会报告这类可读
        drained = False
        for direction, src, dst, slot in live:
            if src.has_buffered():
                move_bytes(direction, src, dst, counter, slot, open_dir)
                drained = True
        if drained:
            continue

        try:
            readable, _, _ = select.select([lane[1].fileno() for lane in live], [], [])
        except (OSError, ValueError) as exc:
            log("WARN", "  select 异常，结束本条连接: %s: %s" % (type(exc).__name__, exc))
            break

        for direction, src, dst, slot in live:
            if src.fileno() in readable:
                move_bytes(direction, src, dst, counter, slot, open_dir)


# ---------------------------------------------------------------- 单连接

def handle_connection(client_sock, client_addr, conn_id):
    """处理一条入站连接；任何异常都只终结这条连接。"""
    counter = [0, 0]        # [上行 客户端->服务端, 下行 服务端->客户端]
    upstream_sock = None
    upstream_ep = None
    try:
        mode = (get_setting("MC_MODE", DEFAULT_MODE) or DEFAULT_MODE).strip().lower()
        if mode not in ("ws", "tls"):
            raise ValueError("MC_MODE 只能是 ws 或 tls，当前为 %r" % mode)
        ws_path = get_setting("MC_WS_PATH", DEFAULT_WS_PATH)
        target_raw = get_setting("MC_TARGET")
        if not target_raw:
            raise ValueError("未配置目标（MC_TARGET 既不在环境变量也不在 relay.conf 里）")
        target_host, target_port = parse_hostport(target_raw, what="MC_TARGET")
        proxy_raw = proxy_from_env()

        log("INFO", "[#%d] 新连接 <- %s:%d 目标=%s:%d 模式=%s%s%s"
            % (conn_id, client_addr[0], client_addr[1], target_host, target_port, mode,
               (" path=" + ws_path) if mode == "ws" else "",
               (" 代理=" + proxy_raw) if proxy_raw else " 直连"))

        if proxy_raw:
            proxy_host, proxy_port = parse_proxy_url(proxy_raw)
            raw = open_via_proxy(proxy_host, proxy_port, target_host, target_port)
        else:
            raw = open_direct(target_host, target_port)

        raw.settimeout(CONNECT_TIMEOUT)       # TLS / ws 握手阶段受超时保护
        try:
            upstream_sock = wrap_tls(raw, target_host)
            if mode == "ws":
                leftover = ws_client_handshake(upstream_sock, target_host, target_port, ws_path)
                upstream_ep = WsEndpoint(upstream_sock, leftover)
            else:
                upstream_ep = RawEndpoint(upstream_sock)
        except BaseException:
            raw.close()
            raise

        upstream_sock.settimeout(None)        # 长会话：不做读超时（MC 自带 keepalive）
        client_sock.settimeout(None)

        pump(RawEndpoint(client_sock), upstream_ep, counter)
        log("INFO", "[#%d] 连接关闭 上行=%d B 下行=%d B%s"
            % (conn_id, counter[0], counter[1], upstream_ep.stats_text()))
    except Exception as exc:
        log("ERROR", "[#%d] 连接失败: %s: %s" % (conn_id, type(exc).__name__, exc))
        log("INFO", "[#%d] 连接关闭 上行=%d B 下行=%d B%s"
            % (conn_id, counter[0], counter[1],
               upstream_ep.stats_text() if upstream_ep is not None else ""))
    finally:
        if isinstance(upstream_ep, WsEndpoint):
            upstream_ep.send_close(1000)
        for sock in (upstream_sock, client_sock):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass


def build_listener(listen_host, listen_port):
    infos = socket.getaddrinfo(listen_host, listen_port, type=socket.SOCK_STREAM)
    family, socktype, proto, _, sockaddr = infos[0]
    server = socket.socket(family, socktype, proto)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(sockaddr)
    server.listen(64)
    return server


def serve_connection(client_sock, client_addr, conn_id):
    """连接线程入口：登记活跃线程，异常不外溢。"""
    with _active_lock:
        _active.add(threading.current_thread())
    try:
        handle_connection(client_sock, client_addr, conn_id)
    finally:
        with _active_lock:
            _active.discard(threading.current_thread())


def main():
    global CONNECT_TIMEOUT, _config

    try:
        _config = load_config()
    except (OSError, ValueError) as exc:
        log("ERROR", "启动失败: 读取 relay.conf 出错: %s" % exc)
        return 2

    target_raw = get_setting("MC_TARGET")
    if not target_raw:
        log("ERROR", "启动失败: 未配置目标：请复制 relay.conf.example 为 relay.conf 并填写，"
                     "或设置 MC_TARGET 环境变量")
        return 2

    try:
        target_host, target_port = parse_hostport(target_raw, what="MC_TARGET")
    except ValueError as exc:
        log("ERROR", "启动失败: %s" % exc)
        return 2

    try:
        listen_host, listen_port = parse_hostport(
            get_setting("LISTEN_ADDR", DEFAULT_LISTEN_ADDR), what="LISTEN_ADDR")
    except ValueError as exc:
        log("ERROR", "启动失败: %s" % exc)
        return 2

    mode = (get_setting("MC_MODE", DEFAULT_MODE) or DEFAULT_MODE).strip().lower()
    if mode not in ("ws", "tls"):
        log("ERROR", "启动失败: MC_MODE 只能是 ws 或 tls，当前为 %r" % mode)
        return 2

    try:
        CONNECT_TIMEOUT = float(get_setting("CONNECT_TIMEOUT", str(DEFAULT_CONNECT_TIMEOUT)))
        if CONNECT_TIMEOUT <= 0:
            raise ValueError("必须为正数")
    except ValueError as exc:
        log("ERROR", "启动失败: CONNECT_TIMEOUT 不是合法秒数（%s）" % exc)
        return 2

    server = build_listener(listen_host, listen_port)
    proxy_raw = proxy_from_env()
    ws_path = get_setting("MC_WS_PATH", DEFAULT_WS_PATH)
    log("INFO", "mc-relay 启动：监听 %s:%d -> 目标 %s:%d (模式=%s%s, 代理=%s, 超时=%.0fs)"
        % (listen_host, listen_port, target_host, target_port, mode,
           (" path=" + ws_path) if mode == "ws" else "",
           proxy_raw or "无(直连)", CONNECT_TIMEOUT))

    def on_signal(signum, _frame):
        log("INFO", "收到信号 %d，停止监听" % signum)
        _stop.set()
        try:
            server.close()
        except OSError:
            pass

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    conn_id = 0
    while not _stop.is_set():
        try:
            client_sock, client_addr = server.accept()
        except OSError as exc:
            if _stop.is_set():
                break
            log("ERROR", "accept 失败（主循环继续）: %s: %s" % (type(exc).__name__, exc))
            time.sleep(0.1)
            continue
        conn_id += 1
        threading.Thread(target=serve_connection,
                         args=(client_sock, client_addr, conn_id), daemon=True).start()

    with _active_lock:
        pending = list(_active)
    for thread in pending:
        thread.join(SHUTDOWN_JOIN_TIMEOUT)
    log("INFO", "mc-relay 已停止")
    return 0


if __name__ == "__main__":
    sys.exit(main())
