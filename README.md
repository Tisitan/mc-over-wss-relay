# mc-relay · 任意 TCP 流量 over wss 的双向桥（客户端 relay + 服务端 ws-bridge）

**一句话**：本地程序只会说**裸 TCP**，远端服务只在 **wss**（WebSocket over TLS）上等你——
本包含**两半**，一头一尾把字节搬运过去：

```
[本地客户端] --裸TCP--> [relay.py] --[可选 CONNECT 代理]--> TLS --> wss 入口
                       （本包·客户端侧）                              |
                                                                     v
[你的服务] <--裸TCP-- [ws-bridge.py] <-- HTTP 反向代理 + 真证书 <-------+
                       （本包·服务端侧）
```

前半段由 `relay.py` 负责（跑在客户端机器上），后半段由 `ws-bridge.py` 负责（跑在服务端机器上），
中间的公网入口需要你自备一个域名 + 真证书 + HTTP 反向代理。

Minecraft（Java 版）是它的实测案例：MC 客户端只认裸 TCP、只会填 `localhost`，
而远端入口是 wss，中间的姿势差由这两个桥补齐。

- **纯 Python3 标准库**，零第三方依赖，两个脚本都是单文件、无混淆，可逐行审计。
- **TLS 证书校验始终开启**（系统根证书链 + 主机名校验），代码里不存在关闭校验的分支。
- **地址全部可配**，代码里没有任何写死的域名/IP。
- 每条连接一条线程，连接内单线程 `select` 泵双向字节；某条连接出错只终结它自己，主循环照常接新连接。

### 运行前提（先对一遍，省得后面踩坑）

| 项 | 要求 |
| --- | --- |
| Python | **3.8 或更新**（实测 3.12）。两个脚本都只用标准库，**不需要 pip install 任何东西** |
| 依赖 | 无。但客户端要能出网到你的 wss 入口；服务端要能连到目标服务 |
| 需要的账号/材料 | 一个**域名** + 该域名可签发的**真证书** + 一个能配反向代理的公网入口（教程仓有完整做法） |
| 确认 Python 可用 | `python3 -V`。Windows 上若没有 `python3`，把命令换成 `py -3` 或 `python` |

**只要一句话就能判断你有没有配错**：客户端 `relay.conf` 里填的 `MC_TARGET` 是**公网入口**（域名:端口），
服务端 `ws-bridge.py --target` 填的是**你自己服务**的地址（比如 `127.0.0.1:25565`）。两个别填反。

---

## 一、先看这里：你要动几台机器

> **只想当客户端用？** 如果服务端已经有人搭好、你只拿到一句「入口地址是 `xxx:yyy`」——
> 直接跳到**第三节**，填个配置就能玩，下面这些机器你都碰不到。

| 机器 | 放什么 | 跑什么 |
| --- | --- | --- |
| **你的服务器**（能访问到目标服务的那台） | `ws-bridge.py` | 监听 `127.0.0.1:25566`，把 ws 帧还原成裸 TCP 转给目标服务 |
| **公网入口**（你的域名 + 真证书 + HTTP 反向代理） | —— | 把 `wss://你的域名/` 的请求反代到上一条的 `127.0.0.1:25566` |
| **客户端机器**（你玩游戏的那台） | `relay.py` + `relay.conf` | 监听 `127.0.0.1:25565`，把裸 TCP 客户端接进 wss 入口 |

三条地址别搞混（这是最容易配错的地方）：

| 配置项 | 填什么 | 例子 |
| --- | --- | --- |
| `ws-bridge.py --target` | **你真正的服务**在哪 | `127.0.0.1:25565`（本机 MC）、`192.0.2.5:25565`（同网段另一台） |
| `ws-bridge.py --listen` | 反代往哪转（一般不用改） | `127.0.0.1:25566` |
| 反代的转发目标 | 就是上面那个 `--listen` | `http://127.0.0.1:25566` |
| `relay.conf` 的 `MC_TARGET` | **公网 wss 入口**（域名:端口） | `your-domain.example:443` |

---

## 二、服务端部署（三步）

### 第 1 步：把 ws-bridge.py 放到你的服务器上，指向真实服务

```bash
# 放到服务器上任意目录，然后（--target 改成你的服务地址）
python3 ws-bridge.py --listen 127.0.0.1:25566 --target 127.0.0.1:25565
```

也可以走环境变量（命令行参数优先于环境变量）：

```bash
MC_TARGET=127.0.0.1:25565 python3 ws-bridge.py
```

启动成功会打印：

```
[INFO] ws-bridge 启动：监听 127.0.0.1:25566 -> 目标 127.0.0.1:25565 (RFC6455 服务端 / 二进制帧桥接)
```

**自测**（在服务器本机上，不经过公网，直接验证这一环）：

```bash
python3 wss_mc_probe.py status 127.0.0.1 25566        # 明文 ws 直连本机的桥；MC 会回 1.21.1 状态
```

`--help` 看全部参数；`--listen` 故意保持只绑回环，**不要**直接把它暴露到公网——对外的入口应该是
带真证书的反代。

**让它常驻**（可选，随手两种写法）：

```bash
# 前台跑着就行，或者：
nohup python3 ws-bridge.py --target 127.0.0.1:25565 > /tmp/ws-bridge.log 2>&1 &
kill %1        # 停止；SIGINT/SIGTERM 都会干净退出
```

想开机自启就把它写成一个 systemd service（`ExecStart=/usr/bin/python3 /path/ws-bridge.py --target ...`），
这一步没有任何特别之处，按你系统上其它服务的样子写即可。

### 第 2 步：给你的域名挂真证书，并让反代把请求转给 ws-bridge

这一层要做的是：一个域名 → 真证书（Let's Encrypt 等公共 CA）→ HTTP 反向代理 → 反代把
`Upgrade: websocket` 的请求转发到上一节的 `127.0.0.1:25566`。

**三个必须满足的点**（否则客户端会在握手阶段报错，且错误信息会直接告诉你卡在哪）：

1. 证书是**公共 CA** 签发（自签证书客户端会拒绝——这是设计如此，不是 bug）；
2. 反代把 `Upgrade: websocket` / `Connection: Upgrade` 两个头**原样透传**（多数反代默认支持，
   但有些默认关闭，比如 nginx 需要 `proxy_set_header Upgrade $http_upgrade;` 与
   `proxy_set_header Connection "upgrade";`）；
3. 反代**不做响应改写**（否则 `Sec-WebSocket-Accept` 校验会失败，客户端会明确报出 got/expect）。

**完整方法论（含隧道 / 证书 / 反代的选型与踩坑）见教程仓：**
<https://github.com/Tisitan/dot-sandbox-egress-guide>

做完这一步，你会拿到一个形如 `your-domain.example:443` 的入口地址。**抽查一行**即可确认证书没问题：

```bash
openssl s_client -connect your-domain.example:443 -servername your-domain.example </dev/null 2>/dev/null | grep -E 'subject=|issuer='
# 期望：issuer 是公共 CA（Let's Encrypt / ZeroSSL 等），而不是你自己签的名字
```

### 第 3 步：客户端机器上跑 relay.py

见下一节。到这里服务端就不需要再动了。

---

## 三、客户端跑通（三分钟）

```bash
# 1) 复制配置模板，填上你的公网 wss 入口（relay.conf 要和 relay.py 放同一个目录）
cp relay.conf.example relay.conf        # Windows: copy relay.conf.example relay.conf
$EDITOR relay.conf          # 至少把 MC_TARGET 改成 你的域名:端口

# 2) 起桥（前台跑，日志直接打在终端；Windows 上若没有 python3 就写 py -3 或 python）
python3 relay.py

# 3) 让客户端连本机
#    Minecraft：多人游戏 -> 添加服务器 -> 地址填 localhost（端口留空即 25565）
```

不知道该填什么？打开 `relay.conf`，只有 `MC_TARGET` 是必填项——把它写成别人给你的那个入口地址
（`域名:端口` 的形式，例如 `your-domain.example:443`），其它保持默认即可。
配置文件放别处也行，用 `RELAY_CONFIG=/path/to/relay.conf python3 relay.py`。

要走出站代理时，代理**只从环境变量读**（不写进配置文件）：

```bash
HTTPS_PROXY=http://127.0.0.1:7890 python3 relay.py
```

后台常驻与停止：

```bash
nohup python3 relay.py > /tmp/mc-relay.log 2>&1 &
kill %1        # 或对进程发 SIGINT / SIGTERM：都会打印「收到信号 N，停止监听」并干净退出（退出码 0）
```

---

## 四、成功标志：日志里的关键行

**先看第一行**——它确认你的配置被读到了、目标没填错：

```
[INFO] mc-relay 启动：监听 127.0.0.1:25565 -> 目标 your-domain.example:443 (模式=ws path=/, 代理=无(直连), 超时=15s)
```

然后客户端一连接，会出现下面这几行（**顺序即判据**；第一行只有走代理时才有）：

```
[INFO]   CONNECT 通过: 192.0.2.10:7890 -> your-domain.example:443 (HTTP/1.1 200 Connection established)   ← 仅走代理时出现
[INFO]   TLS 已建立: TLSv1.3 / TLS_AES_128_GCM_SHA256
[INFO]   WS 升级: HTTP/1.1 101 Switching Protocols (path=/, Sec-WebSocket-Accept 校验通过)
```

也就是说：**直连是两行（`TLS 已建立` + `WS 升级`），走代理是三行**。看到 `WS 升级 … 101` 就说明
**桥这一侧**已经打通。之后能不能进服，取决于服务端的白名单、密码等规则（那是服务端的事）。

TLS 版本与套件由双方协商决定，看到 `TLSv1.2` 之类同样算通过——判据是这几行的**顺序与内容**，不是具体版本。

服务端那半（ws-bridge）能看到对应的一行：

```
[INFO]   [127.0.0.1:54321] 握手完成：GET / (Sec-WebSocket-Version=13)
[INFO]   目标已连接: 127.0.0.1:25565
```

---

## 五、配置文件与环境变量

### relay.conf

放在 `relay.py` **同目录**（也可以用环境变量 `RELAY_CONFIG=/path/to/xxx.conf` 指定别处）。
格式：`KEY=VALUE` 一行一个，`#` 开头是注释，空行忽略，值两侧可加引号。
不确定怎么写就先复制 `relay.conf.example`。

```ini
MC_TARGET=your-domain.example:443
MC_MODE=ws
MC_WS_PATH=/
LISTEN_ADDR=127.0.0.1:25565
CONNECT_TIMEOUT=15
```

### 环境变量

| 变量 | 对应配置 | 默认 | 说明 |
| --- | --- | --- | --- |
| `MC_TARGET` | 远端目标 | **无默认** | `host:port`；缺了会启动报错（退出码 2） |
| `MC_MODE` | 协议模式 | `ws` | `ws` = WebSocket 二进制帧（**就是 wss 那一档**，见下方说明）；`tls` = 旧裸 TLS 直通（已不推荐） |
| `MC_WS_PATH` | ws 请求路径 | `/` | `tls` 模式下忽略 |
| `LISTEN_ADDR` | 本机监听 | `127.0.0.1:25565` | 改成 `0.0.0.0:25565` 会把桥暴露给同网段，不建议 |
| `CONNECT_TIMEOUT` | 握手超时（秒） | `15` | 只作用于建连 / CONNECT / TLS / ws 握手 |
| `HTTPS_PROXY` / `https_proxy` | 出站代理 | 空（直连） | 如 `http://127.0.0.1:7890`；**只从这里读，不写进 relay.conf** |
| `RELAY_CONFIG` | 配置文件的路径 | 脚本同目录 `relay.conf` | 想让配置文件放别处时用它 |

**优先级：环境变量 > relay.conf > 内置默认。** 空字符串一律视为「没设置」，会继续往下回落。

> **`MC_MODE=ws` 就是 wss**：TLS 证书校验始终内置在这条路径里——**先 TLS，再在其上做 WebSocket 升级**，
> 所以你不需要、也**没有**单独的 `wss` 取值。别人说「走 wss 协议」，你这里保持 `MC_MODE=ws` 即可
> （写 `wss` 会被当成非法值，启动时直接报错）。

几点行为约定：

- `MC_TARGET`、`MC_MODE`、`MC_WS_PATH`、`HTTPS_PROXY` 是**每条入站连接开始时重新读取**的，
  改配置只影响之后的新连接；`LISTEN_ADDR`、`CONNECT_TIMEOUT` 只在启动时读一次。
- 握手完成后**不再设读超时**：长会话（游戏挂机之类）不会因为这个桥被掐断。
- **不支持带用户名密码的代理**：代理地址里出现 `user:pass@` 会直接报错，不会静默降级成别的行为。
- 配置错误（目标缺失/格式不对、`MC_MODE` 非法、超时不是正数）都是**启动时打印 `启动失败: ...` 并以退出码 2 结束**；
  正常运行中停止是退出码 0。

---

## 六、排障：日志停在哪一行，就卡在哪一步

**先做这一步：确认你的出站到底走不走代理。** 走不走代理**只取决于环境变量**——配置文件和代码里
没有任何代理开关。所以「我不用代理」的正确落地方式是**先确认环境里没有残留的代理变量**：

```bash
env | grep -i proxy          # 期望：什么都不输出（=干净直连）
# 如果有输出（比如 HTTPS_PROXY=...），而你以为在直连，那多半就是它在起作用：
#   - 想用：保持设置即可（relay 会自动走 CONNECT）
#   - 不想用：env -u HTTPS_PROXY -u https_proxy python3 relay.py
```

然后再按顺序看日志，卡在哪一行就说明问题出在那一步：

| 日志停在这里 / 出现这行 | 含义与对策 |
| --- | --- |
| `启动失败: 未配置目标：...` | 没填 `MC_TARGET`。复制 `relay.conf.example` 为 `relay.conf` 并填写，或设环境变量 |
| `启动失败: MC_TARGET 端口不是整数` 之类 | 目标必须写成 `host:port`，端口别漏别写错 |
| 客户端报「连接被拒绝 / Connection refused」（连 `127.0.0.1:25565` 都连不上） | relay 没在跑，或它监听的端口不是客户端填的那个。检查 relay 终端里有没有 `mc-relay 启动：监听 …` 这一行 |
| 连 `直连目标:` / `CONNECT 通过:` 都没有 | TCP 层面就没通：目标地址/端口写错、代理没起来、或本机没有到目标的网络路径 |
| **直连模式**下握手异常（超时 / 证书报错 / 拿不到 101），而域名解析落到 `198.18.0.0/15`、`198.19.0.0/15` 这类保留段 | 本机有**透明代理**（TUN / fake-ip 类工具，如 Clash 的 TUN 模式）接管了出网，你看到的「直连」其实不是直连。先用 `getent hosts 你的域名` 看解析结果，再看 `ip route` 谁在默认路由上；要么把这类工具改成显式代理模式并设 `HTTPS_PROXY`，要么在它的规则里放行该域名 |
| `CONNECT 被代理拒绝: HTTP/1.1 403 ...` | 代理不放行这个目标；换代理或看代理策略 |
| `TimeoutError: timed out` | 卡在建连 / TLS / ws 握手：链路太慢、对端不可达、或代理没转发 |
| `ssl.SSLCertVerificationError: ...` | 证书链或主机名校验失败：目标证书不是公共 CA 签发，或本机根证书库不对 |
| TLS 过了、没有 `WS 升级: ...101` | 对端不是 WebSocket 端点（或路径 / `Host` 不对）——检查 `MC_WS_PATH` 与服务端反代配置 |
| `WS 升级被拒绝: HTTP/1.1 200 OK` | 同上：对端把 Upgrade 请求当普通 HTTP 处理了 |
| `Sec-WebSocket-Accept 校验失败: got=... expect=...` | 对端不是合规的 RFC6455 实现（或中间有东西改写了握手响应） |
| 关键行都齐了，但客户端连不上 | 卡在**服务端规则**：白名单、密码、服务端没起、或服务端到目标的最后一跳不通 |
| relay 报 `WS 升级被拒绝` / `Sec-WebSocket-Accept 校验失败` | 去**服务端**看：反代有没有透传 `Upgrade`/`Connection` 头、有没有改写响应 |
| relay 关键行齐了，但服务端 ws-bridge 日志没有 `握手完成` | 反代没把请求转到 ws-bridge：核对反代目标是不是 `127.0.0.1:25566`、`--listen` 有没有被改 |
| 服务端出现 `连接目标 ... 失败` / `Connection refused` | ws-bridge 的 `--target` 写错，或目标服务没起来 |
| 服务端出现 `收到 ping(...) -> 回 pong`/`收到 close 帧` 后连接结束 | 正常收尾，不是错误 |

服务端桥（ws-bridge）自己的关键日志行：

```
[INFO] ws-bridge 启动：监听 127.0.0.1:25566 -> 目标 127.0.0.1:25565 (RFC6455 服务端 / 二进制帧桥接)
[INFO]   [127.0.0.1:54321] 握手完成：GET / (Sec-WebSocket-Version=13)
[INFO]   目标已连接: 127.0.0.1:25565
[INFO] [#1] 连接关闭 上行=39 B 下行=29 B
```

看到 `握手完成` + `目标已连接` 说明这一环通了；只看到 `非 WebSocket 升级请求` 则说明
反代把请求当成了普通 HTTP（回到第 2 步检查第 2 点）。
| 用着用着掉线 | 先看桥日志有没有 `连接失败` / `ERROR`；偶发卡顿不必报（跨区链路抖动很常见） |

想单独验证「桥之外的链路通不通」，可以绕开桥直接打远端端点（用包里的 `wss_mc_probe.py`）：

```bash
python3 wss_mc_probe.py status your-domain.example 443 --tls
#  走代理时：  ... --tls --proxy=http://127.0.0.1:7890
```

---

## 七、出问题时怎么报

不需要你猜原因，把这四样**原样**发回来即可定位：

1. **启动行**：`mc-relay 启动：监听 ... -> 目标 ... (模式=..., 代理=..., 超时=...)`
2. **日志**：从启动到最后一行，**整段原样贴**（不要只挑一句；失败行的前后几行往往是关键）；
3. **你敲过的命令 + 它的完整输出 + `echo $?`**；
4. **环境**：操作系统、`python3 -V`、`MC_MODE`、`MC_TARGET`（可只给域名不给端口）、
   `HTTPS_PROXY`（打码可以，但要说清是「有」还是「空」）、复现时刻。

报告模板：

```
【现象】客户端停在「正在连接…」/ 报错原文：xxx
【时间】2026-xx-xx xx:xx
【环境】python3 x.y.z / OS / MC_MODE=ws / HTTPS_PROXY=<有|无>(主机:端口)
【命令】python3 relay.py  然后客户端连 localhost
【桥日志】<启动行 + 全部日志，原样>
【客户端报错】<原文或截图；没有就写「无」>
```

---

## 八、包里有什么

**客户端侧（放在玩游戏的机器上）**

| 文件 | 作用 | 必需? |
| --- | --- | --- |
| `relay.py` | 本地中继桥：裸 TCP ⇄ wss | **必需** |
| `relay.conf.example` | 配置模板，复制成 `relay.conf` 后填你的入口 | **必需**（复制一份） |
| `mc_status_ping.py` | MC 状态探针：打本机 25565 看能不能取到服务器信息 | 可选（排障） |
| `mc_login_probe.py` | MC 登录探针：验证账号能不能登录成功 | 可选（排障） |

> **关于这两个探针的 `HOST` 参数**：`python3 mc_status_ping.py <HOST> <PORT>` 里的 `HOST` 有**两个用途**——
> 既是 TCP 连接目标，也会被写进 MC 握手包的 *server address* 字段（就是真客户端里你填的那个地址）。
> 所以经 relay 测的时候填 `127.0.0.1` 是**故意的**：真实 MC 客户端也只填 `localhost`，
> 这样测出来的行为才和真客户端一致。填域名/别的地址测，走的就不是同一条模拟路径了。

**服务端侧（放在你的服务器上）**

| 文件 | 作用 | 必需? |
| --- | --- | --- |
| `ws-bridge.py` | 服务端桥：wss 帧 ⇄ 裸 TCP，把流量转给真正的服务 | **必需** |
| `wss_mc_probe.py` | wss 探针：可直接打 `wss://` 入口（或用明文打本机 ws-bridge）做对照 | 可选（排障） |

**其它**

| 文件 | 作用 |
| --- | --- |
| `README.md` | 本文件 |
| `LICENSE` | MIT |
| `.gitignore` | 已把 `relay.conf`（你自己的真实配置）排除在仓库外 |

```
mc-over-wss-relay/
├── relay.py               客户端桥，跑在本机：监听 127.0.0.1:25565
├── relay.conf.example     客户端配置模板（复制成 relay.conf）
├── ws-bridge.py           服务端桥，跑在你的服务器：监听 127.0.0.1:25566
├── README.md
├── LICENSE
├── .gitignore
├── mc_status_ping.py      可选探针
├── mc_login_probe.py      可选探针
└── wss_mc_probe.py        可选探针
```

- 三个探针都是**可选**的排障工具，不装也能正常玩；它们各自只做一件事，代码很短、可自行审读。
- `relay.conf`（你自己的真实配置）**不在仓库里**，见 `.gitignore`。

---

## 九、边界声明

- **TLS 证书校验恒开**：`ssl.create_default_context()` + 主机名校验，代码里没有 `CERT_NONE`、
  `check_hostname=False`、也没有任何「跳过校验」的开关（可自行 grep 验证）。
- **不支持代理认证**：带 `user:pass@` 的代理地址会明确报错，不会退化成别的行为。
- **`MC_MODE=tls` 已不推荐**：那是早期的裸 TLS 直通形态，只保留作回归对照；请用默认的 `ws`。
- **不做多路复用**：每条连接各自建一条独立的 TLS + WebSocket 会话，互不影响。
- **单帧上限 16 MiB**，超过按协议错误处理（防止异常大帧撑爆内存）。
- **不协商 WebSocket 扩展**（如压缩），按最朴素的帧格式工作。
- **默认只监听本机回环**；改成 `0.0.0.0` 等于把桥暴露给同网段其他人，不建议。
- 桥**只做字节转发，不解析上层协议**：它不解读你的游戏/应用数据，也不做任何内容改写。
- 桥不保证服务质量：链路延迟、抖动、断开由你的网络与远端服务决定，桥只负责搬运。
- **服务端桥（ws-bridge）不做任何鉴权**：任何能连到它监听端口的人都能用它转发到你的目标服务。
  它默认只绑 `127.0.0.1`，请把访问控制放在**反代那一层**（TLS 客户端证书、HTTP Basic、IP 白名单、
  只允许特定 `Host`/路径等），不要把它直接暴露到公网。
- **两端都不做流量审计/限速**：需要审计或限速请在反代层做。
