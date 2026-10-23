# Kat

Kat 是用 Go 编写的 Linux 服务端代理内核，提供有界资源管理、TCP 转发和 UDP 转发。当前版本 **0.5.20**，命令名为 `kat`，模块名为 `github.com/shui1iao/Kat`。本项目不提供客户端、TUN、图形界面或公网管理接口。

## 协议范围

本版本正式说明的协议范围限于以下五类，不表示对所有客户端、扩展和网络环境全面兼容：

| 协议 | TCP | UDP 与边界 |
| --- | --- | --- |
| SOCKS5 | CONNECT；用户名/密码认证；仅回环地址允许无认证 | UDP ASSOCIATE；不支持 BIND、GSSAPI 或 UDP 分片重组 |
| AnyTLS | v2，兼容 v1；必须使用真实 TLS；逻辑多流与会话复用 | UoT v2 的连接及非连接模式，不是原生 UDP，不支持 UoT v1；FIN 关闭整个逻辑流，不承诺 TCP 半关闭 |
| Shadowsocks 2017 | 单身份 AEAD | 原生 UDP；支持下列三种方法，不支持旧式流密码 |
| Shadowsocks 2022 | 单身份 SIP022 | 原生 UDP；支持下列三种方法，不支持 EIH/iPSK 链或自动多用户密钥探测 |
| Trojan | 原版密码认证，TLS 1.2/1.3 | UDP-over-TLS；没有完整 fallback 或反探测行为，认证失败直接关闭 |

Shadowsocks 方法及凭据：

- SS2017：`aes-128-gcm`、`aes-256-gcm`、`chacha20-ietf-poly1305`，使用 `ss.password`，不填 `ss.key`。兼容性密码派生不是抗穷举密码加固机制，应使用高熵密码。
- SS2022：`2022-blake3-aes-128-gcm` 使用 16 字节密钥；`2022-blake3-aes-256-gcm`、`2022-blake3-chacha20-poly1305` 使用 32 字节密钥。将密码学安全随机字节编码为标准 Base64 填入 `ss.key`，不填 `ss.password`。
- SS 的 TCP 与原生 UDP 监听同一 IP 和端口。SS2022 初始盐及固定头要求在一次底层读取中收到，**不保证任意首段 TCP 分片均可接受**；后续记录支持分片。

源码保留实验性 **VLESS / Snell** 实现，相关工作暂停；它们不属于本版本正式支持承诺。不能据此推断完整 VLESS 扩展、REALITY 各类组合、Snell v5 QUIC 或其他版本的兼容性。

## 构建与使用

使用 Go **1.26.9**。在仓库根目录构建 Linux amd64 静态二进制：

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o kat ./cmd/kat
./kat version
./kat check examples/socks5.json
./kat run examples/socks5.json
```

`version` 输出 `kat 0.5.20`。`check` 严格检查 JSON、未知字段、凭据组合、限额及 TLS 证书/私钥配对，不建立监听。`run` 启动服务；收到 SIGINT/SIGTERM 后停止接入，在 `drain_timeout` 内等待，超时取消并回收。

`third_party/reality` 是带本地修改的实际构建依赖，不能删除或擅自移除 `go.mod` 中的本地 `replace`。首次构建需要准备 `go.mod`/`go.sum` 指定的依赖；依赖齐全后可以使用 `GOTOOLCHAIN=local GOPROXY=off GOFLAGS=-mod=readonly` 离线构建。源码未内置全部依赖缓存。

Release 提供 `kat-0.5.20-linux-amd64`、对应 `.sha256` 及第三方许可附件。可先校验，再改为便于调用的名称：

```sh
sha256sum -c kat-0.5.20-linux-amd64.sha256
chmod +x kat-0.5.20-linux-amd64
./kat-0.5.20-linux-amd64 version
```

## 配置与示例

`examples/` 提供 SOCKS5、SS2017、SS2022、Trojan、AnyTLS 五份配置。所有示例只监听回环地址，并把 UDP 出站源地址绑定到回环地址，**仅用于本地目标，不能直接当作公网部署配置**。示例密码和 SS2022 的递增字节密钥都是公开测试值，必须替换，不能用于真实服务。

- `inbounds`：1–64 个入口；`protocol` 为协议标识，`listen` 为字面 IP 加端口，IPv6 使用 `[::1]:端口`。
- SOCKS5 的 `users` 使用 `username`/`password`；非回环监听必须配置用户，配置后不回退为无认证。SOCKS5 本身不加密，也不支持 TLS 包装，不应作为未加密的公网服务。
- Trojan 的 `users` 只使用 `password`，并且必须配置 `tls`。
- AnyTLS 使用 `anytls.password` 和 `tls`，不填 `users`；`max_sessions`、`max_streams`、`session_streams`、`stream_bytes`、`session_bytes`、`slow_timeout` 限制会话、逻辑流、缓冲和慢消费者。同密码的入口共享身份及预算，冲突配置会被拒绝。
- Shadowsocks 使用 `ss.method` 及相应凭据，不填 `users` 或 `tls`。`ss.tcp_salts`、`ss.salts_2017`、`ss.sessions` 控制有界保护状态；填 0 表示默认，不是禁用校验。相同方法和实际密钥的入口共享身份、重放保护及 UDP 关联，保护设置必须一致。
- `tls.cert`、`tls.key` 指向自行准备的证书和私钥，路径相对启动时的工作目录。Trojan/AnyTLS 示例需要先准备 `server.crt` 和 `server.key`。仓库不附生产证书或私钥。
- `udp_bind_ipv4`、`udp_bind_ipv6` 可指定本机 UDP 出站源地址；省略时由系统路由选择。它们不是路由规则或访问控制系统。

`limits` 的常用字段如下；计数或时长填 0/省略一般表示默认，`tcp_idle` 的 0 表示正式支持协议不启用该闲置超时。时长使用 `"5s"`、`"5m"` 等字符串。

| 字段 | 默认值 | 作用 |
| --- | --- | --- |
| `connections` / `logical_streams` | 1024 / 256 | 物理连接与逻辑流额度 |
| `handshakes` / `dials` | 64 / 64 | 并发握手及拨号额度 |
| `udp_associations` | 128 | UDP 关联额度 |
| `udp_queue` / `udp_queue_bytes` | 16 / `udp_queue × 65507` | 每关联队列的包数与载荷字节预算 |
| `udp_targets` | 64 | 每关联有效回包目标数 |
| `buffer_size` / `pool_buffers` | 16384 / 128 | 普通复制缓冲大小与池缓存数量 |
| `handshake_timeout` / `dial_timeout` | 10s / 5s | 握手与拨号超时 |
| `drain_timeout` / `udp_idle` | 5s / 60s | 退出等待与 UDP 闲置超时 |
| `tcp_idle` | 0 | TCP 活动闲置超时，默认关闭 |
| `disable_fast_path` | false | 强制使用普通缓冲复制路径 |

这些额度不是整个进程的内存硬上限；TLS、协议保护状态、Go 栈和内核 socket 等还有额外开销。队列满可能丢弃 UDP 包。回包仅允许来自关联实际请求过且未过期的精确 IP:port，不承诺任意 full-cone。SOCKS5 UDP 不接受跨 IP 重绑定；同 IP 的不可信进程可能在未限定源端口时抢占首个 UDP 包，部署者需要限制访问。

### SS2017 可选接收缓冲

仅 Linux 的 SS2017 入口可选择 `ss.udp_rcvbuf_2017: 1048576`。**默认省略或 0，不改 socket 接收缓冲，也不占该额外预算**；其他非零值及 SS2022 使用此项都会被拒绝。

启用时按内核读回的接收缓冲值检查至少 1 MiB；原默认值已更大时不缩小。相对原值的正增量计入**全进程额外 8 MiB socket 接收额度上限**，不是进程总内存上限。额度不足、平台不支持或内核实际授予不足时明确失败，不静默降级，也不自动修改系统参数。较大缓冲可能减少短时突发丢包，但积压时会增加排队延时；应按实际业务选择，不是无条件推荐设置。

### SS2022 会话与来源迁移

0.5.19 复用 UDP 会话密码对象；0.5.20 将 UDP 解密和回包处理移出共享状态锁，并增加有界读取并发，不改变认证、重放窗口或目标回包限制。

同身份多个监听入口共享 UDP 会话。来源迁移必须先通过认证与重放校验；回包目的始终使用最新认证来源。迁移期间可能短暂从旧监听入口发出回包，**不承诺回包源监听入口立即切换**。需要固定源端口的客户端或网络策略应考虑这一边界。

## 验证与性能口径

该版本已有普通测试、竞态检测、五类协议的配置/启动冒烟，以及 SS2022 TCP/UDP 定向对比验证；静态二进制在 Debian 11 / glibc 2.31 环境完成版本与配置检查。它们不是一般安全审计，也不代表所有发行版、客户端与配置组合均已验证。

已有短时性能观察仅对应 Linux 主机的 **2 核 / 4 GiB、总带宽 5G、64 并发、每轮 10 秒并重复 3 次**的特定受限口径，不是独立峰值、长期稳定性或生产就绪证明；本版本不作性能领先、长期 SLO 或生产可用性承诺。

## 权利与第三方许可

**Kat 自研代码保留所有权利。** 公开可读不等于授予任意使用、修改或再分发许可；本仓库不设顶层自研 `LICENSE`。

第三方代码、修改后的第三方受许可文件及其许可材料**仍各自遵循原许可**，不受上述自研权利声明替代或收回：

- `third_party/reality` 来源于 XTLS/REALITY 提交 `9234c772ba8f181f31c3e81dc2b4177322e5a9a9`，包含三个文件的本地修改，继续适用 MPL-2.0 及其中保留的许可。对应完整受许可源码、修改说明和差异见 [MPL 说明](MPL-NOTICE.md)、[修改说明](third_party/reality/STAGE_PATCHES.md) 与 `patches/reality/`。
- `github.com/juju/ratelimit v1.0.2` 使用 **LGPL-3.0 加静态/动态链接特别例外**；例外免除其明定的最小对应源码、最小应用代码及安装信息要求，不取消其他适用义务。原文、所引用 GPL-3.0 原文及来源见 `third_party/licenses/` 和 [第三方说明](THIRD_PARTY_NOTICES.md)。
- Go、密码及其他依赖的原始许可文本保留于 `third_party/licenses/` 和第三方源码目录。第三方许可赋予的权利，以及为行使这些权利所需的法定权利，不因 Kat 自研权利声明而受限。

随二进制分发时，应同时提供对应版本公开源码中的受许可文件、修改说明和第三方许可材料；Release 的第三方许可附件也保留这些法律文本。独立测试客户端不属于产品构建或本仓库分发内容。
