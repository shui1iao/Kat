# Kat

Kat 是用 Go 编写的 Linux 服务端代理内核，提供有界资源管理、TCP 转发和 UDP 转发。从 0.6.0 起，Kat 还可以把流量交给上游代理转发：支持出站、链式代理、策略组和规则分流。当前版本 **0.6.1**，命令名为 `kat`，模块名为 `github.com/shui1iao/Kat`。本项目不提供图形客户端、TUN 或公网管理接口。

## 入站协议范围

本版本正式说明的入站协议限于以下五类，不表示对所有客户端、扩展和网络环境全面兼容：

| 协议 | TCP | UDP 与边界 |
| --- | --- | --- |
| SOCKS5 | CONNECT；用户名/密码认证；仅回环地址允许无认证 | UDP ASSOCIATE；不支持 BIND、GSSAPI 或 UDP 分片重组 |
| AnyTLS | v2，兼容 v1；始终使用真实 TLS（省略 `tls` 时使用每次启动随机生成的自签证书，见下文）；逻辑多流与会话复用 | UoT v2 的连接及非连接模式，不是原生 UDP，不支持 UoT v1；FIN 关闭整个逻辑流，不承诺 TCP 半关闭 |
| Shadowsocks 2017 | 单身份 AEAD | 原生 UDP；支持下列三种方法，不支持旧式流密码 |
| Shadowsocks 2022 | 单身份 SIP022 | 原生 UDP；支持下列三种方法，不支持 EIH/iPSK 链或自动多用户密钥探测 |
| Trojan | 原版密码认证，TLS 1.2/1.3 | UDP-over-TLS；没有完整 fallback 或反探测行为，认证失败直接关闭 |

Shadowsocks 方法及凭据：

- SS2017：`aes-128-gcm`、`aes-256-gcm`、`chacha20-ietf-poly1305`，使用 `ss.password`，不填 `ss.key`。兼容性密码派生不是抗穷举密码加固机制，应使用高熵密码。
- SS2022：`2022-blake3-aes-128-gcm` 使用 16 字节密钥；`2022-blake3-aes-256-gcm`、`2022-blake3-chacha20-poly1305` 使用 32 字节密钥。将密码学安全随机字节编码为标准 Base64 填入 `ss.key`，不填 `ss.password`。
- SS 的 TCP 与原生 UDP 监听同一 IP 和端口；原生 UDP 按 `listen` 中的 IP 选择地址族（`0.0.0.0` 与 IPv4 用 IPv4，显式 IPv6 只用 IPv6）。SS2022 初始盐及固定头要求在一次底层读取中收到，**不保证任意首段 TCP 分片均可接受**；后续记录支持分片。

源码保留实验性 **VLESS / Snell** 实现，相关工作暂停；它们不属于本版本正式支持承诺。不能据此推断完整 VLESS 扩展、REALITY 各类组合、Snell v5 QUIC 或其他版本的兼容性。

## 构建与使用

使用 Go **1.26.9**。在仓库根目录构建 Linux amd64 静态二进制：

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o kat ./cmd/kat
./kat version
./kat check examples/socks5.json
./kat run examples/socks5.json
```

`version` 输出 `kat 0.6.1`。`check` 严格检查 JSON、未知字段、凭据组合、限额及 TLS 证书/私钥配对（AnyTLS 入站省略 `tls` 时，`check` 同样会在内存中生成一张随机证书，与之后 `run` 使用的不是同一张），也会读取出站 `tls.ca` 指定的文件，但不建立监听、不联网、不下载，也不读取规则集或 GeoIP 文件（它们在 `run` 时加载）。`run` 启动服务；收到 SIGINT/SIGTERM 后停止接入，在 `drain_timeout` 内等待，超时取消并回收。

`third_party/reality` 是带本地修改的实际构建依赖，不能删除或擅自移除 `go.mod` 中的本地 `replace`。首次构建需要准备 `go.mod`/`go.sum` 指定的依赖；依赖齐全后可以使用 `GOTOOLCHAIN=local GOPROXY=off GOFLAGS=-mod=readonly` 离线构建。源码未内置全部依赖缓存。

Release 提供 `kat-0.6.1-linux-amd64`、对应 `.sha256` 及第三方许可附件。可先校验，再改为便于调用的名称：

```sh
sha256sum -c kat-0.6.1-linux-amd64.sha256
chmod +x kat-0.6.1-linux-amd64
./kat-0.6.1-linux-amd64 version
```

## 配置与示例

`examples/` 提供以下配置。所有示例只监听回环地址，并把 UDP 出站源地址绑定到回环地址，**仅用于本地目标，不能直接当作公网部署配置**。示例密码和 SS2022 的递增字节密钥都是公开测试值，必须替换，不能用于真实服务。

- 入站：`socks5.json`、`shadowsocks-2017.json`、`shadowsocks-2022.json`、`trojan-tls.json`、`anytls-tls.json`。
- `dns-routing.json`：自定义 DNS 上游与直连/拒绝规则（上游指向本机 `127.0.0.1:5353`，需自行准备）。
- `routing.json`：出站、链式代理、四种策略组、规则与规则集；它的出站分别指向上面五份入站示例的本机端口，规则集示例在 `examples/rules/`。规则集路径相对启动时的工作目录，应在仓库根目录运行。

通用字段：

- `inbounds`：1–64 个入口；`protocol` 为协议标识，`listen` 为字面 IP 加端口，IPv6 使用 `[::1]:端口`。
- SOCKS5 的 `users` 使用 `username`/`password`；非回环监听必须配置用户，配置后不回退为无认证。SOCKS5 本身不加密，也不支持 TLS 包装，不应作为未加密的公网服务。
- Trojan 的 `users` 只使用 `password`，并且必须配置 `tls`。
- AnyTLS 使用 `anytls.password`，不填 `users`。`tls` 可以省略：省略时 Kat 使用每次启动随机生成的自签证书（ECDSA P-256，名称为 `localhost`，只在内存中，不写盘），**客户端必须跳过证书校验**；证书每次重启都会变，无法固定指纹，也无法用 CA 校验，因此不能防范中间人。写了 `tls` 时 `cert` 和 `key` 都必填，`tls` 写成 `null`、`{}` 或缺少其中任一项都会被拒绝。`max_sessions`、`max_streams`、`session_streams`、`stream_bytes`、`session_bytes`、`slow_timeout` 限制会话、逻辑流、缓冲和慢消费者。同密码的入口共享身份及预算，冲突配置会被拒绝。
- Shadowsocks 使用 `ss.method` 及相应凭据，不填 `users` 或 `tls`。`ss.tcp_salts`、`ss.salts_2017`、`ss.sessions` 控制有界保护状态；填 0 表示默认，不是禁用校验。相同方法和实际密钥的入口共享身份、重放保护及 UDP 关联，保护设置必须一致。
- `tls.cert`、`tls.key` 指向自行准备的证书和私钥，路径相对启动时的工作目录。Trojan/AnyTLS 入站示例需要先准备 `server.crt` 和 `server.key`（`anytls-tls.json` 演示的是自备证书写法）；`routing.json` 的 Trojan/AnyTLS 出站用同一份 `server.crt` 作为 `tls.ca`，证书需包含 `localhost`。仓库不附生产证书或私钥。
- `udp_bind_ipv4`、`udp_bind_ipv6` 可指定直连（direct）UDP 出站的本机源地址；省略时由系统路由选择。它们不是访问控制系统。

`limits` 的常用字段如下；计数或时长填 0/省略一般表示默认，`tcp_idle` 的 0 表示正式支持协议不启用该闲置超时。时长使用 `"5s"`、`"5m"` 等字符串。

| 字段 | 默认值 | 作用 |
| --- | --- | --- |
| `connections` / `logical_streams` | 1024 / 256 | 物理连接与逻辑流额度 |
| `handshakes` / `dials` | 64 / 64 | 并发握手及拨号额度 |
| `udp_associations` | 128 | UDP 关联额度 |
| `udp_queue` / `udp_queue_bytes` | 16 / `udp_queue × 65507` | 每关联队列的包数与载荷字节预算 |
| `udp_targets` | 64 | 每关联有效回包目标数 |
| `buffer_size` / `pool_buffers` | 16384 / 128 | 普通复制缓冲大小与池缓存数量 |
| `handshake_timeout` / `dial_timeout` | 10s / 5s | 握手与拨号超时；经代理出站时两者之和是拨号（含整条链路握手）的总预算 |
| `drain_timeout` / `udp_idle` | 5s / 60s | 退出等待与 UDP 闲置超时；`udp_idle` 也用于代理 UDP 会话的空闲回收 |
| `tcp_idle` | 0 | TCP 活动闲置超时，默认关闭 |
| `disable_fast_path` | false | 强制使用普通缓冲复制路径 |

这些额度不是整个进程的内存硬上限；TLS、协议保护状态、Go 栈和内核 socket 等还有额外开销。队列满可能丢弃 UDP 包。回包仅允许来自关联实际请求过且未过期的精确 IP:port，不承诺任意 full-cone。SOCKS5 UDP 不接受跨 IP 重绑定；同 IP 的不可信进程可能在未限定源端口时抢占首个 UDP 包，部署者需要限制访问。

SS 原生 UDP 的闲置按“最后一次合法活动之后”计时：通过认证的客户端包，以及来自已授权且未过期目标的合法回包，都会续期；未知或过期来源不续期。

### SS2017 可选接收缓冲

仅 Linux 的 SS2017 入口可选择 `ss.udp_rcvbuf_2017: 1048576`。**默认省略或 0，不改 socket 接收缓冲，也不占该额外预算**；其他非零值及 SS2022 使用此项都会被拒绝。

启用时按内核读回的接收缓冲值检查至少 1 MiB；原默认值已更大时不缩小。相对原值的正增量计入**全进程额外 8 MiB socket 接收额度上限**，不是进程总内存上限。额度不足、平台不支持或内核实际授予不足时明确失败，不静默降级，也不自动修改系统参数。较大缓冲可能减少短时突发丢包，但积压时会增加排队延时；应按实际业务选择，不是无条件推荐设置。

### SS2022 会话与来源迁移

0.5.19 复用 UDP 会话密码对象；0.5.20 将 UDP 解密和回包处理移出共享状态锁，并增加有界读取并发，不改变认证、重放窗口或目标回包限制。

同身份多个监听入口共享 UDP 会话。来源迁移必须先通过认证与重放校验；回包目的始终使用最新认证来源。迁移期间可能短暂从旧监听入口发出回包，**不承诺回包源监听入口立即切换**。需要固定源端口的客户端或网络策略应考虑这一边界。

## 出站、链式代理、策略组与规则分流

以下配置块都是可选的。**不写这些块时，转发方式与 0.5.20 相同：系统 DNS 加直连。** 新块中出现未知字段、显式 `null` 或空字符串，整份配置都会被拒绝；配置文件上限 1 MiB。完整示例见 `examples/routing.json`。

### DNS

`dns` 块决定直连出口和规则匹配时如何解析域名：

- `server`：省略或 `system` 为系统解析（不加应用层缓存）；也可以是 IP 或主机名（可带端口，默认 UDP 53）、`udp://主机[:端口]`、`tcp://主机[:端口]`，或 `https://主机[:端口]/路径`（DoH，POST，标准证书与 SNI 校验，不跟随重定向，没有跳过校验的选项）。上游写主机名时只用系统解析器引导一次。
- `cache_entries`：0–4096；自定义上游默认 256，0 关闭缓存；`system` 只能省略或填 0。缓存最长 300 秒，不做负缓存。
- A 与 AAAA 并发查询，单个地址族失败不影响另一族的结果，最多取 16 个地址。自定义上游失败时不回落到系统解析。
- Kat 不对客户端提供 DNS 服务，不支持 DoT、HTTP/3、FakeIP 或流量嗅探。

### 出站 `outbounds`（最多 256 个）

- 公共字段：`name`（1–64 字节，全局唯一，不能是 `direct` 或 `reject`，不能含空白、控制字符或 `=`）、`type`、`server`、`port`。可选 `via`（经由另一个出站、组或 `direct`），可选 `udp: false`（只承载 TCP）。
- `shadowsocks`：`method` 为 `aes-128-gcm` / `aes-256-gcm` / `chacha20-ietf-poly1305` 时用 `password`；为 `2022-blake3-aes-128-gcm` / `2022-blake3-aes-256-gcm` / `2022-blake3-chacha20-poly1305` 时用 Base64 的 `key`。
- `trojan`：`password`，`tls` 必填（可写 `{}`）。
- `anytls`：`password`，`tls` 必填；可选 `idle_sessions`（空闲会话池，默认 4，最大 32）与 `idle_timeout`（默认 30s，范围 1s–10m）。UDP 使用 UoT v2。
- `socks5`：可选 `username` 和 `password`，两者必须同时填写。
- `tls`：`server_name`、`ca`（PEM 文件）、`pin_sha256`（叶证书 DER 的 SHA-256，64 位十六进制）、`insecure: true`（显式关闭证书校验，不能与 `ca` 或 `pin_sha256` 同时使用）、`alpn`。默认使用系统根证书校验。自签证书请用 `ca` 或 `pin_sha256`，`insecure` 只适合排查问题；唯一例外是连接省略 `tls` 的 Kat AnyTLS 入站，它的证书每次重启都会变，只能使用 `insecure: true`。

**UDP 能力规则：**

- Trojan 的 UDP 与 AnyTLS 的 UoT 都封装在 TCP 流里，任何能走 TCP 的链路上都可用。
- Shadowsocks 与 SOCKS5 使用原生 UDP，只有前面整条链都能转发 UDP 时才可用；否则这个出站只承载 TCP，UDP 会被丢弃并记录 `udp_unsupported`。

**链式代理：** `via` 可以指向出站或组，最多 4 跳代理（组与 direct 不计入），出现环路时配置被拒绝。

### 策略组 `groups`（最多 64 个，每组成员最多 64 个）

通用行为：

- `members` 可以是出站、组或 `direct`；`reject` 只能放在 `select` 组里。
- 组的选择只影响新连接；UDP 会话进行中不换成员。
- 只在还没有发出客户端数据时换成员重试，每条连接最多试 3 个成员，**不重放已发出的数据**。因此 Shadowsocks/Trojan 的凭据错误要到第一次读写才暴露，那一条连接会失败，之后组会降级该成员。
- 切换成员时输出 `kat event=group_switch group=… from=… to=…`。

各类型：

- `select`：使用 `selected` 指定的成员，不写就用第一个。运行中没有切换接口，改选需要修改配置并重启。
- `url-test`：`probe.url` 必填，通过成员对该地址发 HTTP(S) GET，状态码小于 500 算成功；`probe.interval` 默认 10m，`probe.timeout` 默认 5s，组级 `tolerance` 默认 100ms。测速是惰性的：结果过期且组被使用时才重测；第一次使用先走首个成员，同时在后台测速。当前成员 60 秒内真实失败 3 次立即重测；当前成员的代理服务器直接拒绝连接（端口不通）时，一次即重测。
- `fallback`：按成员顺序，选最近测速成功、且真实连接没有连续 2 次失败的成员；前面的成员恢复后切回；全部不可用时用首个成员。
- `smart`：**Kat 自研算法**，设计时参考了 Surge、Egern 对智能策略组的公开描述，**不是对其实现的复刻**，行为和参数可能不同。
  - 评分 =（测速延迟与真实首包时间的平滑值 + 失败惩罚）× `priority`。平滑为 EWMA（α=0.3）；惩罚从 300ms 起、每次连续失败翻倍，上限 10s，每 5 分钟减半。
  - `priority` 按成员名设置，取值 (0, 100]，默认 1；它是乘数，大于 1 降低该成员的优先程度，小于 1 提高。
  - 算作失败：连接失败；发出数据后对方一个字节没回就断开；发出数据后 3 秒无回包；UDP 发包后 3 秒无回包。
  - 切换：候选成员要比当前成员好 20% 以上且至少快 30ms，并且当前成员已使用满 60 秒才换；当前成员出错时立即换。
  - 按目标主机记住最近 1 小时的成功与失败，最多 4096 条。默认每 5 分钟测速一次，连续 5 个周期没有使用就暂停。状态只保存在内存里。

### 规则 `routing`

- `rules`（最多 1024 条）从上到下匹配，命中第一条即停止。每条规则只能有一个匹配字段，再加 `action`（`direct` / `reject`）或 `outbound`（出站名或组名）二选一。
- 匹配字段：`domain`、`domain_suffix`（本域及其子域）、`domain_keyword`、`ip_cidr`、`src_ip_cidr`、`geoip`（国家码或 `private`）、`dst_port`（如 `"443"` 或 `"1000-2000"`）、`network`（`tcp` / `udp`）、`rule_set`。IP 类规则可加 `no_resolve: true`。
- `final`：所有规则都未命中时的去向，默认 `direct`。
- 域名目标遇到第一条需要 IP 的规则时，才用 `dns` 设置解析一次；交给代理的仍是原始域名。在任何需要 IP 的规则之前就命中域名规则并交给代理或拒绝时，不做本地 DNS 查询。直连时，解析出的多个地址逐个按规则判定，被拒绝的地址不会连接。
- 0.5.20 已有的写法 `{"domain" | "domain_suffix" | "ip_cidr": …, "action": …}` 继续有效。

### 规则集 `rule_sets`（最多 32 个）

- 字段：`name`、`format`、`path`（必填，本地文件或下载缓存位置）；可选 `url`（只接受 https）、`interval`（默认 24h，最小 1m）、`via`（下载时经由的出站或组）、`max_bytes`（默认 16 MiB，最大 64 MiB）。
- `format`：
  - `domain`：每行一个域名；以 `.`（Surge DOMAIN-SET 写法）或 `+.`（mihomo 写法）开头表示匹配该域及其子域。
  - `ipcidr`：每行一个 IPv4/IPv6 前缀。
  - `classical`：Surge / mihomo 常见行的子集，支持 `DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD`、`IP-CIDR`、`IP-CIDR6`、`GEOIP`、`DST-PORT`，可附 `no-resolve`；不支持的行会被跳过并计数。
  - 以 `#`、`;`、`//` 开头的行为注释。
- 远程更新：下载完成后先原子写入 `path`，再替换内存中的数据；**下载失败时保留旧数据**。启动时本地文件不存在，该规则集先按空集工作并告警，配置了 `url` 时会退避重试下载。
- 事件：`kat event=rule_set_loaded name=… entries=… skipped=…`、`rule_set_update_failed name=… class=…`。

### GeoIP

- `geoip` 块：`path`（MaxMind DB 格式的国家库 `.mmdb`，必填），`url`、`interval`、`via`、`max_bytes`（默认 64 MiB，最大 256 MiB）含义与规则集相同。
- **Kat 不内置、也不随源码或 Release 分发任何 GeoIP 数据**，国家库需要自行准备，并遵守该数据的许可。`geoip: "private"`（RFC 1918 私有、CGNAT、回环、链路本地、组播、文档与保留地址等）是内置判断，不需要数据库。
- 事件：`geoip_loaded`、`geoip_update_failed class=…`。

### 日志与新增错误类别

运行时诊断写到 stderr，使用固定类别，例如 `kat event=failure stage=resolve reason=dns_failed protocol=outbound inbound=-1 suppressed=0`。不记录凭据、业务内容、目标或客户端地址；同一类别每 5 秒最多输出一次，被抑制的次数附在下一次输出中。本版本新增 `stage=outbound reason=proxy_connect_failed`、`stage=outbound reason=udp_unsupported` 与 `stage=route reason=rule_data_unavailable`。

### 未支持的功能

- VLESS、Snell、HTTP 等其他出站协议；SS2022 EIH/多用户出站；uTLS 指纹。
- load-balance 组、条件组、订阅/外部节点组；运行中切换 `select` 的控制接口或持久化。
- 发出数据后的重放重试。
- AND/OR/NOT 逻辑规则、GeoSite、ASN、进程/UA/URL 规则；mrs/srs/YAML 规则集；mihomo YAML 配置兼容。

## 验证与性能口径

0.6.0 已有普通测试、出站与内核包的竞态检测、`GOOS=windows` 交叉编译，以及真实进程的端到端测试：出站、链式代理、四种策略组的切换与降级、各类规则命中的实际走向，均以 sing-box 1.14.3 和 Kat 自身作为本机上游服务端验证；另做过 2 小时本机回环浸泡。0.6.1 重新运行了全部普通测试、`GOOS=windows` 交叉编译和真实进程端到端测试，并为随机证书模式新增单元测试和真实进程端到端测试（以 Kat 自身的 AnyTLS 出站作为客户端）；竞态检测和回环浸泡没有针对 0.6.1 重做。它们不是一般安全审计，也不代表所有发行版、客户端与配置组合均已验证。

**尚未验证：** Windows 实机运行（只做了交叉编译）；真实 GeoIP 库与公网规则集下载（只用了自制 mmdb 和本机 HTTPS 源）；更长时间运行（只做过 2 小时回环浸泡）；高并发与性能（本版本没有做性能测试）；随机证书模式只用 Kat 自己的 AnyTLS 出站作为客户端测试过，其他客户端未测试。0.5.20 的静态二进制曾在 Debian 11 / glibc 2.31 完成版本与配置检查，0.6.0、0.6.1 构建方式相同，但没有重复该项检查。

0.5.20 记录的短时性能观察仅对应 Linux 主机的 **2 核 / 4 GiB、总带宽 5G、64 并发、每轮 10 秒并重复 3 次**的特定受限口径，且只涉及入站转发，不代表出站、策略组或规则分流的性能；它不是独立峰值、长期稳定性或生产就绪证明。本版本不作性能领先、长期 SLO 或生产可用性承诺。

## 权利与第三方许可

**Kat 自研代码保留所有权利。** 公开可读不等于授予任意使用、修改或再分发许可；本仓库不设顶层自研 `LICENSE`。

第三方代码、修改后的第三方受许可文件及其许可材料**仍各自遵循原许可**，不受上述自研权利声明替代或收回：

- `third_party/reality` 来源于 XTLS/REALITY 提交 `9234c772ba8f181f31c3e81dc2b4177322e5a9a9`，包含三个文件的本地修改，继续适用 MPL-2.0 及其中保留的许可。对应完整受许可源码、修改说明和差异见 [MPL 说明](MPL-NOTICE.md)、[修改说明](third_party/reality/STAGE_PATCHES.md) 与 `patches/reality/`。
- `github.com/juju/ratelimit v1.0.2` 使用 **LGPL-3.0 加静态/动态链接特别例外**；例外免除其明定的最小对应源码、最小应用代码及安装信息要求，不取消其他适用义务。原文、所引用 GPL-3.0 原文及来源见 `third_party/licenses/` 和 [第三方说明](THIRD_PARTY_NOTICES.md)。
- `github.com/oschwald/maxminddb-golang v1.13.1` 用于读取用户自备的 MaxMind DB 国家库，许可为 ISC，未作修改；原文见 `third_party/licenses/`。
- Go、密码及其他依赖的原始许可文本保留于 `third_party/licenses/` 和第三方源码目录。第三方许可赋予的权利，以及为行使这些权利所需的法定权利，不因 Kat 自研权利声明而受限。

随二进制分发时，应同时提供对应版本公开源码中的受许可文件、修改说明和第三方许可材料；Release 的第三方许可附件也保留这些法律文本。独立测试客户端不属于产品构建或本仓库分发内容。
