# Kat 0.6.2：默认额度调整，适配真实客户端并发

本版本提供中文源码说明，以及 Linux amd64 静态二进制、SHA-256 校验文件和第三方许可附件。相对 0.6.1 只调整默认值：调大全局 `limits` 和 AnyTLS 身份的默认额度，并把 AnyTLS 入站 `slow_timeout` 的默认值从 10s 改为 60s。各项取值范围、硬上限和显式填写时的行为都不变，其他功能与 0.6.1 相同。

## 变更

### 默认额度调大

- 全局 `limits` 默认值：`connections` 1024 → 4096，`handshakes` 64 → 512，`dials` 64 → 512，`udp_associations` 128 → 1024，`udp_targets` 64 → 256。`udp_queue`、`udp_queue_bytes`、`buffer_size`、`pool_buffers` 和各项超时不变。
- `logical_streams` 省略（或填 0）时，自动取 `max(8192, 所有不同密码 AnyTLS 身份的 max_streams 之和)`，同一密码出现在多个入口只计一次。因此多个 AnyTLS 身份都用默认额度也能通过 `kat check`；该和超过 65536 时仍然拒绝，需要为各身份显式填写 `max_streams`。显式填写 `logical_streams` 时不做任何调整，仍要求各身份之和不超过它。
- AnyTLS 默认值：`max_sessions` 32 → 512，`max_streams` 64 → 4096，`session_streams` 16 → 64（即上限）。`stream_bytes`、`session_bytes` 不变。
- Shadowsocks（`tcp_salts`、`sessions`、`salts_2017`）以及 Trojan、SOCKS5 没有需要改的协议级默认值，保持不变；后两者随全局额度一起放宽。

### AnyTLS 入站 `slow_timeout` 默认 10s → 60s

- `slow_timeout` 是 AnyTLS 会话的慢消费者及写入超时：缓冲满后，等待对端读取的最长时间，超时关闭整个会话。省略时的默认值从 10s 改为 60s（取值范围的上限）。
- 取值范围仍是 1ms–60s；显式填写时行为与 0.6.1 相同。只改了 Kat AnyTLS 入站的默认值，AnyTLS 出站不受影响。

### 其他

- 版本输出 `kat 0.6.2`。README 的“配置与示例”一节更新了 `limits` 默认值表，新增“AnyTLS 身份额度”表、`logical_streams` 自动取值规则和内存说明。

## 为什么

- 旧默认值来自早期偏保守的“有界资源”设计，当时只用 Kat 自己的客户端测试。Kat 客户端会复用会话，所以从来没撞到上限。
- Surge、mihomo、sing-box 等 AnyTLS 客户端在没有空闲会话时，会为每个并发请求新开一个会话（一条 TLS 连接）。因此 `max_sessions` 实际上等于同一密码下所有用户的并发连接数。32 个会话会被一个客户端很快占满，之后的新连接全部被拒（日志 `session_or_stream_budget`）。
- 用 sing-box 1.14.3 作客户端、在数百个并发流下实测，0.6.1 的默认值还会撞到 `handshakes`（连接突发时 `handshake_limit`）和 `udp_associations`（SS2022 UDP 关联在 `udp_idle` 内保留，累积后出现 `association_or_handshake_limit`）。新默认值下，同样的负载（AnyTLS、SS2022 各 320 条 TCP 下载加 100 个 UDP，Trojan 150 条加 50 个）零拒绝。
- sing-box 这类客户端在多路复用的会话上，单条流暂时不读会挡住整个会话。实测客户端暂停读取 6 秒、随后 500 个会话同时各下载 4 MiB 时，10s 的 `slow_timeout` 会把一部分会话以 `session_io` 关闭，多次测试只有 65%–81% 的下载完成；默认 60s 下 500 个全部成功。

## 兼容性

- **显式填写的值不变**：写在配置里的字段，取值、校验、错误信息和运行时效果都与 0.6.1 相同。
- **未填写的值会变大，升级后行为可能不同**：以前会因额度不足被拒绝的并发连接、握手和 UDP 关联，现在会被接受，进程内存占用也可能相应升高（见下文“内存”）；AnyTLS 会话在对端长时间不读时，要 60s 才会被关闭（原来 10s），期间占用的缓冲和连接释放得更晚。以前靠显式填写额度来绕开旧默认值的配置，可以保留不变。
- 原来会被 `kat check` 拒绝的“多个 AnyTLS 身份都用默认额度”（0.6.1 下 5 个及以上），现在可以通过。这样的配置不能退回 0.6.1 运行。
- **实验协议的连带变化**（只在未显式填写时）：实验性 Snell 的每 PSK 会话数与 XHTTP 的 `MaxConnections` 跟随 `connections`（1024 → 4096），VLESS mux 的 UDP 上限为 `min(udp_associations, 1024)`（128 → 1024）。这些协议的代码没有修改，仍不属于正式支持范围。
- 出站、链式代理、策略组、规则分流与 0.6.1 相同。

## 内存

- 正常使用时内存占用不大：在本机回环上用 sing-box 作客户端、几百个并发流测试（Kat 配置不写任何额度），进程 RSS 峰值约 35–105 MiB；500 个 AnyTLS 会话各下载 4 MiB、客户端先暂停读取 6 秒的压力场景约 105–116 MiB。数量超过额度时直接拒绝，内存不随请求数增长。
- 字节型缓冲的理论上界较大：持有凭据的使用者如果刻意把所有缓冲都占满，按新默认值计算，单个 AnyTLS 身份时约 **2.8 GiB**（0.6.1 默认值约 0.27 GiB）。其中 AnyTLS 会话缓冲 `min(max_sessions × 2 × session_bytes, max_streams × 2 × stream_bytes)` 约 1 GiB，UDP 关联队列 `udp_associations × udp_queue_bytes` 约 1 GiB，其余是连接复制缓冲、TLS 记录缓冲、UDP 读缓冲和 goroutine 栈；每多一个使用默认额度的 AnyTLS 身份再增加约 1 GiB。`slow_timeout` 改为 60s 不改变这些上界，只是对端不读时缓冲最多被占用 60s 才释放，占满上界也更容易维持。
- **内存较小的机器（例如 2 GB）或需要隔离不可信用户时，请在配置中显式填写更小的值。** 例如 `limits.udp_associations: 256`，以及 AnyTLS 的 `max_sessions: 128`、`max_streams: 1024`，可把上面两项最大的缓冲各降到约 256 MiB；也可以减小 `connections`、`session_bytes`、`stream_bytes`，或把 `slow_timeout` 写回 `10s`。本版本没有为小内存机器另设默认值。

## 已知限制

- 默认值面向几位用户的日常使用，不防持有凭据的恶意用户；理论内存上界见上文。
- 0.6.1 的已知限制全部沿用：
  - 随机证书模式（AnyTLS 入站省略 `tls`）下客户端必须跳过校验，无法校验服务端身份，也无法固定指纹；证书每次重启都会变，只存在于内存中，不能导出，不能指定名称或有效期。
  - 未支持：VLESS、Snell、HTTP 等其他出站协议；SS2022 EIH/多用户出站；uTLS 指纹；load-balance、条件组和订阅组；运行中切换 select 的控制接口；AND/OR/NOT 逻辑规则、GeoSite、ASN、进程/UA/URL 规则；mrs/srs/YAML 规则集；mihomo YAML 配置兼容。
  - 组不重放已发出的数据。Shadowsocks/Trojan 的凭据错误要到首次读写才暴露，经过该成员的第一条连接会失败，之后组才会降级它。
  - url-test 无法区分 Shadowsocks/Trojan 凭据错误与目标网站出错，只能按“60 秒内 3 次真实失败”触发重测；只有代理服务器直接拒绝连接时才立即重测。
  - 策略组的测速与评分状态只保存在内存中，重启后重新测速。
  - 入站方面沿用 0.5.20 的边界：SS2022 不支持 EIH/iPSK 链，初始盐与固定头不保证任意 TCP 首段分片可接受；AnyTLS UDP 使用 UoT v2，不是原生 UDP；Trojan 不含完整 fallback/反探测行为；同身份多监听入口迁移后可能短暂从旧入口回包。
  - VLESS / Snell 入站仍为实验实现且工作暂停，不作为正式支持承诺。
  - 示例是回环测试配置，公开占位密码/密钥不可部署；TLS 示例需要自行准备证书和私钥。

## 验证范围与未验证范围

已做：重新运行了全部普通测试、`go vet`、`GOOS=windows` 交叉编译，以及真实进程端到端测试（出站、链式代理、四种策略组、规则分流、随机证书模式，以 sing-box 1.14.3 和 Kat 自身作为本机上游服务端）。新增单元测试覆盖新默认值、显式值保持不变（加载后和启动后的运行时额度）、`logical_streams` 自动取值与多身份、`slow_timeout` 省略为 60s 且显式值原样生效。第三方客户端测试以 sing-box 1.14.3 为客户端、Kat 配置不写任何额度，只在本机回环上进行：AnyTLS、SS2022、Trojan 的数百并发流（TCP 下载加 UDP 回显）零拒绝；超出额度时被硬上限拒绝；AnyTLS 暂停读取后大下载的场景下，0.6.2 默认配置 500 个会话全部成功。0.6.0 做过的出站与内核包竞态检测、2 小时本机回环浸泡没有针对 0.6.2 重做。这些不等同全面安全审计、长期稳定性或生产就绪保证。

**未验证：**

- 第三方客户端并发只用 sing-box 测试过；没有用 Surge、mihomo 做负载，也没有跨公网、真实延迟下的测试。
- 没有在 2 GB 内存的机器上实测；内存结论来自测试机（约 8 GB 内存）上的进程 RSS 和按额度计算的上界。
- `udp_targets`（单个关联多目标）和 `dials`（慢目标排队）的调大依据是代码分析，测试负载没有直接撞到它们；Kat 的 SOCKS5 入站没有单独做第三方并发测试。
- Windows 实机运行（只做了交叉编译）。
- 真实 GeoIP 库与公网规则集下载（只用了自制 mmdb 和本机 HTTPS 源）。
- 长时间运行：只做过 2 小时回环浸泡，不足以排除缓慢的内存增长。
- 性能：本版本没有做性能测试，不作性能承诺。
- 0.6.2 二进制没有重复 0.5.20 在 Debian 11 / glibc 2.31 上做过的静态二进制检查（构建方式相同）。
- 随机证书模式只用 Kat 自己的 AnyTLS 出站作为客户端测试过；sing-box、mihomo 等其他客户端在跳过校验时连接随机证书服务端的情况没有测试。

## 附件与许可

Release 附件：

- `kat-0.6.2-linux-amd64`：Linux amd64 静态二进制（CGO_ENABLED=0，`-trimpath`）。不提供 Windows 二进制。
- `kat-0.6.2-linux-amd64.sha256`：校验文件，使用 `sha256sum -c kat-0.6.2-linux-amd64.sha256` 校验。
- `kat-0.6.2-third-party-licenses.txt`：第三方许可附件。

下载二进制时请同时保留 `kat-0.6.2-third-party-licenses.txt`。对应受许可源码及本地修改在本标签源码的 `third_party/reality/`、`patches/reality/`，其他原许可在 `third_party/licenses/`。REALITY 仍适用 MPL-2.0；juju/ratelimit 适用 LGPL-3.0 加静态/动态链接特别例外；maxminddb-golang v1.13.1 适用 ISC 许可。本版本没有新增第三方依赖。Kat 自研代码保留所有权利，没有顶层自研 LICENSE；该声明不替代或限制第三方原许可。
