# Kat 0.6.3：AnyTLS max_sessions 默认跟随 connections

本版本提供中文源码说明，以及 Linux amd64 静态二进制、SHA-256 校验文件和第三方许可附件。相对 0.6.2 只改一处默认值：AnyTLS 入站身份的 `max_sessions` 在省略或填 0 时，不再固定为 512，而是跟随全局 `limits.connections`。显式填写的值、各项取值范围和其他功能都与 0.6.2 相同。

## 变更

### AnyTLS `max_sessions` 默认值跟随 `connections`

- 省略（或填 0）时，`max_sessions` 等于 `limits.connections`。`connections` 也省略时为 4096，所以默认就是 4096（0.6.2 为 512）；把 `connections` 调小，未填写的 `max_sessions` 会一起变小。
- 显式填写的 `max_sessions` 行为不变：取值 1–65536，越界照旧被 `kat check` 拒绝，错误信息不变。
- 同一密码出现在多个入口时仍共享一个身份，冲突检查仍按生效值比较。`logical_streams` 的自动取值仍是 `max(8192, 各不同密码身份 max_streams 之和)`，与 `max_sessions` 无关。`kat check` 与 `kat run` 得到相同的值。
- 其他 AnyTLS 默认值（`max_streams` 4096、`session_streams` 64、`stream_bytes`、`session_bytes`、`slow_timeout` 60s）和全局 `limits` 默认值都没有改。

### 其他

- 版本输出 `kat 0.6.3`。README 的“AnyTLS 身份额度”表和内存说明相应更新。

## 为什么

- 用 mihomo v1.19.33 作客户端测试发现：mihomo 把每条 UDP 流放进一个独占的 AnyTLS 会话，并在最后一个包之后再保留 60 秒（mihomo 内部写死，不可配置）。所以 mihomo 系客户端占用的会话数约等于“并发 TCP 连接数 + 最近 60 秒内活跃的 UDP 流数”。几位用户共用同一个密码时，很容易超过 512，表现为日志 `session_or_stream_budget`。
- 本机回环实测（Kat 配置不写任何额度，mihomo 每轮 320 条 TCP 下载加 100 个 UDP，连续 3 轮）：0.6.2 在第 3 轮出现 131 次 `session_or_stream_budget` 拒绝，47 条 TCP、59 个 UDP 失败；0.6.3 两次重复都是 0 次拒绝，Kat 侧会话峰值约 620。
- 每个 AnyTLS 会话本来就占一个物理连接，受 `connections` 限制。让 `max_sessions` 默认跟随 `connections`，单一密码就能用到全局连接额度，用户只需要调 `connections` 一个值。

## 兼容性

- **显式填写的 `max_sessions` 不变**：取值、校验、错误信息和运行时效果都与 0.6.2 相同。
- **未填写时会话上限变大，升级后行为可能不同**：0.6.2 下因会话数达到 512 被拒绝的连接，现在会被接受，内存占用可能相应升高（见下文“内存”）。如果显式填写了小于 512 的 `connections` 而没有填 `max_sessions`，默认值会变小到 `connections`，但会话本来就受 `connections` 限制，实际可用的会话数不会减少。
- **同一密码多个入口、一个填写一个不填写**：冲突仍按生效值判断。0.6.2 下“一个入口省略、另一个入口写 `max_sessions: 512`”能通过（都是 512），0.6.3 下省略的那个变为 `connections`，两者不一致，`kat check` 会拒绝（`same AnyTLS identity has conflicting limits`）。升级前请让同一密码的各入口写相同的值，或都不写。
- **一个身份可以用满全部连接**：0.6.2 下每个密码最多 512 个会话，对多个密码之间有一定隔离；0.6.3 默认每个密码都能用到 `connections`。需要在多个密码之间分配额度时，请为各身份显式填写 `max_sessions`。
- 只用 0.6.3 默认值的配置可以退回 0.6.2 运行（会话上限回到 512）；上一条所说的“一个入口省略、另一个入口显式写成 `connections` 的值”这种配置，退回 0.6.2 时会被拒绝。
- AnyTLS 出站、其他入站协议、出站、链式代理、策略组、规则分流与 0.6.2 相同。

## 内存

- 正常使用时内存占用不大：在本机回环上用 sing-box 1.14.3 或 mihomo v1.19.33 作客户端、几百个并发流测试（Kat 配置不写任何额度），进程 RSS 峰值约 38–103 MiB；其中 mihomo AnyTLS 三轮背靠背、会话峰值约 620 时为 78–82 MiB。数量超过额度时直接拒绝，内存不随请求数增长。
- AnyTLS 会话缓冲的上界公式不变：`min(max_sessions × 2 × session_bytes, max_streams × 2 × stream_bytes)`，入、出方向分别计费。默认 `max_sessions` 变为 4096 后，前一项是 8 GiB，后一项（`max_streams` 4096 × 2 × 128 KiB）是 1 GiB，所以单身份仍约 **1 GiB**，由 `max_streams` 决定。
- 会话数上限变大后，每个会话还有不计入上式的固定开销：已关闭流的记录（每会话最多 1024 个流 ID，实测约 25 KiB）和少量控制帧队列。4096 个会话合计最多约 0.1 GiB（0.6.2 的 512 个会话约 12 MiB）。连接复制缓冲、TLS 记录缓冲、goroutine 栈原本就按 `connections` 4096 估算，不变。
- 因此持有凭据的使用者刻意占满所有缓冲时，单个 AnyTLS 身份的理论上界约 **2.9 GiB**（0.6.2 估算约 2.8 GiB）：AnyTLS 会话缓冲约 1 GiB，UDP 关联队列 `udp_associations × udp_queue_bytes` 约 1 GiB，其余是连接复制缓冲、TLS 记录缓冲、UDP 读缓冲、goroutine 栈和上述每会话开销；每多一个使用默认额度的 AnyTLS 身份再增加约 1 GiB。
- **内存较小的机器（例如 2 GB）或需要隔离不可信用户时，请在配置中显式填写更小的值。** 例如 `limits.udp_associations: 256`，以及 AnyTLS 的 `max_sessions: 128`、`max_streams: 1024`，可把上面两项最大的缓冲各降到约 256 MiB；也可以减小 `connections`（未填写的 `max_sessions` 随之变小）、`session_bytes`、`stream_bytes`，或把 `slow_timeout` 写回 `10s`。本版本没有为小内存机器另设默认值。

## 已知限制

- 默认值面向几位用户的日常使用，不防持有凭据的恶意用户；理论内存上界见上文。默认情况下一个密码可以占满全部 `connections`，多个密码之间不再有默认的会话隔离。
- mihomo 的 UDP 流会占住会话 60 秒，这是客户端行为，Kat 无法提前回收；大量短 UDP 流仍可能在 `connections` 用满时被拒绝。
- 0.6.2 的已知限制全部沿用：
  - 随机证书模式（AnyTLS 入站省略 `tls`）下客户端必须跳过校验，无法校验服务端身份，也无法固定指纹；证书每次重启都会变，只存在于内存中，不能导出，不能指定名称或有效期。
  - 未支持：VLESS、Snell、HTTP 等其他出站协议；SS2022 EIH/多用户出站；uTLS 指纹；load-balance、条件组和订阅组；运行中切换 select 的控制接口；AND/OR/NOT 逻辑规则、GeoSite、ASN、进程/UA/URL 规则；mrs/srs/YAML 规则集；mihomo YAML 配置兼容。
  - 组不重放已发出的数据。Shadowsocks/Trojan 的凭据错误要到首次读写才暴露，经过该成员的第一条连接会失败，之后组才会降级它。
  - url-test 无法区分 Shadowsocks/Trojan 凭据错误与目标网站出错，只能按“60 秒内 3 次真实失败”触发重测；只有代理服务器直接拒绝连接时才立即重测。
  - 策略组的测速与评分状态只保存在内存中，重启后重新测速。
  - 入站方面沿用 0.5.20 的边界：SS2022 不支持 EIH/iPSK 链，初始盐与固定头不保证任意 TCP 首段分片可接受；AnyTLS UDP 使用 UoT v2，不是原生 UDP；Trojan 不含完整 fallback/反探测行为；同身份多监听入口迁移后可能短暂从旧入口回包。
  - VLESS / Snell 入站仍为实验实现且工作暂停，不作为正式支持承诺。
  - 示例是回环测试配置，公开占位密码/密钥不可部署；TLS 示例需要自行准备证书和私钥。

## 验证范围与未验证范围

已做：重新运行了全部普通测试、全部包的竞态检测（`-race`）、`go vet`、`GOOS=windows` 交叉编译，以及真实进程端到端测试（出站、链式代理、四种策略组、规则分流、随机证书模式，以 sing-box 1.14.3 和 Kat 自身作为本机上游服务端）。新增单元测试覆盖：省略或填 0 的 `max_sessions` 等于 `connections`（`connections` 省略时 4096，写 1000 时 1000）；显式值保持原值、越界照旧拒绝；同一密码多个入口共享身份与冲突判断；`kat check` 与 `kat run` 结果一致，以及重新校验时跟随变化后的 `connections`。新测试放到 0.6.2 源码上会失败（显式值相关的测试照常通过）。

第三方客户端测试只在本机回环上进行，Kat 配置不写任何额度：

| 客户端 | 协议与负载 | 0.6.3 拒绝数 | Kat RSS 峰值 | Kat 侧会话/连接峰值 |
| --- | --- | --- | --- | --- |
| mihomo v1.19.33 | AnyTLS，320 TCP + 100 UDP，连续 3 轮（两次） | 0、0 | 81.4、77.5 MiB | 619、620 |
| mihomo v1.19.33 | 同上，0.6.2 对照 | 131（`session_or_stream_budget`） | 78.2 MiB | 527（会话数卡在 512，多出的 TLS 连接被拒） |
| mihomo v1.19.33 | Shadowsocks 2022，320 TCP + 100 UDP，3 轮 | 0 | 102.7 MiB | 320 |
| mihomo v1.19.33 | Trojan，150 TCP + 50 UDP，3 轮 | 0 | 48.6 MiB | 294 |
| sing-box 1.14.3 | AnyTLS，320 TCP + 100 UDP，3 轮 | 0 | 63.3 MiB | 451 |
| sing-box 1.14.3 | Shadowsocks 2022，320 TCP + 100 UDP，3 轮 | 0 | 94.2 MiB | 320 |
| sing-box 1.14.3 | Trojan，150 TCP + 50 UDP，2 轮 | 0 | 38.2 MiB | 200 |

这些不等同全面安全审计、长期稳定性或生产就绪保证。

**未验证：**

- 第三方客户端并发只用 sing-box 和 mihomo 测试过；没有用 Surge，也没有跨公网、真实延迟下的测试。
- 没有在 2 GB 内存的机器上实测；内存结论来自测试机（约 8 GB 内存）上的进程 RSS 和按额度计算的上界。没有实测 4096 个会话同时在线时的内存。
- `udp_targets`（单个关联多目标）和 `dials`（慢目标排队）的调大依据是代码分析，测试负载没有直接撞到它们；Kat 的 SOCKS5 入站没有单独做第三方并发测试。
- Windows 实机运行（只做了交叉编译）。
- 真实 GeoIP 库与公网规则集下载（只用了自制 mmdb 和本机 HTTPS 源）。
- 长时间运行：0.6.2 发布后做过一次约 7 小时的本机回环浸泡（0.6.2 源码，仅额外启用本机诊断接口）：Shadowsocks 2022 与 AnyTLS 入站都使用默认额度，sing-box 1.14.3 作客户端，混合 TCP/UDP 负载，期间 4 次断开上游或强杀客户端，负载结束后再观察 30 分钟回落，没有发现内存、goroutine 或文件描述符泄漏。0.6.3 只改了默认值，没有重做浸泡。更长时间的运行和非回环环境下的运行没有验证。
- 性能：本版本没有做性能测试，不作性能承诺。
- 0.6.3 二进制没有重复 0.5.20 在 Debian 11 / glibc 2.31 上做过的静态二进制检查（构建方式相同）。
- 随机证书模式只用 Kat 自己的 AnyTLS 出站、sing-box 和 mihomo（跳过证书校验，本机回环）作为客户端测试过；其他客户端没有测试。

## 附件与许可

Release 附件：

- `kat-0.6.3-linux-amd64`：Linux amd64 静态二进制（CGO_ENABLED=0，`-trimpath`）。不提供 Windows 二进制。
- `kat-0.6.3-linux-amd64.sha256`：校验文件，使用 `sha256sum -c kat-0.6.3-linux-amd64.sha256` 校验。
- `kat-0.6.3-third-party-licenses.txt`：第三方许可附件。

下载二进制时请同时保留 `kat-0.6.3-third-party-licenses.txt`。对应受许可源码及本地修改在本标签源码的 `third_party/reality/`、`patches/reality/`，其他原许可在 `third_party/licenses/`。REALITY 仍适用 MPL-2.0；juju/ratelimit 适用 LGPL-3.0 加静态/动态链接特别例外；maxminddb-golang v1.13.1 适用 ISC 许可。本版本没有新增第三方依赖。Kat 自研代码保留所有权利，没有顶层自研 LICENSE；该声明不替代或限制第三方原许可。
