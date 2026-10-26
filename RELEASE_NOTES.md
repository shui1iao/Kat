# Kat 0.7.0：热重载、自动证书、规则嗅探与动态策略组

这是整批 0.7 功能的首个公开版本，接续 v0.6.3。开发阶段的编号不代表已公开的多个版本。本次只发布 GitHub 源码、标签与 Linux amd64 附件，不自动更新已运行的服务。

## 主要变化

### 日志、统计与本机管理

- 可选分级 text/JSON 日志、文件轮转与访问日志；不配置日志时仍是 stderr、text、info。访问日志默认关闭，开启后记录完整目标和截断来源（IPv4 /24、IPv6 /48）；连接明细同样默认关闭。安全查询命令可显示完整来源，诊断来源事件仅显示截断前缀。请按需启用并管理权限与保存时间，勿把所有日志都视为无敏感信息。
- 有效载荷字节统计、全局/入站/出站/组/规则计数、速率、累计值持久化、连接明细与关闭操作。计量不包含协议/TLS/TCP/IP 封装，不等同网卡或服务商计费。
- 本机管理 API 与 `kat stats/conns/log/reload/select/bans`。默认 Unix socket 使用本用户权限；可选 TCP 只允许回环并必须配置密钥，不是公网 API，也不兼容 Clash API。

### 全配置热重载与持久选择

- SIGHUP 或 `kat reload` 重读启动配置；核心转发配置准备成功后切换，新连接用新配置，已建 TCP/UDP 流保留旧代直至结束。同地址监听复用，准备失败保持原配置。
- 入站增删改、出站、策略组、规则/数据、DNS、额度、日志、安全等均接入；统计按名称延续，不因重载清零。
- `kat select` 切换只影响新连接，选择可持久化，成员消失或配置默认值改变时回配置。不是监视整份配置文件自动重载。

### TLS 与自动证书

- Trojan/AnyTLS 入站：外部证书文件跟随、reload 换证、SNI 多证书与客户端算法选择、ALPN、TLS 1.2/1.3 版本范围、TLS 1.2 安全套件。无效新证书保留旧证书，换证不切断已有流。
- ACME 四种使用方式：Cloudflare DNS-01、HTTP-01 独立监听、HTTP-01 webroot、TLS-ALPN-01；持久保存账户/证书，自动续期和失败退避。仅显式配置时启用；默认 CA 为 Let's Encrypt 正式环境，试用应显式指定 staging。公网挑战可达性与 DNS Token 权限需由部署者准备。
- Trojan/AnyTLS 出站可用 uTLS 客户端指纹；默认仍用标准 TLS，CA/证书 pin 校验方式不变。
- 入站与内置 direct 出站可选 TFO，**默认关闭，不改系统 sysctl**，依赖 Linux/内核及对应系统位支持。详见 [TLS/ACME/TFO 文档](docs/tls-acme-tfo.md)。

### 来源安全与 SOCKS5

- 可选认证失败临时封禁、每 IP TCP 并发上限、每入站来源黑白名单；封禁与并发限制默认关闭，IPv6 按 /64 记账；UDP 认证失败不计猜密，防止伪造来源误封。封禁跨重载保留，关闭即清空、重启清空。
- Trojan TLS 握手后支持可选 TCP fallback，不是完整反探测系统。**即使未配置 fallback，首个非法 Trojan 字节会立即失败，不再等满 56 字节**，可能改变探测时序。
- SOCKS5 BIND 默认关闭；启用后只按请求目标 IP 匹配对端，不用 DST.PORT 筛选；直连转发，不经过路由规则。
- SOCKS5 UDP 分片有界重组默认开启，默认每关联最多 65535 字节、全局 4 MiB、5 秒超时。**允许乱序，不采用 RFC 1928 较小 FRAG 重置队列要求**；回包不分片，不宣称严格 RFC 全兼容。BIND/分片专项使用独立协议客户端，不冒称主流客户端扩展覆盖。

### 规则、数据格式与嗅探

- 增加域名正则/通配符、IP 后缀/ASN、来源地理/ASN/端口、入站名字/类型/端口、协议和嵌套 AND/OR/NOT；端口支持范围与列表。
- GeoSite 与 ASN 数据按用户配置加载/更新；支持文本、Clash YAML、mihomo MRS、sing-box SRS/JSON、Surge RULE-SET/DOMAIN-SET 的受支持子集。未知类型/字段明确拒绝，保留旧数据，不静默兼容不支持的规则。
- 入站可选 TLS SNI、HTTP Host、QUIC Initial SNI 嗅探，**默认关闭**；默认只用于匹配，不覆盖实际目标。开启目标覆盖时重新解析且仍受安全限制。只读首包，超时/端口边界见 README。
- 不分发 GeoIP/GeoSite/ASN 数据，部署者需自行准备并遵守数据许可。

### 策略组与 provider

- `load-balance` 支持 round-robin、consistent-hashing、sticky-sessions；`relay` 提供有序独立克隆链（最多四跳）。健康检查、lazy、失败阈值、预期状态码与动态成员过滤可配置。
- HTTP/file provider 解析 Clash 节点、URI/base64 列表、sing-box 出站；仅支持既有 SS/Trojan/AnyTLS/SOCKS5 节点，不是整份客户端配置兼容。缓存与失败保旧、节点改名/跳过报告、动态配置代重建、现有流保留和 select 状态均接入。
- provider 的客户端指纹映射到 Trojan/AnyTLS uTLS，证书 fingerprint 仍是证书 pin，两者不互相覆盖。订阅 URL、请求头和节点凭据不写入报告；不支持的插件、传输、多路复用等字段有明确边界。

## 默认值、升级与兼容性

- **客户端代理流量默认禁止直连回环、未指定地址及其映射形式**，包括管理回环接口。确需本机目标可显式 `security.allow_loopback: true`，但会扩大可访问面；管理 TCP 密钥仍必需。私网默认允许，`block_private` 默认 false。内核自身 DNS/探测/订阅及连接上游代理不受客户端目标限制。
- **SIGHUP 从 0.6.x 的默认退出改为 reload。** 依赖 SIGHUP 重启的脚本应改用 SIGTERM 或显式 restart；SIGINT/SIGTERM 仍按 drain_timeout 正常退出。
- 资源额度和 AnyTLS `max_sessions` 跟随 `limits.connections` 的默认值保持 v0.6.3；额度不是全进程内存硬上限。旧配置通常可用，但默认回环限制可能有意阻止以前能访问的目标，升级前先 `kat check`。
- 新增状态目录、统计与管理 socket 默认路径可能需要服务沙箱授予写权限。示例均为回环测试配置，公开密码/密钥不可用于真实服务。
- 不新增多用户、mTLS、ECH 或 Kat-Manager 功能适配；附件名称、校验文件与版本命令沿用既有下载校验格式，不代表所有管理功能已有适配。

## 保留的已知限制

1. **未补 6 小时测试**；本次集成版为一次 2 小时负载加 5 分钟恢复，不把旧版本的更长测试当作本版证明。
2. **AnyTLS 已建 carrier 不被改密/删入站撤销**，仍能新开逻辑流，直到 carrier 关闭；新 carrier 按新配置认证。
3. **`api` 与 `stats.file` 重载不是原子切换**。新端口/socket无法监听、统计文件被占用时只告警，不回滚已生效转发配置。

这些行为本版未修改。实验性 VLESS/Snell 代码保留但不属于正式支持承诺；不保证任意扩展/客户端组合兼容。

## 验证范围与例外

- 集成代码：全包 `go vet`、20 个包普通单元测试通过；重点 kernel/group 名称筛选的 race 通过，**非全部包 race**，provider 独立包未被筛选命中。
- sing-box 1.14.3 与 mihomo v1.19.33：SS2022、AnyTLS、Trojan、SOCKS5，TCP/UDP，嗅探关/开两轮共 16 组。UDP 经代理查 `whoami.cloudflare` 核对出口，不只是 echo。
- 一次本机回环混合负载 7200.220 秒，同一进程恢复 300.087 秒；SS2022/AnyTLS 的 TCP 长短流、UDP，239 次负载内 reload、160 次 provider 节点变更，旧流/新流各 320 次校验。客户端错误为空，goroutine 16→16、fd 15→15，HeapLive 采样峰约 64.38 MB、恢复约 6.06 MB，无 OOM。未见本场景下持续无界增长；不作性能或普遍无泄漏保证。外围观察器曾误报一次进程归属，正式测试控制器成功，独立清场已核实，不宣称全部工具退出码均零。
- 发布准备另做精确版本、公开示例、只读配置兼容检查及少量 CLI 定向测试；不重跑长矩阵。
- **未针对最终集成版重做**：全部包 race、Windows 构建/实机、真实 ACME 重新签发/续期、TFO 抓包、超过 4096 并发压力、全部规则/组/订阅矩阵及公网长时间延迟场景。分项历史证据不等于最终版本完整发布验收。上述检查不是一般安全审计。

## 附件与许可

本次附件仅 Linux amd64：

- `kat-0.7.0-linux-amd64`
- `kat-0.7.0-linux-amd64.sha256`（`<hash>  kat-0.7.0-linux-amd64`，与既有下载校验格式兼容）
- `kat-0.7.0-third-party-licenses.txt`

Go 1.26.9，CGO 关闭，`-trimpath -buildvcs=false` 构建。源码标签为 `v0.7.0`。本地 REALITY replace、MPL 源码与补丁、LGPL 链接例外及其余第三方许可保留；Kat 自研代码仍保留所有权利，第三方许可赋予的权利不受影响。详见 [第三方说明](THIRD_PARTY_NOTICES.md) 和 [MPL 说明](MPL-NOTICE.md)。
