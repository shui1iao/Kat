# Kat 0.6.0：出站、链式代理、策略组与规则分流

本版本提供中文源码说明，以及 Linux amd64 静态二进制、SHA-256 校验文件和第三方许可附件。所有新功能都由可选配置块启用；不写新块时仍是系统 DNS 加直连，原有入站协议与配置写法不变。

## 主要内容

- **出站**：SOCKS5、Shadowsocks（SS2017 三种 AEAD 方法与 SS2022 三种方法）、Trojan、AnyTLS（UoT v2）客户端。TLS 支持默认证书校验、自备 CA、叶证书 SHA-256 固定，以及显式关闭校验。
- **链式代理**：`via` 指向出站或策略组，最多 4 跳，环路拒绝。Trojan/AnyTLS 的 UDP 封装在 TCP 中，可经任意链路；Shadowsocks/SOCKS5 的原生 UDP 只在整条链都能转发 UDP 时可用，否则该出站只承载 TCP。
- **策略组**：select、url-test、fallback、smart。只在发出客户端数据之前换成员重试，最多 3 个，不重放。url-test 在当前成员的代理服务器直接拒绝连接时立即重测。smart 是 Kat 自研算法，参考 Surge、Egern 的公开描述设计，不是对其实现的复刻。
- **规则分流**：domain、domain_suffix、domain_keyword、ip_cidr、src_ip_cidr、geoip、dst_port、network、rule_set，动作为 direct、reject 或指定出站/组，`final` 兜底，IP 类规则支持 `no_resolve`。0.5.20 的直连/拒绝写法继续有效。
- **规则集**：domain、ipcidr、classical 三种文本格式（兼容 Surge / mihomo 常见写法的子集），可用本地文件，也可配置 https 地址定期更新；下载结果原子写入，失败时保留旧数据。
- **GeoIP**：读取用户自备的 MaxMind DB 国家库（使用 ISC 许可的 maxminddb-golang）；内置 `private` 地址判断，不需要数据库。**Kat 不内置、也不分发任何 GeoIP 数据。**
- **DNS**：可选 `dns` 块支持系统解析、UDP/TCP 上游与 DoH，带有界缓存；直连出口和规则匹配都使用它。
- **诊断**：stderr 输出固定类别的错误日志（`kat event=failure stage=… reason=…`），不含凭据、目标或客户端地址，同类限频；新增 `proxy_connect_failed`、`udp_unsupported`、`rule_data_unavailable` 三个类别，以及 `group_switch`、`rule_set_loaded` 等事件。
- **SS 原生 UDP**：按 `listen` 的 IP 选择地址族；闲置改为从最后一次合法活动起计时（客户端认证包或已授权目标的合法回包都会续期），仍使用 `limits.udp_idle`。
- 版本输出 `kat 0.6.0`。字段、行为和限制详见 README 的“出站、链式代理、策略组与规则分流”一节；完整回环示例见 `examples/routing.json`。

## 已知限制

- 未支持：VLESS、Snell、HTTP 等其他出站协议；SS2022 EIH/多用户出站；uTLS 指纹；load-balance、条件组和订阅组；运行中切换 select 的控制接口；AND/OR/NOT 逻辑规则、GeoSite、ASN、进程/UA/URL 规则；mrs/srs/YAML 规则集；mihomo YAML 配置兼容。
- 组不重放已发出的数据。Shadowsocks/Trojan 的凭据错误要到首次读写才暴露，经过该成员的第一条连接会失败，之后组才会降级它。
- url-test 无法区分 Shadowsocks/Trojan 凭据错误与目标网站出错，只能按“60 秒内 3 次真实失败”触发重测；只有代理服务器直接拒绝连接时才立即重测。
- 策略组的测速与评分状态只保存在内存中，重启后重新测速。
- 入站方面沿用 0.5.20 的边界：SS2022 不支持 EIH/iPSK 链，初始盐与固定头不保证任意 TCP 首段分片可接受；AnyTLS UDP 使用 UoT v2，不是原生 UDP；Trojan 不含完整 fallback/反探测行为；同身份多监听入口迁移后可能短暂从旧入口回包。
- VLESS / Snell 入站仍为实验实现且工作暂停，不作为正式支持承诺。
- 示例是回环测试配置，公开占位密码/密钥不可部署；TLS 示例需要自行准备证书和私钥。

## 验证范围与未验证范围

已做：普通测试、出站与内核包的竞态检测、`GOOS=windows` 交叉编译，以及真实进程端到端测试（出站、链式代理、四种策略组的切换与降级、各类规则命中的实际走向，以 sing-box 1.14.3 和 Kat 自身作为本机上游服务端），另有 2 小时本机回环浸泡。这些不等同全面安全审计、长期稳定性或生产就绪保证。

**未验证：**

- Windows 实机运行（只做了交叉编译）。
- 真实 GeoIP 库与公网规则集下载（只用了自制 mmdb 和本机 HTTPS 源）。
- 长时间运行：只做过 2 小时回环浸泡，不足以排除缓慢的内存增长。
- 高并发与性能：本版本没有做性能测试，不作性能承诺。
- 0.6.0 二进制没有重复 0.5.20 在 Debian 11 / glibc 2.31 上做过的静态二进制检查（构建方式相同）。

## 附件与许可

Release 附件：

- `kat-0.6.0-linux-amd64`：Linux amd64 静态二进制（CGO_ENABLED=0，`-trimpath`）。不提供 Windows 二进制。
- `kat-0.6.0-linux-amd64.sha256`：校验文件，使用 `sha256sum -c kat-0.6.0-linux-amd64.sha256` 校验。
- `kat-0.6.0-third-party-licenses.txt`：第三方许可附件。

下载二进制时请同时保留 `kat-0.6.0-third-party-licenses.txt`。对应受许可源码及本地修改在本标签源码的 `third_party/reality/`、`patches/reality/`，其他原许可在 `third_party/licenses/`。REALITY 仍适用 MPL-2.0；juju/ratelimit 适用 LGPL-3.0 加静态/动态链接特别例外；本版本新增的 maxminddb-golang v1.13.1 适用 ISC 许可。Kat 自研代码保留所有权利，没有顶层自研 LICENSE；该声明不替代或限制第三方原许可。
