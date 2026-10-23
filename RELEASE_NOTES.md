# Kat 0.5.20：静态构建与 UDP 会话改进

本版本提供中文源码说明，以及 Linux amd64 静态二进制、SHA-256 校验文件和第三方许可附件。

## 主要内容

- 项目、模块与命令统一为 Kat、`github.com/shui1iao/Kat`、`kat`；版本输出 `kat 0.5.20`。
- 正式说明范围为 SOCKS5、AnyTLS、SS2017、SS2022、Trojan，具体 TCP/UDP 和密码方法边界见 README。
- 包含 SS2017 可选 1 MiB UDP 接收缓冲：默认关闭，全进程额外 socket 接收额度上限 8 MiB；增大缓冲可能增加排队延时。
- 包含 0.5.19 的 SS2022 UDP 会话密码对象复用，以及 0.5.20 的解密/回包移出共享锁和有界读取并发改进。

## 已知限制

- 同身份多监听入口共享 SS2022 UDP 会话。迁移后回包目的始终为最新认证来源，但短时间内可能仍从旧监听入口发出。
- SS2022 不支持 EIH/iPSK 链；初始盐与固定头不保证任意 TCP 首段分片可接受。AnyTLS UDP 使用 UoT v2，不是原生 UDP；Trojan 不含完整 fallback/反探测行为。
- VLESS / Snell 保留为实验实现且工作暂停，不作为正式完整支持承诺。
- 示例是回环测试配置，公开占位密码/密钥不可部署；TLS 示例需要自行准备证书和私钥。
- 已有普通/竞态、启动冒烟和定向功能验证，不等同全面安全审计、长期稳定性或生产就绪保证。短时性能口径仅为 2 核/4 GiB、总带宽 5G、64 并发、10 秒 × 3，不宣称独立峰值或长期 SLO。

## 附件与许可

校验：`sha256sum -c kat-0.5.20-linux-amd64.sha256`。

下载二进制时请同时保留 `kat-0.5.20-third-party-licenses.txt`。对应受许可源码及本地修改在本标签源码的 `third_party/reality/`、`patches/reality/`，其他原许可在 `third_party/licenses/`。REALITY 仍适用 MPL-2.0；juju/ratelimit 适用 LGPL-3.0 加静态/动态链接特别例外。Kat 自研代码保留所有权利，没有顶层自研 LICENSE；该声明不替代或限制第三方原许可。
