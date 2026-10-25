# REALITY 源码与修改说明

`third_party/reality/` 保留 XTLS/REALITY 的源码快照，来源提交为
`9234c772ba8f181f31c3e81dc2b4177322e5a9a9`，模块版本为
`v0.0.0-20260322125925-9234c772ba8f`。

上游来源：<https://github.com/XTLS/REALITY/tree/9234c772ba8f181f31c3e81dc2b4177322e5a9a9>。

本地修改日期为 2026-10-18，仅涉及以下三个受许可源码文件：

| 文件 | 修改内容 | 对应差异 |
| --- | --- | --- |
| `common.go` | 保存初始化后只读的有界预检结果，并在配置克隆时保留 | [差异](patches/reality/common.go.diff) |
| `record_detect.go` | 使用有界、可取消的公开接口预检替代无界异步检测 | [差异](patches/reality/record_detect.go.diff) |
| `tls.go` | 为握手及未认证回退建立超时和取消传播，限制检测结果，并独立初始化 TLS 控制记录预算，以处理未发送可选兼容 CCS 时的首个 KeyUpdate | [差异](patches/reality/tls.go.diff) |

该目录保留原始 `LICENSE`（MPL-2.0）、`LICENSE-Go`、版权头和相关第三方说明。三个文件及其修改仍受原许可约束；Kat 自研代码的“保留所有权利”声明不改变这些权利。

根目录 `go.mod` 使用 `replace github.com/xtls/reality => ./third_party/reality`；此修改后的源码确实进入二进制，不能仅为整理目录而删除。本地修改不是上游发布，也不代表所有上游使用方式均兼容。更新上游或工具链时需要重新核对差异。

分发二进制时，应向接收者提供可获取的对应受许可源码及本地修改，并保留许可、版权和修改说明。本版本对应源码位于公开仓库 `https://github.com/shui1iao/Kat` 的 `v0.6.3` 标签中，受许可部分为 `third_party/reality/`，差异为 `patches/reality/`；源码归档由相同标签生成。应将二进制与该版本源码和第三方许可附件一起提供，不能用此说明代替实际提供源码或其他适用义务。
