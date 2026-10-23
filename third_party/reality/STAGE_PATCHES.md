# REALITY 本地修改说明

来源：XTLS/REALITY 提交 `9234c772ba8f181f31c3e81dc2b4177322e5a9a9`，模块版本 `v0.0.0-20260322125925-9234c772ba8f`。本地修改日期：2026-10-18；这不是上游发布。

仅修改 `common.go`、`record_detect.go` 和 `tls.go`：分别增加只读预检结果、将检测改为有界可取消操作、传播握手/回退取消并限制记录处理。`tls.go` 还使用既有 TLS 常量初始化控制记录预算，使没有可选兼容 CCS 的合法 TLS 1.3 会话能处理首个 KeyUpdate。

逐文件差异位于 [common.go](../../patches/reality/common.go.diff)、[record_detect.go](../../patches/reality/record_detect.go.diff)、[tls.go](../../patches/reality/tls.go.diff)。来源、修改内容和二进制分发的源码获取路径见 [MPL 说明](../../MPL-NOTICE.md)。

原始 MPL-2.0、Go 许可及版权声明保持不变。受许可文件及修改继续适用其原许可，不受 Kat 自研代码的权利声明替代。分发二进制时，必须提供对应受许可源码和修改，并保留所需许可及通知。

这些修改服务于本项目有界 RAW 服务端适配，不承诺对所有 REALITY 客户端或监听方式通用兼容；更新上游或工具链时需重新核对三个差异。
