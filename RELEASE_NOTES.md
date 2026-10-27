# Kat 0.7.1：热重载修复与 AnyTLS 自定义 padding

这是基于 v0.7.0 的修复版本，只发布源码、标签和 Linux amd64 附件，**不自动更新已运行的服务**。既有默认值、正式协议范围与实验性 VLESS/Snell 边界不变，不增加 Kat-Manager 功能或 Windows 正式附件。

## 主要变化

- **AnyTLS 旧会话授权撤销**：成功重载修改密码、删除入站、换监听或切换协议后，旧 TLS carrier 不能再开新的 TCP/UDP 逻辑流，已准入的流继续完成；恢复原密码或监听不会复活已撤销会话。无关规则、名称、预算或 padding 变更不误撤销。
- **运行期热重载原子性**：API 监听/鉴权及统计、select 状态目标纳入同次提交。候选监听、实例锁或状态文件准备/安装失败，原转发配置、API 鉴权、累计值与运行选择保持，失败不消耗 generation，也不误撤销 AnyTLS 会话。成功提交后才切换。启动时资源失败仅告警的既有行为不变；这是进程内事务，不是断电恢复保证，提交后新的磁盘故障仍可能导致周期保存告警。
- **AnyTLS 入站自定义 padding**：新增内联 `anytls.padding_scheme` 字符串，省略或空串沿用默认，最大 4096 字节，同密码多入站须保持有效方案及预算一致。`check`、启动与重载均拒绝非法方案；客户端方案指纹不匹配时原样下发方案文本，不改写协议或承诺反封锁效果。

```json
"anytls": {
  "password": "replace-with-your-password",
  "padding_scheme": "stop=2\n0=30-30\n1=100-200"
}
```

padding 重载仅影响新绑定接入的 TLS carrier；旧 carrier（包括随后新开的流）保留旧 codec/方案，不广播、不强断。单改 padding 不撤销身份，旧 carrier 的新流仍使用当前路由代；客户端复用旧池时，不保证立即全部采用新方案。没有文件入口或自动监控。

## 验证与保留边界

- 三项变更的全包普通单元测试、`go vet` 与重点 race 通过；2026-10-27 在相同功能源码仅设版本为 0.7.1 后，全包 `go test -race -p 2 -parallel 2 -count=1 -timeout=900s ./...`、全包 `go vet` 均通过，无 DATA RACE。
- Linux/Windows amd64 测试构建通过，Windows 仅交叉构建、未实机测试。正式 Linux 附件另从已提交且干净的公开树构建，检查精确版本、静态 ELF/amd64 与 CLI（含 padding）定向测试。
- 0.7.0 的客户端矩阵与 2 小时负载是旧基线证据，**本版未重做 2 小时、未补 6 小时**，也未重跑完整外部客户端矩阵、真实 ACME 签发续期、TFO 抓包、超过 4096 并发压力或全部规则/组/订阅组合。不据此宣称全面兼容、性能领先或普遍无泄漏。

升级前请先备份配置并运行 `kat check`；自定义 padding 不需要时可不配置。0.7.0 引入的客户端直连回环限制等安全默认值继续保留，公开示例中的密码/密钥只是测试值，不能用于真实服务。详见 [README](README.md)。

## 附件与许可

仅提供以下三份正式附件，保持既有下载校验格式：

- `kat-0.7.1-linux-amd64`
- `kat-0.7.1-linux-amd64.sha256`（`<64hex>  kat-0.7.1-linux-amd64`，末尾换行）
- `kat-0.7.1-third-party-licenses.txt`

Go 1.26.9，CGO 关闭，`-trimpath -buildvcs=false`；对应源码标签 `v0.7.1`。依赖版本未变，本地 REALITY replace、MPL 源码/修改说明/补丁、LGPL 链接例外与其余原始法律文本保留。Kat 自研代码仍保留所有权利，第三方许可赋予的权利不受影响。见 [第三方说明](THIRD_PARTY_NOTICES.md) 与 [MPL 说明](MPL-NOTICE.md)。
