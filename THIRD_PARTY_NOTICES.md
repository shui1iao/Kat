# 第三方组件与二进制分发说明

Kat 自研代码保留所有权利；下述第三方组件及其修改继续适用各自原许可。此说明不替代原始法律文本，也不限制第三方许可授予的权利。

## REALITY

`third_party/reality/` 是构建实际使用的 XTLS/REALITY 提交 `9234c772ba8f181f31c3e81dc2b4177322e5a9a9` 源码及本地修改。原始 MPL-2.0 及 Go 许可均在该目录保留，修改及完整源码获取路径见 [MPL 说明](MPL-NOTICE.md)。不要只分发差异而不提供对应受许可源码。

## juju/ratelimit

二进制包含 `github.com/juju/ratelimit v1.0.2`，版权声明为 Canonical Ltd.，许可为 LGPL-3.0，附原作者提供的静态/动态链接特别例外。库源码未作本地修改。

- [库的原始许可和特别例外](third_party/licenses/github.com_juju_ratelimit@v1.0.2-LICENSE)
- [LGPL 引用的 GPL-3.0 原文](third_party/licenses/GPL-3.0.txt)
- 对应上游源码：<https://github.com/juju/ratelimit/tree/v1.0.2>

特别例外允许分发静态或动态链接的组合作品，无需提供 LGPL 第 4d 项定义的最小对应源码、最小应用代码及第 4e 项安装信息，但保留其他适用义务。本版本保留库的显著使用说明、版权、LGPL/例外及 GPL 原文，并随二进制提供许可附件。Kat 的权利声明不禁止第三方许可所允许的库修改，也不限制为调试这些库修改而依法或依适用许可进行的逆向工程。

## maxminddb-golang

二进制包含 `github.com/oschwald/maxminddb-golang v1.13.1`，由 `internal/route` 用于读取用户自行提供的 MaxMind DB（`.mmdb`）国家库。版权声明为 Gregory J. Oschwald，许可为 ISC。库源码未作本地修改。

- [库的原始许可](third_party/licenses/github.com_oschwald_maxminddb-golang@v1.13.1-LICENSE)
- 对应上游源码：<https://github.com/oschwald/maxminddb-golang/tree/v1.13.1>

Kat 不内置、不随源码或二进制分发任何 GeoIP 数据；使用者自备的数据库适用其各自的许可。

## 其他组件

`third_party/licenses/` 保留 Go、golang.org/x/crypto、golang.org/x/net、golang.org/x/sys、golang.org/x/text、BLAKE3、cpuid、Brotli、CIRCL、WebSocket、compress、go-proxyproto、uTLS、maxminddb-golang 等组件的原始许可或专利文本。目录中可能保留同一组件的不同版本许可副本，实际编译版本以 `go.mod`、`go.sum` 和二进制构建信息为准，不将旧版本许可副本误称为新增运行依赖。

产品源码及静态附件不包含独立测试客户端的源码或二进制，产品构建不依赖这些客户端。测试中可选使用的外部服务端程序（如 sing-box）只在设置相应环境变量时由测试调用，既不随源码或二进制分发，也不是产品的链接依赖。请勿将未分发的测试工具许可误当作本产品的链接依赖许可。

## 随二进制提供

`kat-0.6.0-third-party-licenses.txt` 附件汇总本说明、MPL 修改说明、第三方许可原文及其目录路径。对应受许可源码与差异可从 `https://github.com/shui1iao/Kat/tree/v0.6.0` 获取；分发者应保持此获取路径及对应版本源码可用，同时履行各原许可的其他适用义务。原始法律文本不翻译或改写。
