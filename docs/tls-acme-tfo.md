# TLS 证书、ACME 自动证书与 TCP Fast Open（0.7.0）

本文说明 0.7.0 新增的入站 TLS 选项（Trojan / AnyTLS）、出站 uTLS 指纹、ACME 自动证书和 TCP Fast Open。所有新字段都是可选的：不写时保留原有 TLS/TCP 行为。

## 入站 TLS（Trojan / AnyTLS）

```json
"tls": {
  "cert": "/etc/kat/a.crt", "key": "/etc/kat/a.key",
  "certificates": [{"cert": "/etc/kat/b.crt", "key": "/etc/kat/b.key"}],
  "watch": true, "watch_interval": "60s",
  "alpn": ["h2", "http/1.1"],
  "min_version": "1.2", "max_version": "1.3",
  "cipher_suites": ["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"],
  "acme": { ... }
}
```

| 字段 | 默认 | 说明 |
|---|---|---|
| `cert` / `key` | — | 默认证书。必须成对出现；与 `acme` 至少写一个。 |
| `certificates` | 空 | 更多证书（最多 64 组），按 SNI 选择。 |
| `watch` | `false` | 跟随外部证书文件：定期检查文件内容（哈希），变化后热加载。只针对证书文件，不是监听配置文件。 |
| `watch_interval` | `60s` | 检查间隔，1 秒到 24 小时；需要 `watch`。 |
| `alpn` | 空 | 服务端 ALPN 列表（最多 8 项）。客户端提供了 ALPN 而与列表没有交集时握手失败。 |
| `min_version` / `max_version` | `1.2` / 不限 | 只接受 `"1.2"`、`"1.3"`。 |
| `cipher_suites` | Go 默认 | TLS 1.2 密码套件（Go 认为安全的套件名）；`min_version` 为 `1.3` 时不能写。TLS 1.3 套件不可配置。 |
| `acme` | — | 自动证书，见下文。 |

**证书选择**：先在所有证书中找覆盖 SNI 名称的（支持通配符证书）；同一名称有多张时（例如一张 ECDSA、一张 RSA），选客户端支持的那张。没有 SNI 或没有匹配的名称时，使用默认证书（`cert`，没有 `cert` 时为第一张可用证书，含 ACME 证书）。

**证书热加载**：

- `kat reload` / SIGHUP 时重新读取所有证书文件；
- `watch` 打开时，Kat 按 `watch_interval` 检查文件内容，变化后加载新证书。外部程序分两步写证书和私钥时，Kat 发现不配对会等 1 秒再读一次；
- 换证书只影响之后的新握手，已有连接不断开；
- 新证书无效（无法解析、证书与私钥不配对、已过期、无法读取）时：reload 整体拒绝并保持旧配置；跟随文件时保留旧证书并输出一次告警 `kat event=tls_certificate_reload_failed source=watch ... action=keep_previous`，文件修好后自动恢复。成功时输出 `kat event=tls_certificate_reloaded source=reload|watch`，附证书序列号、名称与到期时间。

不支持 mTLS、ECH、OCSP stapling。

## ACME 自动证书（Trojan / AnyTLS 入站）

```json
"tls": {
  "acme": {
    "domains": ["proxy.example.com"],
    "email": "ops@example.com",
    "challenge": "dns-01",
    "dns": {"provider": "cloudflare", "api_token_file": "/etc/kat/cf-token"}
  }
}
```

| 字段 | 默认 | 说明 |
|---|---|---|
| `domains` | — | 1 至 100 个域名；通配符（`*.example.com`）只能用 `dns-01`。 |
| `challenge` | — | `http-01`、`tls-alpn-01` 或 `dns-01`。 |
| `email` | 空 | 账户联系邮箱，可省略。 |
| `directory` | Let's Encrypt 正式环境 | ACME 目录 URL（https），例如 Let's Encrypt staging 或自建 CA。 |
| `directory_ca` | 系统根证书 | 访问目录 URL 时信任的根证书文件（私有 CA 用）。 |
| `eab` | 无 | 外部账户绑定：`{"key_id": "...", "mac_key": "<base64url>"}`。 |
| `key_type` | `ecdsa` | 证书私钥类型：`ecdsa`（P-256）或 `rsa`（2048）。 |
| `storage` | `<状态目录>/acme` | 账户密钥和证书的存放目录（root 运行时为 `/var/lib/kat/acme`）。 |
| `http_listen` | `:80` | `http-01` 独立监听地址；只在验证期间监听。多个证书使用同一地址时共用一个监听。 |
| `webroot` | 空 | `http-01` 改为把验证文件写入 `<webroot>/.well-known/acme-challenge/`，由现有 Web 服务器提供；与 `http_listen` 二选一。 |
| `dns.provider` | — | 目前只有 `cloudflare`。 |
| `dns.api_token` / `dns.api_token_file` | — | 二选一。请使用只限所需域名、只有 Zone:DNS:Edit 权限（不写 `zone_id` 时另需 Zone:Read）的 API Token；不支持 Global API Key。 |
| `dns.zone_id` | 自动查找 | 写了就不需要 Zone:Read。 |
| `dns.resolvers` | 域名的权威服务器 | 申请前确认 TXT 已生效时查询的 DNS 服务器（`host:port`）。 |
| `dns.propagation_timeout` | `2m` | 等待 TXT 生效的上限（1 秒到 1 小时）；超时只告警并继续提交验证。 |
| `dns.ttl` | `120` | TXT 记录 TTL（60–86400）。 |

验证方式说明：

- `http-01`：CA 访问 `http://<域名>:80/.well-known/acme-challenge/...`。独立监听需要 Kat 能绑定该端口（或由前端转发）；端口已被 Web 服务器占用时用 `webroot`。
- `tls-alpn-01`：CA 连接 `<域名>:443`，由这个入站本身应答（`acme-tls/1`），因此入站需要在 443 端口对外可达。
- `dns-01`：Kat 通过 Cloudflare API 创建 `_acme-challenge` TXT 记录，验证完成后按记录 ID 删除（只删自己创建的记录）。

**存储与重启**：账户密钥按 CA 目录和邮箱区分，证书按域名集合区分，文件权限 0600、目录 0700，写入用临时文件加原子改名。重启时如果已存证书仍有效且未到续期时间，直接使用，不会重新申请。

**续期**：证书剩余有效期不足 1/3 时续期（90 天证书约在到期前 30 天）。失败时告警 `kat event=acme_renew_failed ... attempt=N retry_in=...`（旧证书继续使用，已过期时注明 `current_expired=true`），按退避重试：间隔从有效期的 1/20（1 分钟封顶，至少 5 秒）开始翻倍，最长为有效期的 1/6 与 6 小时中较小者。续期成功后热替换，已有连接不断开。

**首次申请期间**：证书拿到之前，只配置了 `acme` 的入站用内存里的临时自签证书应答（客户端校验会失败），拿到后自动换上。

**热重载**：ACME 配置不变（含 Token）时，reload 沿用同一个证书管理器与证书，不会重新申请；配置变化时按新配置申请。

## 出站 uTLS 指纹（Trojan / AnyTLS 出站）

```json
"tls": {"server_name": "example.com", "fingerprint": "chrome"}
```

`fingerprint` 可选值：`chrome`、`firefox`、`safari`、`ios`、`edge`、`android`、`360`、`qq`、`random`（进程启动后从 chrome/firefox/safari/ios/edge 中随机固定一个）。不写时使用 Go 自带的 TLS 实现，保留原有行为。证书校验方式（默认校验、`ca`、`pin_sha256`、`insecure`）不变；写了 `alpn` 时替换浏览器模板里的 ALPN 列表。

## TCP Fast Open

```json
{
  "direct": {"tcp_fast_open": true},
  "inbounds": [{"protocol": "trojan", "listen": "0.0.0.0:443", "tcp_fast_open": true, ...}]
}
```

- 入站 `tcp_fast_open`（默认 `false`）：监听 socket 接受 SYN 中携带的数据。reload 时可开关，复用的监听 socket 也会随之更新。
- 根 `direct.tcp_fast_open`（默认 `false`）：内置 direct 出站（包括连到上游代理服务器的第一跳）发起连接时启用 TFO，第一段数据在已有 cookie 时随 SYN 发出。
- Kat 不修改系统参数。启动和 reload 时读取 `net.ipv4.tcp_fastopen`：入站需要第 2 位（值含 2），direct 需要第 1 位（值含 1），不满足时告警，例如 `kat event=tfo_sysctl_insufficient side=server sysctl=net.ipv4.tcp_fastopen value=1 required_bit=0x2 effect=inbound_tfo_inactive hint=set_net.ipv4.tcp_fastopen_to_3`。此时连接照常建立，只是不使用 TFO。非 Linux 平台上该选项被忽略并告警。
