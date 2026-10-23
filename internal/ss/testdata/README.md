# 固定规范导出向量

`spec-vectors.json` 的 SHA-256 为：
`38e744be494eb1381705327c13c61efa5cb8b914d7ae8032d823bd171a8bb491`。

这些是按规范独立生成并固定的测试向量，不声称是上游作者发布的官方向量。生成时不导入本库或对端编解码器；独立字节布局使用标准 AES-GCM、x/crypto 的 ChaCha 和另一 BLAKE3 实现交叉核对。生成工具不随产品分发，单测只读取固定 JSON。

规范来源为 shadowsocks-org 提交 `34598d65054dad975d330ff9d7317b0d41cf1efd`：
- <https://github.com/shadowsocks/shadowsocks-org/blob/34598d65054dad975d330ff9d7317b0d41cf1efd/docs/doc/aead.md>
- 同提交的 `docs/doc/sip022.md` 和 `docs/doc/what-is-shadowsocks.md`。

每种方法包含固定密钥、盐、请求/响应明文及密文、TCP 子密钥和 UDP 时间/会话字段。密钥为从 00 起递增的公开测试字节，目标为 127.0.0.1:443，时间为 Unix 1700000000；这些值不是生产凭据。向量提供可重复的独立预期输入，不等同形式化证明或密码审计。修订向量应先独立核对规范及生成过程，不能在单测中用被测实现重建预期值。
