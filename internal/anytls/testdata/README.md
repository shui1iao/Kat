# 独立规范固定夹具

`spec-fixtures.json` 是按公开规范独立生成并固定的测试输入；不调用本库编解码器，也不是上游作者发布的官方测试向量。测试读取已固定 JSON，不在运行时重建预期值。

来源：
- <https://github.com/anytls/anytls-go/blob/9666872946857b50a74fdb692896d77b53773cb2/docs/protocol.md>：认证、帧、设置、关闭与填充格式。
- <https://github.com/SagerNet/sing-box/blob/7054cac5124465ffdb145870d7c01885566711b1/docs/configuration/shared/udp-over-tcp.md>：UoT v2 的连接与非连接格式。

夹具使用公开测试密码 `fixture-password`、客户端标识 `spec-fixture/1`、回环目标及短载荷，覆盖 v1/v2 设置、逻辑流、心跳及 UoT 分包。`metadata-settings.json` 保存元数据边界输入。这里只按规范事实构造输入，没有复制上游实现；生成工具不随产品分发。修改预期值前应独立核对对应规范，而不是让预期值追随被测实现。
