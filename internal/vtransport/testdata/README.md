# 固定传输夹具来源

固定数据依据公开协议事实构造，不用生产编码器生成预期结果：

- `TestProtoFixedFixtureAndLimits`：固定 protobuf 字节验证末值和重复字段拼接。
- `TestGRPCMalformedFrameStatusAndBoundedProto`：固定 gRPC 帧验证重复字段、压缩标志、越界及截断。
- `TestRFC6455FragmentsPingAndTextRejected`：固定掩码、二进制分片、心跳及续帧，验证顺序与拒绝文本帧。
- `TestUpgradePreReadBytesAndServerFirst`：HTTP 升级后紧随大量字节，检查预读数据不丢失。
- `TestWebSocketEarlyDataAndLargeStream`：固定早期数据前缀与后续二进制流，检查前缀只出现一次。

依据 RFC 6455、gRPC over HTTP/2 帧格式、protobuf 长度限定字段格式及 Xray 的 `transport/internet/grpc/encoding/stream.proto` 消息字段事实构造。测试中的独立 VLESS 请求解析只用于验证，不作为生产协议支持范围的扩展，也不代表全部客户端兼容性。
