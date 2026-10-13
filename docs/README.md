# 计算接口文档

`crypto.swagger.json` 是生成的 OpenAPI 2.0 描述，用于查阅 CryptService 的 HTTP 映射与消息结构。如何调用、会话如何结束以及 gRPC 认证方式，先读 [仓库 README](../README.md)。

协议事实源是 [crypto.proto](../crypto.proto)。修改接口时同步生成 protobuf、gRPC、gateway 和 Swagger 文件，不单独手改 JSON。文档整理没有重新生成协议文件。
