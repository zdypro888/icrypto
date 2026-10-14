# 计算接口文档

`crypto.swagger.json` 是生成的 OpenAPI 2.0 描述，用于查阅 CryptService 的 HTTP 映射与消息结构。如何调用、会话如何结束以及 gRPC 认证方式，先读 [仓库 README](../README.md)。

协议事实源是 [crypto.proto](../crypto.proto)。修改接口时同步生成 protobuf、gRPC、gateway 和 Swagger 文件，不单独手改 JSON。文档整理没有重新生成协议文件。

运行 `../scripts/generate-proto.sh` 重新生成全部协议产物。当前NAC端点为 `/nac/init` 与 `/nac/generate-validation`；老的 `/identity/*` 计算路由已移除。业务协议中的Apple字段名仍按原始字节保留。
