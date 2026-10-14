#!/bin/sh
# 从同一份契约生成全部客户端、服务端和 HTTP/OpenAPI 产物，禁止逐文件手改。
set -eu
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_dir"
for tool in protoc protoc-gen-go protoc-gen-go-grpc protoc-gen-grpc-gateway protoc-gen-openapiv2; do
    command -v "$tool" >/dev/null || { echo "Missing protobuf tool: $tool" >&2; exit 1; }
done
# 包内固定 Google HTTP 注解源码；工具版本由生成文件头和 README 记录。
protoc -I . -I tools \
    --go_out=. --go_opt=paths=source_relative \
    --go-grpc_out=. --go-grpc_opt=paths=source_relative \
    --grpc-gateway_out=. --grpc-gateway_opt=paths=source_relative \
    --openapiv2_out=docs crypto.proto
