# icrypto

计算接口、protobuf/gRPC契约及Go客户端。这里不实现模拟器、硬件后端或独立服务器。

| 文件 | 职责 |
| --- | --- |
| [crypto.proto](crypto.proto) | RPC、消息字段与HTTP映射的事实源 |
| [cryptor.go](cryptor.go) | 与传输无关的计算接口 |
| [cryptor.impl.go](cryptor.impl.go) | 会话标识、超时与gRPC客户端 |
| [options.go](options.go) | 初始化选项及参数约束 |
| [docs/](docs/README.md) | 完整使用说明和生成的OpenAPI描述 |

## 使用与生命周期

Go版本以[go.mod](go.mod)为准。通过`InitGRPC`、`InitGRPCWithAPIKey`或`InitGRPCWithCreds`建立客户端工厂，每次`NewCryptor()`创建独立`client_id`。

1. `Initialize`建立计算会话，并合并服务端返回的设备状态。
2. 后续取得新设备状态时，通过可选`DeviceSynchronizer.SyncDevice`同步，不重建环境。
3. 在同一实例中完成需要保持上下文的握手；业务方应串行化完整事务。
4. 无论成功或失败，都调用`Finalize`清理。

单次`ActivationSign`不要求`Initialize`，使用临时环境；`ActivationSignInSession`使用已有环境。设备身份、初始化环境及签名profile是三种不同参数，不能互相替代。

详细示例、认证、服务端注册、错误及选项语义见[使用参考](docs/usage.md)。客户端不负责向业务服务器发送激活或注册请求。

## 接口分组

| 分组 | 接口 |
| --- | --- |
| 生命周期 | `Initialize`、`SyncDevice`、`Finalize` |
| 传统签名 | `ActivationSign`、`ActivationSignInSession` |
| DRM | `DRMActivation*` |
| ADI | `ADIStartProvisioning`、`ADIEndProvisioning`、`ADIGenerateLoginCode` |
| Absinthe / PSC | `AbsintheHello`、`AbsintheAddOption`、`AbsintheActivateSession`、`AbsintheSignData` |
| NAC | `NACInit`、`NACGenerateValidation` |
| SAP | `SAPExchange`、`SAPSignPrime`、`SAPVerifyPrime`、`SAPSign`、`SAPVerify` |

NAC计算路由为`/nac/init`及`/nac/generate-validation`；旧Identity计算方法已经移除。客户端、代理及服务端必须使用相容契约，不能仅凭protobuf字段编号保留就假定旧方法名仍可用。

## 修改与验证

修改协议后运行`./scripts/generate-proto.sh`，同步更新protobuf、gRPC、gateway及Swagger；不要手改生成文件。工具版本保留在生成文件头。

```sh
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
```

同一workspace的业务编排在`idevice`，执行后端在`iunios`；本模块保持独立契约与客户端职责。[完整参考](docs/usage.md)中的研究背景不等于本客户端执行硬件运算，部署记录也不表示当前服务状态。
