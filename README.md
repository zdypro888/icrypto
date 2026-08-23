# icrypto

Apple 设备激活与身份验证的 RPC API 契约与 Go 客户端库，提供 gRPC/REST API 定义和与传输无关的密码服务接口。

## 项目定位

本仓库负责协议与客户端抽象，不包含可独立启动的密码服务或硬件模拟实现：

- [`crypto.proto`](./crypto.proto)：`CryptService` 的 protobuf/gRPC 定义及 REST 路由注解。
- [`cryptor.go`](./cryptor.go)：与传输无关的 `Cryptor` 接口，以及可选的 `DeviceSynchronizer` 能力。
- [`cryptor.impl.go`](./cryptor.impl.go)：带会话标识、超时和消息大小限制的 gRPC 客户端。
- [`docs/crypto.swagger.json`](./docs/crypto.swagger.json)：由协议定义生成的 OpenAPI 文档。
- `crypto*.pb.go`：protobuf、gRPC 和 grpc-gateway 生成代码。

服务端需要实现生成的 `CryptServiceServer` 接口。REST 路由由 grpc-gateway 生成，但 HTTP server 的监听、认证和部署由宿主程序负责。

## API 概览

| 分类 | RPC / Go 方法 | 用途 |
| --- | --- | --- |
| 会话生命周期 | `Initialize`、`SyncDevice`、`Finalize` | 初始化密码会话、合并后续设备状态、释放会话 |
| DRM 激活 | `ActivationDRMHandshake`、`ActivationDRMProcess`、`ActivationDRMSignature`、`ActivationDeprecated`、`ActivationRecord` | DRM 握手、签名与激活记录处理 |
| ADI | `ADIStartProvisioning`、`ADIEndProvisioning`、`ADIGenerateLoginCode` | Anisette/ADI provisioning 与登录码生成 |
| Absinthe | `AbsintheHello`、`AbsintheAddOption`、`AbsintheActivateSession`、`AbsintheSignData` | Absinthe 会话建立、配置与签名 |
| Identity | `IdentitySession`、`IdentityValidation` | IDS/iMessage 身份会话和验证数据生成 |
| SAP | `SAPExchange`、`SAPSignPrime`、`SAPVerifyPrime`、`SAPSign`、`SAPVerify` | SAP 协议交换、签名与验证 |

每次通过 `NewCryptorGRPC`（或初始化后的 `NewCryptor` 工厂）创建客户端时，都会生成独立的 `client_id`；服务端应使用它关联同一调用方的会话状态。

## 安装

本模块要求 Go 1.26.4 或更高版本：

```bash
go get github.com/zdypro888/icrypto
```

下方快速开始额外使用了项目的 `idevice.Device` 实现：

```bash
go get github.com/zdypro888/idevice
```

## gRPC 客户端快速开始

下面示例使用 `idevice.Device` 作为 `IPlistObject`。自定义设备类型需要实现 `Marshal() ([]byte, error)` 和 `Unmarshal([]byte) error`，同时其字段必须能被 `go-plist` 编码成 binary plist。

```go
package main

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/zdypro888/icrypto"
	"github.com/zdypro888/idevice"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() (err error) {
	// 2116 是关联项目 iunios/cmd/icryptor 当前使用的端口；部署其他
	// 服务端时替换成实际地址。InitGRPC 仅适合回环地址或可信子进程。
	if err := icrypto.InitGRPC("127.0.0.1:2116"); err != nil {
		return fmt.Errorf("initialize gRPC client: %w", err)
	}

	cryptor := icrypto.NewCryptor()
	device := &idevice.Device{
		// 填入当前工作流需要的设备字段。
	}
	ctx := context.Background()

	if err := cryptor.Initialize(ctx, icrypto.InitializeType_AUTO, device); err != nil {
		return fmt.Errorf("initialize cryptor: %w", err)
	}
	defer func() {
		if finalizeErr := cryptor.Finalize(context.Background()); finalizeErr != nil {
			err = errors.Join(err, fmt.Errorf("finalize cryptor: %w", finalizeErr))
		}
	}()

	// Initialize 可能补全硬件标识；随后才可请求依赖这些标识的票据。
	if device.APTicket == nil {
		if err := device.RequestAPTicket(ctx); err != nil {
			return fmt.Errorf("request AP ticket: %w", err)
		}
	}
	if device.APTicket == nil {
		return errors.New("AP ticket request returned no ticket")
	}
	synchronizer, ok := cryptor.(icrypto.DeviceSynchronizer)
	if !ok {
		return errors.New("cryptor does not support device state synchronization")
	}
	// 将新增状态合并到远端，但不重建 VM、SEP 或 guest session。
	if err := synchronizer.SyncDevice(ctx, device); err != nil {
		return fmt.Errorf("sync device state: %w", err)
	}

	collectionBlob, handshakeRequest, err := cryptor.ActivationDRMHandshake(ctx)
	if err != nil {
		return fmt.Errorf("create DRM handshake: %w", err)
	}
	fmt.Printf("collection blob: %d bytes, handshake request: %d bytes\n", len(collectionBlob), len(handshakeRequest))
	return nil
}
```

### 推荐生命周期

1. 调用一次 `InitGRPC`、`InitGRPCWithAPIKey` 或 `InitGRPCWithCreds`，初始化进程级客户端工厂。
2. 通过 `NewCryptor()` 创建一个有独立 `client_id` 的业务会话。
3. 调用 `Initialize`，并使用响应更新传入的设备对象。
4. 如果随后取得了依赖硬件标识的 AP ticket 或其他设备状态，调用 `DeviceSynchronizer.SyncDevice`。
5. 执行 DRM、ADI、Absinthe、Identity 或 SAP 操作。
6. 无论成功或失败，都调用 `Finalize` 释放远端会话。

`SyncDevice` 被设计成独立的可选接口，以保持现有 `Cryptor` 实现的源码兼容性。需要该能力的调用方必须做类型断言；旧版服务端没有该 RPC 时会返回 `Unimplemented`，不能静默跳过依赖同步状态的流程。

设备数据在 `Initialize` 和 `SyncDevice` 中均以完整 binary plist 传输。`SyncDevice` 的具体字段合并策略由服务端实现决定。

## 服务端集成

本仓库只提供生成的服务接口。实现方应按值嵌入 `UnimplementedCryptServiceServer`，实现所需 RPC，再注册到宿主 gRPC server：

```go
type cryptService struct {
	icrypto.UnimplementedCryptServiceServer
}

service := &cryptService{}
grpcServer := grpc.NewServer(
	grpc.MaxRecvMsgSize(64*1024*1024),
	grpc.MaxSendMsgSize(64*1024*1024),
)
icrypto.RegisterCryptServiceServer(grpcServer, service)
```

上面只展示注册关系，未实现任何密码操作。若要暴露 REST API，宿主还必须配置 grpc-gateway、监听地址、认证和 TLS。

## 传输与认证

| 初始化函数 | 传输 | 认证元数据 | 适用场景 |
| --- | --- | --- | --- |
| `InitGRPC(address)` | 明文 gRPC | `client_id` | 回环地址或可信子进程 |
| `InitGRPCWithAPIKey(address, apiKey)` | 明文 gRPC | `client_id`、`x-api-key` | 由其他安全信道保护的代理连接 |
| `InitGRPCWithCreds(address, apiKey, creds)` | 自定义 gRPC credentials；`creds == nil` 时退回明文 | `client_id`，可选 `x-api-key` | TLS 或其他受认证传输 |

客户端为每次 RPC 派生最长 60 秒的上下文，并把单条消息的发送和接收上限设置为 64 MiB。不要把明文初始化函数用于不可信网络；API key 只提供应用层身份信息，不能替代传输加密。

## 协议与生成代码

修改协议时，以 [`crypto.proto`](./crypto.proto) 为事实源，并在同一个变更中重新生成以下文件：

- `crypto.pb.go`
- `crypto_grpc.pb.go`
- `crypto.pb.gw.go`
- `docs/crypto.swagger.json`

不要直接编辑生成文件。客户端与服务端升级时需要保持协议版本一致，尤其是会话生命周期 RPC（当前包括 `SyncDevice`）。

当前仓库尚未提供一键生成脚本。本版本使用 libprotoc 35.0（生成文件头记录为 `protoc` v7.35.0）、`protoc-gen-go` 1.36.11、`protoc-gen-go-grpc` 1.6.2，以及 grpc-gateway/OpenAPI 插件 2.27.8 生成；重新生成时还需要 Google API proto include 路径。

## 开发与验证

```bash
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
go mod verify
go mod tidy -diff
```

## 技术背景

以下内容描述本项目所面向的真机安全模型，不代表 `icrypto` 客户端本身执行硬件运算；实际能力与安全边界取决于服务端后端。对应逆向证据保存在同一工作区 `iunios/sep/docs/` 下的 `attestation.md`、`kernel_aes_15_8_8.md` 和 `fairplay_iokit.md`。

### 系统架构概述

iOS 设备的激活与身份验证涉及多层硬件和软件协作：

- **应用处理器（AP）**：运行 iOS 用户态进程（mobileactivationd、identityservicesd、fairplayd 等）
- **内核驱动**：IOAESAccelerator（硬件 AES 引擎）、AppleKeyStore（密钥管理）、ProvInfoIOKit（设备信息采集）
- **安全隔区（SEP）**：独立处理器，运行 SEPOS，管理 UID/GID 硬件密钥、SKS（Secure Key Store）密钥体系
- **硬件密钥引擎**：AES 加速器内置 GID（同型号共享）、UID（设备唯一）、Device Key（设备密钥）等不可导出的硬件密钥

数据流方向：AP 用户态 → 内核 IOKit → AES 硬件 / SEP，密钥运算全部在硬件内完成，AP 侧只能请求运算、不能读取密钥本体。

---

### DRM 激活流程（iOS 10+）

#### 流程概览

```
设备                                Apple 服务器
  |                                      |
  |-- 1. 采集设备信息 + InFieldCollection -->|
  |-- 2. drmHandshake (SCRT + PCRT) ------>|
  |<-- 3. SUInfo + HandshakeResponse -------|
  |-- 4. PSC 处理 SUInfo ----------------->|
  |-- 5. 生成 ActivationXML + 签名 ------->|
  |-- 6. deviceActivation ----------------->|
  |<-- 7. ActivationRecord ----------------|
```

#### 关键阶段

**阶段 1：设备信息采集**
- SerialNumber、UDID、ECID、IMEI 等基础标识
- InFieldCollection manifest：由 ProvInfoIOKit 通过 IOAESAccelerator 的 special key 和 descrambler 硬件加密生成，包含设备的硬件指纹

**阶段 2：DRM Handshake**
- SCRT（Secure Certificate）：由 SEP 的 SIK/DeviceKey 生成，经 ECIES 加密
- PCRT：InFieldCollection 采集的设备证明数据
- SigningKey 签名 IngestBody，确保请求完整性

**阶段 3-4：PSC 会话（Provisioning Session Control）**
- Apple 返回 SUInfo + HandshakeResponseMessage + ServerKP
- mobileactivationd 内部的 PSC 函数处理密钥协商
- SUInfo 通过 ProvInfoIOKit 使用 AES special key 加密后存储为 psc.sui

**阶段 5-6：激活签名与提交**
- FairPlay 签名：fairplayd 对 ActivationXML 做 FairPlay 签名
- RK 签名：SEP 的 RefKey 签名 ActivationXML
- PSC SignAct：PSC 会话签名 + ServerKP
- 三组签名 + 证书链一起提交给 `albert.apple.com/deviceservices/deviceActivation`

**阶段 7：ActivationRecord**
- Apple 验证通过后返回：DeviceCertificate、FairPlayKeyData、AccountToken、UniqueDeviceCertificate 等
- 设备写入激活记录，完成激活

#### IOAESAccelerator Special Key 机制

内核 AES 硬件引擎在启动时执行 `_initKeyCache`：

1. 从 nonce table 读取 source plaintext（每个 entry：4B handle + 4B keyType + 16B plaintext）
2. 用 GID/UID key 加密 GID 类 plaintext → cached key
3. 禁用 GID/UID 的直接硬件访问（`disableHardwareKey`）
4. 用 Device Key 加密剩余 plaintext → cached key
5. 后续 AES 操作通过 handle（如 0x899、0x89D）查 cached table 获取密钥

Special key 的 cached ciphertext 是设备相关的（UID/Device Key 每台不同），FairPlay 和 ProvInfoIOKit 的加密结果依赖这些 cached key 的正确性。

#### Descrambler（0xBB8）

IOAESAccelerator 的 descrambler（keyId=3000）是硬件级的解扰操作：
- 输入：key data（来自 special key 加密结果） + addon data（32 字节 info）
- 内部使用与 UID 相关的固定硬件密钥
- 输出：解扰后的 seed 数据

Descrambler 的输入 key data 依赖 special key（如 0x89D）的加密结果，因此 special key 的正确性直接影响 descrambler 输出。

---

### SEP 密钥体系（SKS）

#### 密钥类型

**命名说明（2026-04-15 实测验证）**：SEP 固件内部缓存/函数名与 mobileactivationd、Apple 用户层的术语存在**互调**，容易混淆。项目 Go 代码中的 `SKSClient` 字段采用**用户层**命名，与 `SecKeyCopySystemKey` 一致；下表分别列出两套名称。

| Go 字段 (用户层) | SEP 函数 / cache | SecKeyCopySystemKey | 用途 |
|------------------|------------------|---------------------|------|
| `SIK`            | `sks_create_key_simple(1,1)` = `sks_create_device_key()` (cache: g_uik_key_cache) | (0) "com.apple.setoken.sik" | 出厂持久, attest UIK / 签 BAA SIKPub |
| `UIK`            | `sks_create_key_simple(2,2)` (cache: g_device_key_cache) | (2)/(3) "com.apple.setoken.uikc/uikp" | 出厂持久, attest RefKey / BIK |
| `GIDDerivedKey`  | `sks_create_gid_key(2)`, SEP key_type=6 "sep gid key" | (无对应) | SCRT1 链根 |
| `SessionKey/SigningKey/RefKey` | `sks_create_key_simple` (7/8/9) 或 `CreateSigningKey` | — | 签名用途 |

#### Attestation 链

```
GIDDerivedKey → SIK → UIK → RefKey
```

- SCRT1 (CollectSIK):           GIDDerivedKey → SIK
- UIKCertification:             **SIK → UIK**         (SIK 签 UIK)
- RKCertification (DRM):        **UIK → RefKey**       (UIK 签 RefKey)
- RKCertification (BAA):        **UIK → BIK**          (同构, 只是 target 是一次性 BIK)
- SCRT2 (CollectSigningAttestation): SIK → SigningKey
- 每级 attestation 包含 GIDPubkeyHash = SHA256(签名方公钥)，形成信任链

---

### iMessage（IDS）注册与 Absinthe 验证

#### 注册流程

```
设备                                    Apple IDS 服务
  |                                          |
  |-- 1. 获取 validation cert ------------->|
  |-- 2. IdentitySession + AbsintheHello -->|
  |<-- 3. SessionInfo + AbsintheResponse ---|
  |-- 4. AbsintheActivateSession ---------->|
  |-- 5. IdentityValidation + AbsintheSign ->|
  |<-- 6. 注册成功 -------------------------|
```

#### Absinthe 机制

Absinthe 是苹果的设备验证框架（absd daemon），用于 iMessage/FaceTime 等服务的注册验证：

- **AbsintheHello**：生成 hello 消息，创建 validation session
- **AbsintheActivateSession**：用 Apple 返回的 response + server key 激活 session
- **AbsintheSignData**：用激活后的 session 签名数据

Absinthe 内部通过 IOAESAccelerator 的 descrambler（keyId=0xBB8）进行硬件级加密操作，与 DRM 激活共享相同的 AES 基础设施。

#### SUInfo（psc.sui）的作用

psc.sui 是 PSC 会话过程中产生的加密数据，由 ProvInfoIOKit 使用 special key（0x89D）加密 SUInfo 生成。它在后续的 iMessage 注册等流程中作为设备信任凭证使用。

---

### 硬件安全边界

#### 不可导出的密钥

- **UID Key**：设备唯一，烧录在 SoC 中，只能在 AES 硬件引擎内使用
- **GID Key**：同型号/SoC 家族共享，同样不可导出
- **Device Key（0x7D0）**：设备唯一的 AES 密钥，用于 special key 派生
- **SEP 密钥**：SIK、DeviceKey 等 SEP 密钥只在安全隔区内存在

#### ECID 绑定

ECID（Exclusive Chip ID）是 SoC 唯一编号，用于个性化签名（personalization）。AP Ticket、激活记录等都绑定到 ECID，使授权只对单台设备有效。

#### Special Key 与 Descrambler 的桥梁作用

Special key 的 cached ciphertext 是连接软件 AES 操作和硬件 descrambler 的桥梁：
- 软件侧：用 cached key 做 AES 加密，产生 key data
- 硬件侧：descrambler 用内部密钥对 key data 做解扰
- 两者必须配套，cached key 必须是由真实硬件密钥派生的正确值

---

## 合规声明

本项目仅用于安全研究与学术目的。涉及的技术分析基于公开资料、Apple Platform Security 文档及安全研究社区的成果。请勿用于任何未经授权的用途。

---

## 参考资料

- [Apple Platform Security - Secure Enclave](https://support.apple.com/guide/security/secure-enclave-sec59b0b31ff/web)
- [Apple Platform Security - Keybags for Data Protection](https://support.apple.com/guide/security/keybags-for-data-protection-sec6483d5760/web)
- [Apple Platform Security - Secure Software Updates](https://support.apple.com/guide/security/secure-software-updates-secf683e0b36/web)
- [Apple Platform Security - iMessage Security Overview](https://support.apple.com/guide/security/imessage-security-overview-secd9764312f/web)
- [iMessage PQ3 Protocol](https://security.apple.com/blog/imessage-pq3/)
- [iMessage Contact Key Verification](https://security.apple.com/blog/imessage-contact-key-verification/)
- [The Apple Wiki - APTicket](https://theapplewiki.com/wiki/APTicket)
- [The Apple Wiki - ECID](https://theapplewiki.com/wiki/ECID)
