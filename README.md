# icrypto

Apple iOS 设备激活与身份验证加密框架（gRPC / RESTful API）

API 文档：见 `docs/crypto.swagger.json`

---

# 一、系统架构概述

iOS 设备的激活与身份验证涉及多层硬件和软件协作：

- **应用处理器（AP）**：运行 iOS 用户态进程（mobileactivationd、identityservicesd、fairplayd 等）
- **内核驱动**：IOAESAccelerator（硬件 AES 引擎）、AppleKeyStore（密钥管理）、ProvInfoIOKit（设备信息采集）
- **安全隔区（SEP）**：独立处理器，运行 SEPOS，管理 UID/GID 硬件密钥、SKS（Secure Key Store）密钥体系
- **硬件密钥引擎**：AES 加速器内置 GID（同型号共享）、UID（设备唯一）、Device Key（设备密钥）等不可导出的硬件密钥

数据流方向：AP 用户态 → 内核 IOKit → AES 硬件 / SEP，密钥运算全部在硬件内完成，AP 侧只能请求运算、不能读取密钥本体。

---

# 二、DRM 激活流程（iOS 10+）

## 2.1 流程概览

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

## 2.2 关键阶段

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

## 2.3 IOAESAccelerator Special Key 机制

内核 AES 硬件引擎在启动时执行 `_initKeyCache`：

1. 从 nonce table 读取 source plaintext（每个 entry：4B handle + 4B keyType + 16B plaintext）
2. 用 GID/UID key 加密 GID 类 plaintext → cached key
3. 禁用 GID/UID 的直接硬件访问（`disableHardwareKey`）
4. 用 Device Key 加密剩余 plaintext → cached key
5. 后续 AES 操作通过 handle（如 0x899、0x89D）查 cached table 获取密钥

Special key 的 cached ciphertext 是设备相关的（UID/Device Key 每台不同），FairPlay 和 ProvInfoIOKit 的加密结果依赖这些 cached key 的正确性。

## 2.4 Descrambler（0xBB8）

IOAESAccelerator 的 descrambler（keyId=3000）是硬件级的解扰操作：
- 输入：key data（来自 special key 加密结果） + addon data（32 字节 info）
- 内部使用与 UID 相关的固定硬件密钥
- 输出：解扰后的 seed 数据

Descrambler 的输入 key data 依赖 special key（如 0x89D）的加密结果，因此 special key 的正确性直接影响 descrambler 输出。

---

# 三、SEP 密钥体系（SKS）

## 3.1 密钥类型

| keyType | 名称 | 创建方式 | 特点 |
|---------|------|---------|------|
| 1 | DeviceKey | sks_create_device_key | 设备唯一，用于 SCRT/PCRT |
| 2 | UIK (committed) | sks_create_key_simple(2,2) | UID 派生，用于设备证明 |
| 3 | UIK (proposed) | sks_create_gid_key(3) | GID 派生 |
| 6 | SIK | sks_create_gid_key(2) | 不可导出的根密钥 |
| 7/8/9 | SigningKey/RefKey | sks_create_key_simple | 签名用途 |

## 3.2 Attestation 链

```
SIK → DeviceKey → UIK → RefKey
```

- UIKCertification：DeviceKey 签 UIK（SecKeyCreateAttestation）
- RKCertification：UIK 签 RefKey
- 每级 attestation 包含 GIDPubkeyHash = SHA256(签名方公钥)，形成信任链

---

# 四、iMessage（IDS）注册与 Absinthe 验证

## 4.1 注册流程

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

## 4.2 Absinthe 机制

Absinthe 是苹果的设备验证框架（absd daemon），用于 iMessage/FaceTime 等服务的注册验证：

- **AbsintheHello**：生成 hello 消息，创建 validation session
- **AbsintheActivateSession**：用 Apple 返回的 response + server key 激活 session
- **AbsintheSignData**：用激活后的 session 签名数据

Absinthe 内部通过 IOAESAccelerator 的 descrambler（keyId=0xBB8）进行硬件级加密操作，与 DRM 激活共享相同的 AES 基础设施。

## 4.3 SUInfo（psc.sui）的作用

psc.sui 是 PSC 会话过程中产生的加密数据，由 ProvInfoIOKit 使用 special key（0x89D）加密 SUInfo 生成。它在后续的 iMessage 注册等流程中作为设备信任凭证使用。

---

# 五、硬件安全边界

## 5.1 不可导出的密钥

- **UID Key**：设备唯一，烧录在 SoC 中，只能在 AES 硬件引擎内使用
- **GID Key**：同型号/SoC 家族共享，同样不可导出
- **Device Key（0x7D0）**：设备唯一的 AES 密钥，用于 special key 派生
- **SEP 密钥**：SIK、DeviceKey 等 SEP 密钥只在安全隔区内存在

## 5.2 ECID 绑定

ECID（Exclusive Chip ID）是 SoC 唯一编号，用于个性化签名（personalization）。AP Ticket、激活记录等都绑定到 ECID，使授权只对单台设备有效。

## 5.3 Special Key 与 Descrambler 的桥梁作用

Special key 的 cached ciphertext 是连接软件 AES 操作和硬件 descrambler 的桥梁：
- 软件侧：用 cached key 做 AES 加密，产生 key data
- 硬件侧：descrambler 用内部密钥对 key data 做解扰
- 两者必须配套，cached key 必须是由真实硬件密钥派生的正确值

---

# 六、合规声明

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
