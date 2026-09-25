// Package icrypto 定义设备密码计算接口及 RPC 客户端。
// idevice 负责业务流程和 Apple HTTP 交互，iunios 实现本地运行环境与原生计算；
// 本包不决定使用 A/B 哪套身份，也不负责取得 Apple 的握手响应。
package icrypto

import (
	"context"
	"fmt"
)

// CryptoError 保留原生计算函数返回的错误码及出错阶段。
// Code 不是 HTTP 状态码；调用方应保留 Method，避免将不同阶段的错误混为一谈。
type CryptoError struct {
	Code   int32
	Method string
}

func (ce *CryptoError) Error() string {
	return fmt.Sprintf("method: %s code: %d", ce.Method, ce.Code)
}

// IPlistObject 是跨后端传递设备状态的编解码契约。
// 具体实现决定编码格式，不能仅凭接口名称假定 Marshal 一定返回 XML plist。
// Initialize 可回写设备状态；传入共享设备前，业务层应创建独立快照。
type IPlistObject interface {
	Marshal() ([]byte, error)
	Unmarshal(data []byte) error
}

// DeviceSynchronizer 表示后端支持向现有会话合并设备状态。
// 用于补入 Initialize 后取得的 AP 票据等信息，不重新创建会话或清除握手状态。
// 调用方需检查此能力；不能用重复 Initialize 代替同步。
type DeviceSynchronizer interface {
	SyncDevice(ctx context.Context, device IPlistObject) error
}

// Cryptor 表示一个计算会话，不等同于设备身份或物理硬件。
// 除独立的 ActivationSign 外，计算前必须 Initialize，结束时必须 Finalize。
// 同一次握手的所有步骤必须使用同一实例；调用方负责完整业务流程的串行化，
// 单个方法的锁不能防止两个握手交错。失败后不能假定原生会话仍可复用。
// 支持哪些计算由运行环境决定，接口存在不代表 Legacy、iPhone5 等环境都支持。
type Cryptor interface {
	// ActivationSign 单次计算传统激活签名和证书，不要求 Initialize。
	// profile 选择签名实现；macOSRuntime 仅选择 macOS 计算环境；device 提供计算身份。
	// activationXML 必须是最终发送的原始 XML 字节，签名后不能重新编码。
	// 实现负责释放临时计算环境，不修改传入设备，也不替换已有会话。
	ActivationSign(ctx context.Context, profile ActivationSigningProfile, macOSRuntime MacOSRuntime, device IPlistObject, activationXML []byte) (signature, certificate []byte, err error)

	// Initialize 按设备身份与 options 创建有状态计算环境，可向 device 回写硬件信息。
	// options 不改变上报的机型和系统版本；切换运行环境应先结束旧会话。
	Initialize(ctx context.Context, options InitializeOptions, device IPlistObject) error
	// Finalize 释放会话资源；即使初始化或握手失败，也应执行清理。
	// 清理应使用独立且有超时的 context，避免业务取消导致资源滞留。
	Finalize(ctx context.Context) error

	// ActivationDRMHandshake 开始 DRM 激活，返回送交 Apple 的采集数据与握手消息。
	// 需要支持 DRM 的运行环境和相应硬件；不执行 Apple 网络请求。
	ActivationDRMHandshake(ctx context.Context) (collectionBlob, handshakeRequest []byte, err error)
	// ActivationDRMProcess 在同一会话处理握手响应，返回 UIK 与 RK。
	// 三项输入须来自本次流程，不能跨设备或跨会话拼接。
	ActivationDRMProcess(ctx context.Context, suinfo, handshakeResponseMessage, serverKP []byte) (uik, rk []byte, err error)
	// ActivationDRMSignature 在 DRM 握手后签署最终激活 XML。
	// 各返回值对应独立协议字段，调用方不得调换顺序或再次编码被签名的数据。
	ActivationDRMSignature(ctx context.Context, activationXML []byte) (signature, certificate, rkSignature, signedActivationRequest, serverKP []byte, err error)
	// ActivationDeprecated 使用已初始化会话计算传统激活签名；不表示 iOS9 实现。
	// 独立传统激活应使用 ActivationSign，避免借用正在进行其他握手的会话。
	ActivationDeprecated(ctx context.Context, activationXML []byte) (signature, certificate []byte, err error)
	// ActivationRecord 将激活返回材料交给 DRM 会话，导出 psc.sui。
	// 调用方先验证激活记录，再提交业务设备状态；各字段保持 Apple 返回的原始字节。
	// 当前 iunios 实现使用 FairPlayKeyData 并导出会话状态，其余字段不参与该实现的计算。
	ActivationRecord(ctx context.Context, unbrick bool, accountTokenCertificate, deviceCertificate, regulatoryInfo, fairPlayKeyData, accountToken, accountTokenSignature, uniqueDeviceCertificate []byte) (pscSUI []byte, err error)

	// ADIStartProvisioning 用服务器 SPIM 开始配置，返回 CPIM 和本实例内有效的会话句柄。
	// CPIM 由业务层发送给 Apple，session 交给同一实例的 ADIEndProvisioning。
	ADIStartProvisioning(ctx context.Context, dsid int64, spim []byte) (cpim []byte, session uint64, err error)
	// ADIEndProvisioning 完成配置并产生 MID、OTP 和可保存的 ADI 状态。
	// session 非零时消费本次配置的 PTM、TK 和路由信息；为零时使用已有 ADI 请求 OTP。
	// adi 是已有配置数据，不是 FairPlayKeyData；不要记录返回的 OTP 或 ADI 到普通日志。
	ADIEndProvisioning(ctx context.Context, session uint64, dsid int64, rinfo int64, ptm, tk, adi []byte) (mid, otp, updatedADI []byte, err error)
	// ADIGenerateLoginCode 使用 ADI 配置计算登录码；它不是短信验证码的读取接口。
	ADIGenerateLoginCode(ctx context.Context, dsid int64, adi []byte) (loginCode uint32, err error)

	// AbsintheHello 为 Absinthe 握手生成 hello；mode 原样传给原生实现。
	// 不等同于下方的 IdentitySession/IdentityValidation，两条流程不能互相替代。
	AbsintheHello(ctx context.Context, mode int) (hello []byte, err error)
	// AbsintheAddOption 配置 BAA 证书及中间证书。
	// 当前 iunios 原生调用的 BIK 句柄固定为零，尚未消费 bikKeyRef 的字节。
	AbsintheAddOption(ctx context.Context, bikKeyRef, baaCert, intermediateRootCert []byte) error
	// AbsintheActivateSession 使用服务器响应和密钥推进当前 Absinthe 会话。
	// validationData 在这里是该握手的输入，不能仅凭名称当作注册用的 validation-data。
	AbsintheActivateSession(ctx context.Context, validationData, serverKey []byte) error
	// AbsintheSignData 在已建立的 Absinthe 会话中签名，返回签名和输出服务器密钥。
	AbsintheSignData(ctx context.Context, dataToSign []byte) (signature, serverKey []byte, err error)

	// IdentitySession 用服务器证书生成 Validation 握手请求，供业务层发送给 Apple。
	// 后续 IdentityValidation 必须继续使用本实例的状态。
	IdentitySession(ctx context.Context, cert []byte) (sessionInfoRequest []byte, err error)
	// IdentityValidation 处理服务器 sessionInfo 并对 signData 生成 validation-data。
	// sessionInfo 为空时沿用已有握手状态；signData 必须保持协议要求的原始字节。
	IdentityValidation(ctx context.Context, sessionInfo, signData []byte) (validationData []byte, err error)

	// SAPExchange 按指定版本交换 SAP 握手数据；网络交互由业务层推进。
	SAPExchange(ctx context.Context, version int, data []byte) (response []byte, err error)
	// SAPSignPrime 在当前 SAP 会话生成 prime 签名。
	SAPSignPrime(ctx context.Context, signData []byte) (signature []byte, err error)
	// SAPVerifyPrime 验证当前 SAP 会话的 prime 数据，验证失败返回错误。
	SAPVerifyPrime(ctx context.Context, data []byte) error
	// SAPSign 在当前 SAP 会话对原始数据签名。
	SAPSign(ctx context.Context, signData []byte) (signature []byte, err error)
	// SAPVerify 使用同一 SAP 会话验证数据及签名，失败不能当作握手成功。
	SAPVerify(ctx context.Context, data, signature []byte) error
}

// NewCryptorCall 创建独立的计算客户端；不同业务会话不应共享同一个有状态实例。
type NewCryptorCall func() Cryptor

// NewCryptor 由程序启动时注入本地或远程后端工厂，使用前必须设置。
// 不应在并发业务运行期间替换；具体会话的释放由调用方负责。
var NewCryptor NewCryptorCall
