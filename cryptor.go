package icrypto

import (
	"context"
	"fmt"
)

// CryptoError error for crypto
type CryptoError struct {
	Code   int32
	Method string
}

func (ce *CryptoError) Error() string {
	return fmt.Sprintf("method: %s code: %d", ce.Method, ce.Code)
}

type Cryptor interface {
	//Initialize with device plist data
	Initialize(ctx context.Context, type_ InitializeType, device *Device) error
	//Finalize finalize object
	Finalize(ctx context.Context) error

	//ActivationDRMHandshake generate [0]CollectionBlob and [1]handshakeRequestMessage
	ActivationDRMHandshake(ctx context.Context) ([]byte, []byte, error)
	//ActivationDRMProcess process handshake response and return [0]UIK [1]RK
	ActivationDRMProcess(ctx context.Context, suinfo, handshakeResponseMessage, serverKP []byte) ([]byte, []byte, error)
	//ActivationDRMSignature sign activation xml and return [0]fairpalySign, [1]fairplayCert, [2]RKSignature, [3]signActRequest, [4]serverKP
	ActivationDRMSignature(ctx context.Context, activationXML []byte) ([]byte, []byte, []byte, []byte, []byte, error)
	//ActivationDeprecated return [0]fairpalySign, [1]fairplayCert
	ActivationDeprecated(ctx context.Context, activationXML []byte) ([]byte, []byte, error)
	//ActivationRecord set activation response return [0]subCAKey, [1]attestationKey, [2]UIK, [3]RK, [4]psc.sui
	ActivationRecord(ctx context.Context, unbrick bool, AccountTokenCertificate, DeviceCertificate, RegulatoryInfo, FairPlayKeyData, AccountToken, AccountTokenSignature, UniqueDeviceCertificate []byte) ([]byte, []byte, []byte, []byte, []byte, error)

	//ADIStartProvisioning 返回 CPIM Session Error
	ADIStartProvisioning(ctx context.Context, dsid int64, spim []byte) ([]byte, uint64, error)
	//ADIEndProvisioning 返回 MID OTP ADI Error
	ADIEndProvisioning(ctx context.Context, session uint64, dsid int64, rinfo int64, ptm []byte, tk []byte, adi []byte) ([]byte, []byte, []byte, error)
	//ADIGenerateLoginCode 返回 loginCode
	ADIGenerateLoginCode(ctx context.Context, dsid int64, adi []byte) (uint32, error)

	//AbsintheHello 取得 absinthe hello
	AbsintheHello(ctx context.Context, mode int) ([]byte, error)
	//AbsintheAddOption 添加 option
	AbsintheAddOption(ctx context.Context, BIKKeyRef []byte, BAACert []byte, intermediateRootCert []byte) error
	//AbsintheActivateSession 设置 session 返回（absinthe-response）
	AbsintheActivateSession(ctx context.Context, validationData []byte, serverKey []byte) error
	//AbsintheSignData signData 返回 signature outServKey
	AbsintheSignData(ctx context.Context, dataToSign []byte) ([]byte, []byte, error)

	//IdentitySession 注册 SessionInfoRequest
	IdentitySession(ctx context.Context, cert []byte) ([]byte, error)
	//IdentityValidation 取得VD
	IdentityValidation(ctx context.Context, sessionInfo []byte, signData []byte) ([]byte, error)

	//SAPExchange 交换数据
	SAPExchange(ctx context.Context, version int, data []byte) ([]byte, error)
	//SAPSignPrime 签名 prime
	SAPSignPrime(ctx context.Context, signData []byte) ([]byte, error)
	//SAPVerifyPrime 验证 prime
	SAPVerifyPrime(ctx context.Context, data []byte) error
	//SAPSign 签名
	SAPSign(ctx context.Context, signData []byte) ([]byte, error)
	//SAPVerify 验证
	SAPVerify(ctx context.Context, data []byte, signature []byte) error
}

// NewCryptorCall 创建cryptor调用
type NewCryptorCall func() Cryptor

// NewCryptor 创建cryptor
var NewCryptor NewCryptorCall
