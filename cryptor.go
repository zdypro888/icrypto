package icrypto

import (
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
	Initialize(device any) error
	//Finalize finalize object
	Finalize() error

	//ActivationDRMHandshake generate [0]CollectionBlob and [1]handshakeRequestMessage
	ActivationDRMHandshake() ([]byte, []byte, error)
	//ActivationDRMProcess process handshake response and return [0]UIK [1]RK
	ActivationDRMProcess(suinfo, handshakeResponseMessage, serverKP []byte) ([]byte, []byte, error)
	//ActivationDRMSignature sign activation xml and return [0]fairpalySign, [1]fairplayCert, [2]RKSignature, [3]signActRequest, [4]serverKP
	ActivationDRMSignature(activationXML []byte) ([]byte, []byte, []byte, []byte, []byte, error)
	//ActivationDeprecated return [0]fairpalySign, [1]fairplayCert
	ActivationDeprecated(activationXML []byte) ([]byte, []byte, error)
	//ActivationRecord set activation response return [0]subCAKey, [1]attestationKey, [2]UIK, [3]RK, [4]psc.sui
	ActivationRecord(unbrick bool, AccountTokenCertificate, DeviceCertificate, RegulatoryInfo, FairPlayKeyData, AccountToken, AccountTokenSignature, UniqueDeviceCertificate []byte) ([]byte, []byte, []byte, []byte, []byte, error)

	//ADIStartProvisioning 返回 CPIM Session Error
	ADIStartProvisioning(dsid int64, spim []byte) ([]byte, uint64, error)
	//ADIEndProvisioning 返回 MID OTP ADI Error
	ADIEndProvisioning(session uint64, dsid int64, rinfo int64, ptm []byte, tk []byte, adi []byte) ([]byte, []byte, []byte, error)
	//AbsintheHello 取得 absinthe hello
	AbsintheHello(mode int) ([]byte, error)
	//AbsintheAddOption 添加 option
	AbsintheAddOption(BIKKeyRef []byte, BAACert []byte, intermediateRootCert []byte) error
	//AbsintheAtivateSession 设置 session 返回（absinthe-response）
	AbsintheAtivateSession(validationData []byte, serverKey []byte) error
	//AbsintheSignData signData 返回 signature outServKey
	AbsintheSignData(dataToSign []byte) ([]byte, []byte, error)
	//IndentitySession 注册 SessionInfoRequest
	IndentitySession(cert []byte) ([]byte, error)
	//IndentityValidation 取得VD
	IndentityValidation(sessionInfo []byte, signData []byte) ([]byte, error)
}

// NewCryptorCall 创建cryptor调用
type NewCryptorCall func() Cryptor

// NewCryptor 创建cryptor
var NewCryptor NewCryptorCall
