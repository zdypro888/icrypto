package icrypto

import (
	"fmt"
)

//CryptoError error for crypto
type CryptoError struct {
	Code    int32
	Message string
}

func (ce *CryptoError) Error() string {
	return fmt.Sprintf("%s(Code: %d)", ce.Message, ce.Code)
}

type Cryptor interface {
	//Initialize 初始化
	Initialize(device any, hardware int) error
	//Finalize 释放
	Finalize() error
	//Activation 取得激活信息 Sign Cert Error
	Activation(sha1Data []byte) ([]byte, []byte, error)
	ActivationKeyData(keyData []byte) error
	//ActivationDRMHandshake 请求DRM 返回 session handshakeMessage Error
	ActivationDRMHandshake() (uint64, []byte, error)
	//ActivationDRMHandshakeResponse 设置DRM信息 返回 SignActRequest ServerKP Error
	ActivationDRMHandshakeResponse(session uint64, fdrBlob []byte, suInfo []byte, handshakeResponseMessage []byte, serverKP []byte, activationInfoXML []byte) ([]byte, []byte, error)
	//ADIStartProvisioning 返回 CPIM Session Error
	ADIStartProvisioning(dsid int64, spim []byte) ([]byte, uint64, error)
	//ADIEndProvisioning 返回 MID OTP ADI Error
	ADIEndProvisioning(session uint64, dsid int64, rinfo int64, ptm []byte, tk []byte, adi []byte) ([]byte, []byte, []byte, error)
	//AbsintheHello 取得 absinthe hello
	AbsintheHello(mode int) ([]byte, error)
	//IndentitySession 注册 SessionInfoRequest
	IndentitySession(cert []byte) ([]byte, error)
	//IndentityValidation 取得VD
	IndentityValidation(sessionInfo []byte, signData []byte) ([]byte, error)
}

var NewCryptor func() (Cryptor, error)
