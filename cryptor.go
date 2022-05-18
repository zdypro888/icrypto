package icrypto

import (
	context "context"
	"errors"
	"fmt"
	"time"

	uuid "github.com/satori/go.uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"howett.net/plist"
)

var cryptoConn *grpc.ClientConn
var cryptoClient CryptServiceClient

func InitCryptor(address string) error {
	var err error
	if cryptoConn, err = grpc.Dial(address, grpc.WithTransportCredentials(insecure.NewCredentials())); err != nil {
		return err
	}
	cryptoClient = NewCryptServiceClient(cryptoConn)
	return nil
}

//CryptoError error for crypto
type CryptoError struct {
	Code    int32
	Message string
}

func (ce *CryptoError) Error() string {
	return fmt.Sprintf("%s(Code: %d)", ce.Message, ce.Code)
}

type Cryptor struct {
	clientId string
}

func NewCryptor() (*Cryptor, error) {
	if cryptoClient == nil {
		return nil, errors.New("please InitCryptor first")
	}
	crypt := &Cryptor{
		clientId: uuid.NewV4().String(),
	}
	return crypt, nil
}

func (crypt *Cryptor) metaContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	md := metadata.Pairs("client_id", crypt.clientId)
	metactx := metadata.NewOutgoingContext(ctx, md)
	return metactx, cancel
}

//Initialize init crypto with device[see device struct]
func (crypt *Cryptor) Initialize(device any) error {
	devicePlist, err := plist.MarshalIndent(device, plist.BinaryFormat, "\t")
	if err != nil {
		return err
	}
	ctx, cancel := crypt.metaContext()
	defer cancel()
	if _, err = cryptoClient.Initialize(ctx, &InitializeRequest{DevicePlist: devicePlist}); err != nil {
		return err
	}
	return nil
}

//InitDevice finalize crypto
func (crypt *Cryptor) Finalize() error {
	ctx, cancel := crypt.metaContext()
	defer cancel()
	if _, err := cryptoClient.Finalize(ctx, &FinalizeRequest{}); err != nil {
		return err
	}
	return nil
}

//Activation 取得激活信息 Sign Cert Error
func (crypt *Cryptor) Activation(sha1Data []byte) ([]byte, []byte, error) {
	ctx, cancel := crypt.metaContext()
	defer cancel()
	var err error
	var response *ActivationResponse
	if response, err = cryptoClient.Activation(ctx, &ActivationRequest{Sha1Data: sha1Data}); err != nil {
		return nil, nil, err
	}
	if response.Code != 0 {
		return nil, nil, &CryptoError{Code: response.Code, Message: "Activation Faild"}
	}
	return response.Sign, response.Cert, nil
}

//ActivationKeyData 设置激活KEY
func (crypt *Cryptor) ActivationKeyData(keyData []byte) error {
	ctx, cancel := crypt.metaContext()
	defer cancel()
	var err error
	if _, err = cryptoClient.ActivationKeyData(ctx, &ActivationKeyDataRequest{KeyData: keyData}); err != nil {
		return err
	}
	return nil
}

//ActivationDRMHandshake 请求DRM 返回 session handshakeMessage Error
func (crypt *Cryptor) ActivationDRMHandshake() (uint64, []byte, error) {
	ctx, cancel := crypt.metaContext()
	defer cancel()
	var err error
	var response *ActivationDRMHandshakeResponse
	if response, err = cryptoClient.ActivationDRMHandshake(ctx, &ActivationDRMHandshakeRequest{}); err != nil {
		return 0, nil, err
	}
	if response.Code != 0 {
		return 0, nil, &CryptoError{Code: response.Code, Message: "DRMHandshake Faild"}
	}
	return response.Session, response.HandshakeRequestMessage, nil
}

//ActivationDRMHandshakeResponse 设置DRM信息 返回 SignActRequest ServerKP Error
func (crypt *Cryptor) ActivationDRMHandshakeResponse(session uint64, fdrBlob []byte, suInfo []byte, handshakeResponseMessage []byte, serverKP []byte, activationInfoXML []byte) ([]byte, []byte, error) {
	ctx, cancel := crypt.metaContext()
	defer cancel()
	var err error
	var response *ActivationDRMHandshakeInfoResponse
	if response, err = cryptoClient.ActivationDRMHandshakeInfo(ctx, &ActivationDRMHandshakeInfoRequest{Session: session, FDRBlob: fdrBlob, SUInfo: suInfo, HandshakeResponseMessage: handshakeResponseMessage, ServerKP: serverKP, ActivationInfoXML: activationInfoXML}); err != nil {
		return nil, nil, err
	}
	if response.Code != 0 {
		return nil, nil, &CryptoError{Code: response.Code, Message: "DRMHandshakeResponse Faild"}
	}
	return response.SignActRequest, response.ServerKP, nil
}

//ADIStartProvisioning 返回 CPIM Session Error
func (crypt *Cryptor) ADIStartProvisioning(dsid int64, spim []byte) ([]byte, uint64, error) {
	ctx, cancel := crypt.metaContext()
	defer cancel()
	var err error
	var response *ADIStartProvisioningResponse
	if response, err = cryptoClient.ADIStartProvisioning(ctx, &ADIStartProvisioningRequest{DSID: dsid, SPIM: spim}); err != nil {
		return nil, 0, err
	}
	if response.Code != 0 {
		return nil, 0, &CryptoError{Code: response.Code, Message: "ADIStartProvisioning Faild"}
	}
	return response.CPIM, response.Session, nil
}

//ADIEndProvisioning 返回 MID OTP ADI Error
func (crypt *Cryptor) ADIEndProvisioning(session uint64, dsid int64, rinfo int64, ptm []byte, tk []byte, adi []byte) ([]byte, []byte, []byte, error) {
	ctx, cancel := crypt.metaContext()
	defer cancel()
	var err error
	var response *ADIEndProvisioningResponse
	if response, err = cryptoClient.ADIEndProvisioning(ctx, &ADIEndProvisioningRequest{Session: session, DSID: dsid, RINFO: rinfo, PTM: ptm, TK: tk, ADI: adi}); err != nil {
		return nil, nil, nil, err
	}
	if response.Code != 0 {
		return nil, nil, nil, &CryptoError{Code: response.Code, Message: "ADIEndProvisioning Faild"}
	}
	return response.MID, response.OTP, response.ADI, nil
}

//IndentitySession 注册 SessionInfoRequest
func (crypt *Cryptor) IndentitySession(cert []byte) ([]byte, error) {
	ctx, cancel := crypt.metaContext()
	defer cancel()
	var err error
	var response *IndentitySessionResponse
	if response, err = cryptoClient.IndentitySession(ctx, &IndentitySessionRequest{Cert: cert}); err != nil {
		return nil, err
	}
	if response.Code != 0 {
		return nil, &CryptoError{Code: response.Code, Message: "IndentitySession Faild"}
	}
	return response.Request, nil
}

//IndentityValidation 取得VD
func (crypt *Cryptor) IndentityValidation(sessionInfo []byte, signData []byte) ([]byte, error) {
	ctx, cancel := crypt.metaContext()
	defer cancel()
	var err error
	var response *IndentityValidationResponse
	if response, err = cryptoClient.IndentityValidation(ctx, &IndentityValidationRequest{Response: sessionInfo, SignData: signData}); err != nil {
		return nil, err
	}
	if response.Code != 0 {
		return nil, &CryptoError{Code: response.Code, Message: "IndentityValidation Faild"}
	}
	return response.VlidationData, nil
}
