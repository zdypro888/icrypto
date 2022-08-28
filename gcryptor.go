package icrypto

import (
	context "context"
	"time"

	uuid "github.com/satori/go.uuid"
	"github.com/zdypro888/go-plist"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

var cryptoConn *grpc.ClientConn
var cryptoClient CryptServiceClient

func InitCryptorGRPC(address string) error {
	var err error
	if cryptoConn, err = grpc.Dial(address, grpc.WithTransportCredentials(insecure.NewCredentials())); err != nil {
		return err
	}
	cryptoClient = NewCryptServiceClient(cryptoConn)
	NewCryptor = func(ckind CryptorKind) Cryptor {
		return NewCryptorGRPC(101)
	}
	return nil
}

func NewCryptorGRPC(hardware int) Cryptor {
	crypt := &CryptorGrpc{
		ClientId: uuid.NewV4().String(),
		Hardware: hardware,
		Client:   cryptoClient,
	}
	return crypt
}

type CryptorGrpc struct {
	ClientId string
	Hardware int
	Client   CryptServiceClient
}

func (crypt *CryptorGrpc) metaContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	md := metadata.Pairs("client_id", crypt.ClientId)
	metactx := metadata.NewOutgoingContext(ctx, md)
	return metactx, cancel
}

// Initialize init crypto with device[see device struct]
func (crypt *CryptorGrpc) Initialize(device any) error {
	devicePlist, err := plist.MarshalIndent(device, plist.BinaryFormat, "\t")
	if err != nil {
		return err
	}
	ctx, cancel := crypt.metaContext()
	defer cancel()
	if _, err = crypt.Client.Initialize(ctx, &InitializeRequest{DevicePlist: devicePlist, Hardware: int32(crypt.Hardware)}); err != nil {
		return err
	}
	return nil
}

// InitDevice finalize crypto
func (crypt *CryptorGrpc) Finalize() error {
	ctx, cancel := crypt.metaContext()
	defer cancel()
	if _, err := crypt.Client.Finalize(ctx, &FinalizeRequest{}); err != nil {
		return err
	}
	return nil
}

// Activation 取得激活信息 Sign Cert Error
func (crypt *CryptorGrpc) Activation(sha1Data []byte) ([]byte, []byte, error) {
	ctx, cancel := crypt.metaContext()
	defer cancel()
	var err error
	var response *ActivationResponse
	if response, err = crypt.Client.Activation(ctx, &ActivationRequest{Sha1Data: sha1Data}); err != nil {
		return nil, nil, err
	}
	return response.Sign, response.Cert, nil
}

// ActivationKeyData 设置激活KEY
func (crypt *CryptorGrpc) ActivationKeyData(keyData []byte) error {
	ctx, cancel := crypt.metaContext()
	defer cancel()
	var err error
	if _, err = crypt.Client.ActivationKeyData(ctx, &ActivationKeyDataRequest{KeyData: keyData}); err != nil {
		return err
	}
	return nil
}

// ActivationDRMGenerate 取得 ActivationDRM HelloMessage
func (crypt *CryptorGrpc) ActivationDRMGenerate() ([]byte, error) {
	ctx, cancel := crypt.metaContext()
	defer cancel()
	var err error
	var response *ActivationDRMGenerateResponse
	if response, err = crypt.Client.ActivationDRMGenerate(ctx, &ActivationDRMGenerateRequest{}); err != nil {
		return nil, err
	}
	return response.HelloMessage, nil
}

// ActivationDRMResponse 设置返回 message(process response message)
func (crypt *CryptorGrpc) ActivationDRMResponse(HandshakeResponseMessage []byte, serverKP []byte) error {
	ctx, cancel := crypt.metaContext()
	defer cancel()
	var err error
	if _, err = crypt.Client.ActivationDRMResponse(ctx, &ActivationDRMResponseRequest{HandshakeResponseMessage: HandshakeResponseMessage, ServerKP: serverKP}); err != nil {
		return err
	}
	return nil
}

// ActivationDRMSignData signData 返回 signActRequest serverKP
func (crypt *CryptorGrpc) ActivationDRMSignData(dataToSign []byte) ([]byte, []byte, error) {
	ctx, cancel := crypt.metaContext()
	defer cancel()
	var err error
	var response *ActivationDRMSignDataResponse
	if response, err = crypt.Client.ActivationDRMSignData(ctx, &ActivationDRMSignDataRequest{ActivationInfoXML: dataToSign}); err != nil {
		return nil, nil, err
	}
	return response.SignActRequest, response.ServerKP, nil
}

// ADIStartProvisioning 返回 CPIM Session Error
func (crypt *CryptorGrpc) ADIStartProvisioning(dsid int64, spim []byte) ([]byte, uint64, error) {
	ctx, cancel := crypt.metaContext()
	defer cancel()
	var err error
	var response *ADIStartProvisioningResponse
	if response, err = crypt.Client.ADIStartProvisioning(ctx, &ADIStartProvisioningRequest{DSID: dsid, SPIM: spim}); err != nil {
		return nil, 0, err
	}
	return response.CPIM, response.Session, nil
}

// ADIEndProvisioning 返回 MID OTP ADI Error
func (crypt *CryptorGrpc) ADIEndProvisioning(session uint64, dsid int64, rinfo int64, ptm []byte, tk []byte, adi []byte) ([]byte, []byte, []byte, error) {
	ctx, cancel := crypt.metaContext()
	defer cancel()
	var err error
	var response *ADIEndProvisioningResponse
	if response, err = crypt.Client.ADIEndProvisioning(ctx, &ADIEndProvisioningRequest{Session: session, DSID: dsid, RINFO: rinfo, PTM: ptm, TK: tk, ADI: adi}); err != nil {
		return nil, nil, nil, err
	}
	return response.MID, response.OTP, response.ADI, nil
}

func (crypt *CryptorGrpc) AbsintheHello(mode int) ([]byte, error) {
	ctx, cancel := crypt.metaContext()
	defer cancel()
	var err error
	var response *AbsintheHelloResponse
	if response, err = crypt.Client.AbsintheHello(ctx, &AbsintheHelloRequest{Mode: int32(mode)}); err != nil {
		return nil, err
	}
	return response.HelloMessage, nil
}

func (crypt *CryptorGrpc) AbsintheAddOption(BIKKey []byte, BAACert []byte, intermediateRootCert []byte) error {
	ctx, cancel := crypt.metaContext()
	defer cancel()
	var err error
	if _, err = crypt.Client.AbsintheAddOption(ctx, &AbsintheAddOptionRequest{BIKKey: BIKKey, BAACert: BAACert, IntermediateRootCert: intermediateRootCert}); err != nil {
		return err
	}
	return nil
}

// AbsintheAtivateSession 设置 session 返回（absinthe-response）
func (crypt *CryptorGrpc) AbsintheAtivateSession(validationData []byte, serverKey []byte) error {
	ctx, cancel := crypt.metaContext()
	defer cancel()
	var err error
	if _, err = crypt.Client.AbsintheAtivateSession(ctx, &AbsintheAtivateSessionRequest{ValidationData: validationData, ServerKey: serverKey}); err != nil {
		return err
	}
	return nil
}

// AbsintheSignData signData 返回 signature outServKey
func (crypt *CryptorGrpc) AbsintheSignData(dataToSign []byte) ([]byte, []byte, error) {
	ctx, cancel := crypt.metaContext()
	defer cancel()
	var err error
	var response *AbsintheSignDataResponse
	if response, err = crypt.Client.AbsintheSignData(ctx, &AbsintheSignDataRequest{SignData: dataToSign}); err != nil {
		return nil, nil, err
	}
	return response.Signature, response.OutServKey, nil
}

// IndentitySession 注册 SessionInfoRequest
func (crypt *CryptorGrpc) IndentitySession(cert []byte) ([]byte, error) {
	ctx, cancel := crypt.metaContext()
	defer cancel()
	var err error
	var response *IndentitySessionResponse
	if response, err = crypt.Client.IndentitySession(ctx, &IndentitySessionRequest{Cert: cert}); err != nil {
		return nil, err
	}
	return response.Request, nil
}

// IndentityValidation 取得VD
func (crypt *CryptorGrpc) IndentityValidation(sessionInfo []byte, signData []byte) ([]byte, error) {
	ctx, cancel := crypt.metaContext()
	defer cancel()
	var err error
	var response *IndentityValidationResponse
	if response, err = crypt.Client.IndentityValidation(ctx, &IndentityValidationRequest{Response: sessionInfo, SignData: signData}); err != nil {
		return nil, err
	}
	return response.VlidationData, nil
}
