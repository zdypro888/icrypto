package icrypto

import (
	context "context"
	"fmt"
	"time"

	uuid "github.com/satori/go.uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

var cryptoConn *grpc.ClientConn
var cryptoClient CryptServiceClient
var cryptoAPIKey string // 用于 iclouder 代理认证

// InitGRPC 初始化 gRPC 连接（直连 cryptor 服务，无需 apiKey）
func InitGRPC(address string) error {
	return InitGRPCWithAPIKey(address, "")
}

// InitGRPCWithAPIKey 初始化 gRPC 连接（连接 iclouder 代理时需要 apiKey）
func InitGRPCWithAPIKey(address, apiKey string) error {
	var err error
	if cryptoConn, err = grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials())); err != nil {
		return err
	}
	cryptoClient = NewCryptServiceClient(cryptoConn)
	cryptoAPIKey = apiKey
	NewCryptor = NewCryptorGRPC
	return nil
}

func NewCryptorGRPC() Cryptor {
	crypt := &CryptorGRPC{
		ClientId: uuid.NewV4().String(),
		APIKey:   cryptoAPIKey,
		Client:   cryptoClient,
	}
	return crypt
}

type CryptorGRPC struct {
	ClientId string
	APIKey   string // x-api-key for iclouder proxy
	Client   CryptServiceClient
}

func (crypt *CryptorGRPC) metaContext(ctx context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	pairs := []string{"client_id", crypt.ClientId}
	if crypt.APIKey != "" {
		pairs = append(pairs, "x-api-key", crypt.APIKey)
	}
	md := metadata.Pairs(pairs...)
	metactx := metadata.NewOutgoingContext(ctx, md)
	return metactx, cancel
}

// Initialize init crypto with device[see device struct]
func (crypt *CryptorGRPC) Initialize(ctx context.Context, type_ InitializeType, device *Device) error {
	ctx, cancel := crypt.metaContext(ctx)
	defer cancel()
	if response, err := crypt.Client.Initialize(ctx, &InitializeRequest{Type: type_, Device: device}); err != nil {
		return err
	} else {
		*device = *response.Device
	}
	return nil
}

// InitDevice finalize crypto
func (crypt *CryptorGRPC) Finalize(ctx context.Context) error {
	ctx, cancel := crypt.metaContext(ctx)
	defer cancel()
	if _, err := crypt.Client.Finalize(ctx, &FinalizeRequest{}); err != nil {
		return err
	}
	return nil
}

// ActivationDRMHandshake generate [0]CollectionBlob and [1]handshakeRequestMessage
func (crypt *CryptorGRPC) ActivationDRMHandshake(ctx context.Context) ([]byte, []byte, error) {
	ctx, cancel := crypt.metaContext(ctx)
	defer cancel()
	var err error
	var response *ActivationDRMHandshakeResponse
	if response, err = crypt.Client.ActivationDRMHandshake(ctx, &ActivationDRMHandshakeRequest{}); err != nil {
		return nil, nil, err
	}
	return response.CollectionBlob, response.HandshakeRequestMessage, nil
}

// ActivationDRMProcess process handshake response and return [0]UIK [1]RK
func (crypt *CryptorGRPC) ActivationDRMProcess(ctx context.Context, suinfo, handshakeResponseMessage, serverKP []byte) ([]byte, []byte, error) {
	ctx, cancel := crypt.metaContext(ctx)
	defer cancel()
	var err error
	var response *ActivationDRMProcessResponse
	if response, err = crypt.Client.ActivationDRMProcess(ctx, &ActivationDRMProcessRequest{SUInfo: suinfo, HandshakeResponseMessage: handshakeResponseMessage, ServerKP: serverKP}); err != nil {
		return nil, nil, err
	}
	return response.UIK, response.RK, nil
}

// ActivationDRMSignature sign activation xml and return [0]fairpalySign, [1]fairplayCert, [2]RKSignature, [3]signActRequest, [4]serverKP
func (crypt *CryptorGRPC) ActivationDRMSignature(ctx context.Context, activationXML []byte) ([]byte, []byte, []byte, []byte, []byte, error) {
	ctx, cancel := crypt.metaContext(ctx)
	defer cancel()
	var err error
	var response *ActivationDRMSignatureResponse
	if response, err = crypt.Client.ActivationDRMSignature(ctx, &ActivationDRMSignatureRequest{ActivationInfoXml: activationXML}); err != nil {
		return nil, nil, nil, nil, nil, err
	}
	return response.FairplaySignature, response.FairplayCertChain, response.RKSignature, response.SignActRequest, response.ServerKP, nil
}

// ActivationDeprecated return [0]fairpalySign, [1]fairplayCert
func (crypt *CryptorGRPC) ActivationDeprecated(ctx context.Context, activationXML []byte) ([]byte, []byte, error) {
	ctx, cancel := crypt.metaContext(ctx)
	defer cancel()
	var err error
	var response *ActivationDeprecatedResponse
	if response, err = crypt.Client.ActivationDeprecated(ctx, &ActivationDeprecatedRequest{ActivationInfoXml: activationXML}); err != nil {
		return nil, nil, err
	}
	return response.Sign, response.Cert, nil
}

// ActivationRecord set activation response return [0]subCAKey, [1]attestationKey, [2]UIK, [3]RK, [4]psc.sui
func (crypt *CryptorGRPC) ActivationRecord(ctx context.Context, unbrick bool, AccountTokenCertificate, DeviceCertificate, RegulatoryInfo, FairPlayKeyData, AccountToken, AccountTokenSignature, UniqueDeviceCertificate []byte) ([]byte, []byte, []byte, []byte, []byte, error) {
	ctx, cancel := crypt.metaContext(ctx)
	defer cancel()
	var err error
	var response *ActivationRecordResponse
	if response, err = crypt.Client.ActivationRecord(ctx, &ActivationRecordRequest{
		Unbrick:                 unbrick,
		AccountTokenCertificate: AccountTokenCertificate,
		DeviceCertificate:       DeviceCertificate,
		RegulatoryInfo:          RegulatoryInfo,
		FairplayKeyData:         FairPlayKeyData,
		AccountToken:            AccountToken,
		AccountTokenSignature:   AccountTokenSignature,
		UniqueDeviceCertificate: UniqueDeviceCertificate,
	}); err != nil {
		return nil, nil, nil, nil, nil, err
	}
	return response.SubCAKey, response.AttestationKey, response.UIK, response.RK, response.PscSui, nil
}

// ADIStartProvisioning 返回 CPIM Session Error
func (crypt *CryptorGRPC) ADIStartProvisioning(ctx context.Context, dsid int64, spim []byte) ([]byte, uint64, error) {
	ctx, cancel := crypt.metaContext(ctx)
	defer cancel()
	var err error
	var response *ADIStartProvisioningResponse
	if response, err = crypt.Client.ADIStartProvisioning(ctx, &ADIStartProvisioningRequest{DSID: dsid, SPIM: spim}); err != nil {
		return nil, 0, err
	}
	return response.CPIM, response.Session, nil
}

// ADIEndProvisioning 返回 MID OTP ADI Error
func (crypt *CryptorGRPC) ADIEndProvisioning(ctx context.Context, session uint64, dsid int64, rinfo int64, ptm []byte, tk []byte, adi []byte) ([]byte, []byte, []byte, error) {
	ctx, cancel := crypt.metaContext(ctx)
	defer cancel()
	var err error
	var response *ADIEndProvisioningResponse
	if response, err = crypt.Client.ADIEndProvisioning(ctx, &ADIEndProvisioningRequest{Session: session, DSID: dsid, RINFO: rinfo, PTM: ptm, TK: tk, ADI: adi}); err != nil {
		return nil, nil, nil, err
	}
	return response.MID, response.OTP, response.ADI, nil
}

// ADIGenerateLoginCode 返回 loginCode
func (crypt *CryptorGRPC) ADIGenerateLoginCode(ctx context.Context, dsid int64, adi []byte) (uint32, error) {
	ctx, cancel := crypt.metaContext(ctx)
	defer cancel()
	var err error
	var response *ADIGenerateLoginCodeResponse
	if response, err = crypt.Client.ADIGenerateLoginCode(ctx, &ADIGenerateLoginCodeRequest{DSID: dsid, ADI: adi}); err != nil {
		return 0, err
	}
	if response.Code != 0 {
		return 0, fmt.Errorf("ADIGenerateLoginCode error: %d", response.Code)
	}
	return response.LoginCode, nil
}

func (crypt *CryptorGRPC) AbsintheHello(ctx context.Context, mode int) ([]byte, error) {
	ctx, cancel := crypt.metaContext(ctx)
	defer cancel()
	var err error
	var response *AbsintheHelloResponse
	if response, err = crypt.Client.AbsintheHello(ctx, &AbsintheHelloRequest{Mode: int32(mode)}); err != nil {
		return nil, err
	}
	return response.HelloMessage, nil
}

func (crypt *CryptorGRPC) AbsintheAddOption(ctx context.Context, BIKKey []byte, BAACert []byte, intermediateRootCert []byte) error {
	ctx, cancel := crypt.metaContext(ctx)
	defer cancel()
	var err error
	if _, err = crypt.Client.AbsintheAddOption(ctx, &AbsintheAddOptionRequest{BikKey: BIKKey, BaaCert: BAACert, IntermediateRootCert: intermediateRootCert}); err != nil {
		return err
	}
	return nil
}

// AbsintheActivateSession 设置 session 返回（absinthe-response）
func (crypt *CryptorGRPC) AbsintheActivateSession(ctx context.Context, validationData []byte, serverKey []byte) error {
	ctx, cancel := crypt.metaContext(ctx)
	defer cancel()
	var err error
	if _, err = crypt.Client.AbsintheActivateSession(ctx, &AbsintheActivateSessionRequest{ValidationData: validationData, ServerKey: serverKey}); err != nil {
		return err
	}
	return nil
}

// AbsintheSignData signData 返回 signature outServKey
func (crypt *CryptorGRPC) AbsintheSignData(ctx context.Context, dataToSign []byte) ([]byte, []byte, error) {
	ctx, cancel := crypt.metaContext(ctx)
	defer cancel()
	var err error
	var response *AbsintheSignDataResponse
	if response, err = crypt.Client.AbsintheSignData(ctx, &AbsintheSignDataRequest{SignData: dataToSign}); err != nil {
		return nil, nil, err
	}
	return response.Signature, response.OutServKey, nil
}

// IdentitySession 注册 SessionInfoRequest
func (crypt *CryptorGRPC) IdentitySession(ctx context.Context, cert []byte) ([]byte, error) {
	ctx, cancel := crypt.metaContext(ctx)
	defer cancel()
	var err error
	var response *IdentitySessionResponse
	if response, err = crypt.Client.IdentitySession(ctx, &IdentitySessionRequest{Cert: cert}); err != nil {
		return nil, err
	}
	return response.Request, nil
}

// IdentityValidation 取得VD
func (crypt *CryptorGRPC) IdentityValidation(ctx context.Context, sessionInfo []byte, signData []byte) ([]byte, error) {
	ctx, cancel := crypt.metaContext(ctx)
	defer cancel()
	var err error
	var response *IdentityValidationResponse
	if response, err = crypt.Client.IdentityValidation(ctx, &IdentityValidationRequest{Response: sessionInfo, SignData: signData}); err != nil {
		return nil, err
	}
	return response.ValidationData, nil
}

func (crypt *CryptorGRPC) SAPExchange(ctx context.Context, version int, data []byte) ([]byte, error) {
	ctx, cancel := crypt.metaContext(ctx)
	defer cancel()
	var err error
	var response *SAPExchangeResponse
	if response, err = crypt.Client.SAPExchange(ctx, &SAPExchangeRequest{Version: int32(version), Data: data}); err != nil {
		return nil, err
	}
	return response.ExchangeData, nil
}

func (crypt *CryptorGRPC) SAPSignPrime(ctx context.Context, signData []byte) ([]byte, error) {
	ctx, cancel := crypt.metaContext(ctx)
	defer cancel()
	var err error
	var response *SAPSignPrimeResponse
	if response, err = crypt.Client.SAPSignPrime(ctx, &SAPSignPrimeRequest{SignData: signData}); err != nil {
		return nil, err
	}
	return response.Signature, nil
}

func (crypt *CryptorGRPC) SAPVerifyPrime(ctx context.Context, data []byte) error {
	ctx, cancel := crypt.metaContext(ctx)
	defer cancel()
	var err error
	if _, err = crypt.Client.SAPVerifyPrime(ctx, &SAPVerifyPrimeRequest{Data: data}); err != nil {
		return err
	}
	return nil
}

func (crypt *CryptorGRPC) SAPSign(ctx context.Context, signData []byte) ([]byte, error) {
	ctx, cancel := crypt.metaContext(ctx)
	defer cancel()
	var err error
	var response *SAPSignResponse
	if response, err = crypt.Client.SAPSign(ctx, &SAPSignRequest{SignData: signData}); err != nil {
		return nil, err
	}
	return response.Signature, nil
}

func (crypt *CryptorGRPC) SAPVerify(ctx context.Context, data []byte, signature []byte) error {
	ctx, cancel := crypt.metaContext(ctx)
	defer cancel()
	var err error
	if _, err = crypt.Client.SAPVerify(ctx, &SAPVerifyRequest{Data: data, Signature: signature}); err != nil {
		return err
	}
	return nil
}
