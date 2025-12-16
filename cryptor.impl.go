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

func (crypt *CryptorGRPC) metaContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	pairs := []string{"client_id", crypt.ClientId}
	if crypt.APIKey != "" {
		pairs = append(pairs, "x-api-key", crypt.APIKey)
	}
	md := metadata.Pairs(pairs...)
	metactx := metadata.NewOutgoingContext(ctx, md)
	return metactx, cancel
}

// Initialize init crypto with device[see device struct]
func (crypt *CryptorGRPC) Initialize(type_ InitializeType, device *Device) error {
	ctx, cancel := crypt.metaContext()
	defer cancel()
	if response, err := crypt.Client.Initialize(ctx, &InitializeRequest{Type: type_, Device: device}); err != nil {
		return err
	} else {
		device.OStype = response.Device.OStype
		device.SerialNumber = response.Device.SerialNumber
		// macOS
		device.Model = response.Device.Model
		device.OSRevision = response.Device.OSRevision
		device.OSVersion = response.Device.OSVersion
		device.BoardId = response.Device.BoardId
		device.DiskId = response.Device.DiskId
		device.HardWareUUID = response.Device.HardWareUUID
		device.MacAddress = response.Device.MacAddress
		device.ROM = response.Device.ROM
		device.MLB = response.Device.MLB
		device.KGq3489Ugfi = response.Device.KGq3489Ugfi
		device.KFyp98Tpgj = response.Device.KFyp98Tpgj
		device.KkbjfrfpoJU = response.Device.KkbjfrfpoJU
		device.KoycqAZloTNDm = response.Device.KoycqAZloTNDm
		device.KabKPld1EcMni = response.Device.KabKPld1EcMni
		// iOS
		device.ProductType = response.Device.ProductType
		device.IMEI = response.Device.IMEI
		device.UniqueChipID = response.Device.UniqueChipID
		device.UniqueDeviceID = response.Device.UniqueDeviceID
		device.WifiAddress = response.Device.WifiAddress
		device.BluetoothAddress = response.Device.BluetoothAddress
		device.SecureElementSN = response.Device.SecureElementSN
		// Global
		device.BuildVersion = response.Device.BuildVersion
		device.ProductVersion = response.Device.ProductVersion
		device.FairplayKeyData = response.Device.FairplayKeyData
		device.ADI = response.Device.ADI
		device.APTicket = response.Device.APTicket
		device.SUInfo = response.Device.SUInfo
	}
	return nil
}

// InitDevice finalize crypto
func (crypt *CryptorGRPC) Finalize() error {
	ctx, cancel := crypt.metaContext()
	defer cancel()
	if _, err := crypt.Client.Finalize(ctx, &FinalizeRequest{}); err != nil {
		return err
	}
	return nil
}

// ActivationDRMHandshake generate [0]CollectionBlob and [1]handshakeRequestMessage
func (crypt *CryptorGRPC) ActivationDRMHandshake() ([]byte, []byte, error) {
	ctx, cancel := crypt.metaContext()
	defer cancel()
	var err error
	var response *ActivationDRMHandshakeResponse
	if response, err = crypt.Client.ActivationDRMHandshake(ctx, &ActivationDRMHandshakeRequest{}); err != nil {
		return nil, nil, err
	}
	return response.CollectionBlob, response.HandshakeRequestMessage, nil
}

// ActivationDRMProcess process handshake response and return [0]UIK [1]RK
func (crypt *CryptorGRPC) ActivationDRMProcess(suinfo, handshakeResponseMessage, serverKP []byte) ([]byte, []byte, error) {
	ctx, cancel := crypt.metaContext()
	defer cancel()
	var err error
	var response *ActivationDRMProcessResponse
	if response, err = crypt.Client.ActivationDRMProcess(ctx, &ActivationDRMProcessRequest{SUInfo: suinfo, HandshakeResponseMessage: handshakeResponseMessage, ServerKP: serverKP}); err != nil {
		return nil, nil, err
	}
	return response.UIK, response.RK, nil
}

// ActivationDRMSignature sign activation xml and return [0]fairpalySign, [1]fairplayCert, [2]RKSignature, [3]signActRequest, [4]serverKP
func (crypt *CryptorGRPC) ActivationDRMSignature(activationXML []byte) ([]byte, []byte, []byte, []byte, []byte, error) {
	ctx, cancel := crypt.metaContext()
	defer cancel()
	var err error
	var response *ActivationDRMSignatureResponse
	if response, err = crypt.Client.ActivationDRMSignature(ctx, &ActivationDRMSignatureRequest{ActivationInfoXML: activationXML}); err != nil {
		return nil, nil, nil, nil, nil, err
	}
	return response.FairPlaySignature, response.FairPlayCertChain, response.RKSignature, response.SignActRequest, response.ServerKP, nil
}

// ActivationDeprecated return [0]fairpalySign, [1]fairplayCert
func (crypt *CryptorGRPC) ActivationDeprecated(activationXML []byte) ([]byte, []byte, error) {
	ctx, cancel := crypt.metaContext()
	defer cancel()
	var err error
	var response *ActivationDeprecatedResponse
	if response, err = crypt.Client.ActivationDeprecated(ctx, &ActivationDeprecatedRequest{ActivationInfoXML: activationXML}); err != nil {
		return nil, nil, err
	}
	return response.Sign, response.Cert, nil
}

// ActivationRecord set activation response return [0]subCAKey, [1]attestationKey, [2]UIK, [3]RK, [4]psc.sui
func (crypt *CryptorGRPC) ActivationRecord(unbrick bool, AccountTokenCertificate, DeviceCertificate, RegulatoryInfo, FairPlayKeyData, AccountToken, AccountTokenSignature, UniqueDeviceCertificate []byte) ([]byte, []byte, []byte, []byte, []byte, error) {
	ctx, cancel := crypt.metaContext()
	defer cancel()
	var err error
	var response *ActivationRecordResponse
	if response, err = crypt.Client.ActivationRecord(ctx, &ActivationRecordRequest{
		Unbrick:                 unbrick,
		AccountTokenCertificate: AccountTokenCertificate,
		DeviceCertificate:       DeviceCertificate,
		RegulatoryInfo:          RegulatoryInfo,
		FairPlayKeyData:         FairPlayKeyData,
		AccountToken:            AccountToken,
		AccountTokenSignature:   AccountTokenSignature,
		UniqueDeviceCertificate: UniqueDeviceCertificate,
	}); err != nil {
		return nil, nil, nil, nil, nil, err
	}
	return response.SubCAKey, response.AttestationKey, response.UIK, response.RK, response.PSCSui, nil
}

// ADIStartProvisioning 返回 CPIM Session Error
func (crypt *CryptorGRPC) ADIStartProvisioning(dsid int64, spim []byte) ([]byte, uint64, error) {
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
func (crypt *CryptorGRPC) ADIEndProvisioning(session uint64, dsid int64, rinfo int64, ptm []byte, tk []byte, adi []byte) ([]byte, []byte, []byte, error) {
	ctx, cancel := crypt.metaContext()
	defer cancel()
	var err error
	var response *ADIEndProvisioningResponse
	if response, err = crypt.Client.ADIEndProvisioning(ctx, &ADIEndProvisioningRequest{Session: session, DSID: dsid, RINFO: rinfo, PTM: ptm, TK: tk, ADI: adi}); err != nil {
		return nil, nil, nil, err
	}
	return response.MID, response.OTP, response.ADI, nil
}

// ADIGenerateLoginCode 返回 loginCode
func (crypt *CryptorGRPC) ADIGenerateLoginCode(dsid int64, adi []byte) (uint32, error) {
	ctx, cancel := crypt.metaContext()
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

func (crypt *CryptorGRPC) AbsintheHello(mode int) ([]byte, error) {
	ctx, cancel := crypt.metaContext()
	defer cancel()
	var err error
	var response *AbsintheHelloResponse
	if response, err = crypt.Client.AbsintheHello(ctx, &AbsintheHelloRequest{Mode: int32(mode)}); err != nil {
		return nil, err
	}
	return response.HelloMessage, nil
}

func (crypt *CryptorGRPC) AbsintheAddOption(BIKKey []byte, BAACert []byte, intermediateRootCert []byte) error {
	ctx, cancel := crypt.metaContext()
	defer cancel()
	var err error
	if _, err = crypt.Client.AbsintheAddOption(ctx, &AbsintheAddOptionRequest{BIKKey: BIKKey, BAACert: BAACert, IntermediateRootCert: intermediateRootCert}); err != nil {
		return err
	}
	return nil
}

// AbsintheAtivateSession 设置 session 返回（absinthe-response）
func (crypt *CryptorGRPC) AbsintheAtivateSession(validationData []byte, serverKey []byte) error {
	ctx, cancel := crypt.metaContext()
	defer cancel()
	var err error
	if _, err = crypt.Client.AbsintheAtivateSession(ctx, &AbsintheAtivateSessionRequest{ValidationData: validationData, ServerKey: serverKey}); err != nil {
		return err
	}
	return nil
}

// AbsintheSignData signData 返回 signature outServKey
func (crypt *CryptorGRPC) AbsintheSignData(dataToSign []byte) ([]byte, []byte, error) {
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
func (crypt *CryptorGRPC) IndentitySession(cert []byte) ([]byte, error) {
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
func (crypt *CryptorGRPC) IndentityValidation(sessionInfo []byte, signData []byte) ([]byte, error) {
	ctx, cancel := crypt.metaContext()
	defer cancel()
	var err error
	var response *IndentityValidationResponse
	if response, err = crypt.Client.IndentityValidation(ctx, &IndentityValidationRequest{Response: sessionInfo, SignData: signData}); err != nil {
		return nil, err
	}
	return response.VlidationData, nil
}

func (crypt *CryptorGRPC) SAPExchange(data []byte) ([]byte, error) {
	ctx, cancel := crypt.metaContext()
	defer cancel()
	var err error
	var response *SAPExchangeResponse
	if response, err = crypt.Client.SAPExchange(ctx, &SAPExchangeRequest{Data: data}); err != nil {
		return nil, err
	}
	return response.ExchangeData, nil
}

func (crypt *CryptorGRPC) SAPSignPrime(signData []byte) ([]byte, error) {
	ctx, cancel := crypt.metaContext()
	defer cancel()
	var err error
	var response *SAPSignPrimeResponse
	if response, err = crypt.Client.SAPSignPrime(ctx, &SAPSignPrimeRequest{SignData: signData}); err != nil {
		return nil, err
	}
	return response.Signature, nil
}

func (crypt *CryptorGRPC) SAPVerifyPrime(data []byte) error {
	ctx, cancel := crypt.metaContext()
	defer cancel()
	var err error
	if _, err = crypt.Client.SAPVerifyPrime(ctx, &SAPVerifyPrimeRequest{Data: data}); err != nil {
		return err
	}
	return nil
}

func (crypt *CryptorGRPC) SAPSign(signData []byte) ([]byte, error) {
	ctx, cancel := crypt.metaContext()
	defer cancel()
	var err error
	var response *SAPSignResponse
	if response, err = crypt.Client.SAPSign(ctx, &SAPSignRequest{SignData: signData}); err != nil {
		return nil, err
	}
	return response.Signature, nil
}

func (crypt *CryptorGRPC) SAPVerify(data []byte, signature []byte) error {
	ctx, cancel := crypt.metaContext()
	defer cancel()
	var err error
	if _, err = crypt.Client.SAPVerify(ctx, &SAPVerifyRequest{Data: data, Signature: signature}); err != nil {
		return err
	}
	return nil
}
