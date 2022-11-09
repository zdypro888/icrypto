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
	NewCryptor = NewCryptorGRPC
	return nil
}

func NewCryptorGRPC() Cryptor {
	crypt := &CryptorGrpc{
		ClientId: uuid.NewV4().String(),
		Client:   cryptoClient,
	}
	return crypt
}

type CryptorGrpc struct {
	ClientId string
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
	if _, err = crypt.Client.Initialize(ctx, &InitializeRequest{DevicePlist: devicePlist}); err != nil {
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

// ActivationDRMHandshake generate [0]CollectionBlob and [1]handshakeRequestMessage
func (crypt *CryptorGrpc) ActivationDRMHandshake() ([]byte, []byte, error) {
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
func (crypt *CryptorGrpc) ActivationDRMProcess(suinfo, handshakeResponseMessage, serverKP []byte) ([]byte, []byte, error) {
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
func (crypt *CryptorGrpc) ActivationDRMSignature(activationXML []byte) ([]byte, []byte, []byte, []byte, []byte, error) {
	ctx, cancel := crypt.metaContext()
	defer cancel()
	var err error
	var response *ActivationDRMSignatureRespone
	if response, err = crypt.Client.ActivationDRMSignature(ctx, &ActivationDRMSignatureRequest{ActivationInfoXML: activationXML}); err != nil {
		return nil, nil, nil, nil, nil, err
	}
	return response.FairPlaySignature, response.FairPlayCertChain, response.RKSignature, response.SignActRequest, response.ServerKP, nil
}

// ActivationDeprecated return [0]fairpalySign, [1]fairplayCert
func (crypt *CryptorGrpc) ActivationDeprecated(activationXML []byte) ([]byte, []byte, error) {
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
func (crypt *CryptorGrpc) ActivationRecord(unbrick bool, AccountTokenCertificate, DeviceCertificate, RegulatoryInfo, FairPlayKeyData, AccountToken, AccountTokenSignature, UniqueDeviceCertificate []byte) ([]byte, []byte, []byte, []byte, []byte, error) {
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
