package icrypto

import (
	context "context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/zdypro888/go-plist"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// grpcState is one consistent (conn, client, apiKey) triple. It is published
// atomically so NewCryptorGRPC can never pair the client of one Init call with
// the API key of another.
type grpcState struct {
	conn   *grpc.ClientConn
	client CryptServiceClient
	apiKey string // 用于 iclouder 代理认证
}

var (
	cryptoState atomic.Pointer[grpcState]

	cryptoMu sync.Mutex
	// cryptoConns holds every connection opened by Init*, including ones that a
	// later Init superseded: cryptors created earlier keep using them, so they
	// are only released by CloseGRPC.
	cryptoConns []*grpc.ClientConn
)

// InitGRPC 初始化 gRPC 连接（直连 cryptor 服务，无需 apiKey）。
// 警告：使用明文传输，仅适用于回环地址或可信子进程。
func InitGRPC(address string) error {
	return InitGRPCWithAPIKey(address, "")
}

// InitGRPCWithAPIKey 初始化 gRPC 连接（连接 iclouder 代理时需要 apiKey）。
// 警告：使用明文传输，仅适用于回环地址或可信子进程。
func InitGRPCWithAPIKey(address, apiKey string) error {
	return initGRPC(address, apiKey, insecure.NewCredentials())
}

// InitGRPCWithCreds 初始化 gRPC 连接，支持自定义传输凭证。
// 若 creds 为 nil，则退回使用明文传输（insecure）。
func InitGRPCWithCreds(address, apiKey string, creds credentials.TransportCredentials) error {
	if creds == nil {
		creds = insecure.NewCredentials()
	}
	return initGRPC(address, apiKey, creds)
}

func initGRPC(address, apiKey string, creds credentials.TransportCredentials) error {
	conn, err := grpc.NewClient(address,
		grpc.WithTransportCredentials(creds),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(64*1024*1024),
			grpc.MaxCallSendMsgSize(64*1024*1024),
		),
	)
	if err != nil {
		return err
	}
	cryptoMu.Lock()
	defer cryptoMu.Unlock()
	cryptoConns = append(cryptoConns, conn)
	cryptoState.Store(&grpcState{conn: conn, client: NewCryptServiceClient(conn), apiKey: apiKey})
	NewCryptor = NewCryptorGRPC
	return nil
}

// CloseGRPC closes every connection opened by InitGRPC*. Cryptors created
// before the call stop working; call it only on shutdown.
func CloseGRPC() error {
	cryptoMu.Lock()
	defer cryptoMu.Unlock()
	cryptoState.Store(nil)
	var errs []error
	for _, conn := range cryptoConns {
		if err := conn.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	cryptoConns = nil
	return errors.Join(errs...)
}

func NewCryptorGRPC() Cryptor {
	crypt := &CryptorGRPC{ClientId: uuid.NewString()}
	if state := cryptoState.Load(); state != nil {
		crypt.APIKey = state.apiKey
		crypt.Client = state.client
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
	// Previously NewOutgoingContext replaced all caller metadata, dropping
	// tracing/routing/authentication fields. Copy it, then replace only the
	// identity fields owned by this cryptor so duplicate IDs cannot survive.
	md, _ := metadata.FromOutgoingContext(ctx)
	md = md.Copy()
	md.Set("client_id", crypt.ClientId)
	if crypt.APIKey != "" {
		md.Set("x-api-key", crypt.APIKey)
	}
	metactx := metadata.NewOutgoingContext(ctx, md)
	return metactx, cancel
}

// Initialize 创建远端计算会话，并将后端返回的设备状态写入传入对象。
func (crypt *CryptorGRPC) Initialize(ctx context.Context, options InitializeOptions, device IPlistObject) error {
	if err := options.Validate(); err != nil {
		return err
	}
	if device == nil {
		return fmt.Errorf("initialize: nil device")
	}
	ctx, cancel := crypt.metaContext(ctx)
	defer cancel()
	devicePlist, err := plist.Marshal(device, plist.BinaryFormat)
	if err != nil {
		return err
	}
	request := &InitializeRequest{IosDrm: options.IOSDRM, MacosRuntime: options.MacOSRuntime, Device: devicePlist}
	if response, err := crypt.Client.Initialize(ctx, request); err != nil {
		return err
	} else if err := device.Unmarshal(response.Device); err != nil {
		return err
	} else {
		return nil
	}
}

// SyncDevice synchronizes state acquired after Initialize (for example an AP
// ticket requested with hardware identifiers returned by Initialize). It is a
// state merge on the server; it must not rebuild the remote cryptor.
func (crypt *CryptorGRPC) SyncDevice(ctx context.Context, device IPlistObject) error {
	if device == nil {
		return fmt.Errorf("sync device: nil device")
	}
	devicePlist, err := plist.Marshal(device, plist.BinaryFormat)
	if err != nil {
		return fmt.Errorf("sync device: marshal device: %w", err)
	}
	ctx, cancel := crypt.metaContext(ctx)
	defer cancel()
	if _, err := crypt.Client.SyncDevice(ctx, &SyncDeviceRequest{Device: devicePlist}); err != nil {
		return fmt.Errorf("sync device: %w", err)
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

// ActivationDRMHandshake 开始 DRM 激活握手，返回采集数据和握手请求。
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

// ActivationDRMProcess 处理 DRM 握手响应，返回 UIK 与 RK。
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

// ActivationDRMSignature 签署激活 XML，返回签名、证书、RK 签名、激活请求和服务器密钥。
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

// ActivationDeprecated 使用当前会话计算传统激活签名及证书；独立签名优先使用 ActivationSign。
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

// ActivationRecord 向 DRM 会话提供激活记录并导出 psc.sui。
func (crypt *CryptorGRPC) ActivationRecord(ctx context.Context, unbrick bool, AccountTokenCertificate, DeviceCertificate, RegulatoryInfo, FairPlayKeyData, AccountToken, AccountTokenSignature, UniqueDeviceCertificate []byte) ([]byte, error) {
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
		return nil, err
	}
	return response.PscSui, nil
}

// ADIStartProvisioning 开始 ADI 配置，返回 CPIM 和当前实例的会话句柄。
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

// ADIEndProvisioning 完成配置或复用 ADI，返回 MID、OTP 和更新后的 ADI 状态。
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

// ADIGenerateLoginCode 从 ADI 配置生成登录码。
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

// AbsintheActivateSession 使用服务器响应推进当前 Absinthe 会话。
func (crypt *CryptorGRPC) AbsintheActivateSession(ctx context.Context, validationData []byte, serverKey []byte) error {
	ctx, cancel := crypt.metaContext(ctx)
	defer cancel()
	var err error
	if _, err = crypt.Client.AbsintheActivateSession(ctx, &AbsintheActivateSessionRequest{ValidationData: validationData, ServerKey: serverKey}); err != nil {
		return err
	}
	return nil
}

// AbsintheSignData 使用 Absinthe 会话签名，返回签名和输出服务器密钥。
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

// IdentitySession 生成 Validation 握手请求。
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

// IdentityValidation 处理 Validation 握手响应并生成 validation-data。
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

// ActivationSign 将签名实现限制在单次 RPC，不能把 Legacy 当作全局初始化模式。
func (crypt *CryptorGRPC) ActivationSign(ctx context.Context, profile ActivationSigningProfile, macOSRuntime MacOSRuntime, device IPlistObject, activationXML []byte) ([]byte, []byte, error) {
	if err := ValidateMacOSRuntime(macOSRuntime); err != nil {
		return nil, nil, err
	}
	if device == nil {
		return nil, nil, fmt.Errorf("activation device is nil")
	}
	ctx, cancel := crypt.metaContext(ctx)
	defer cancel()
	data, err := device.Marshal()
	if err != nil {
		return nil, nil, err
	}
	response, err := crypt.Client.ActivationSign(ctx, &ActivationSignRequest{Profile: profile, MacosRuntime: macOSRuntime, Device: data, ActivationInfoXml: activationXML})
	if err != nil {
		return nil, nil, err
	}
	return response.Sign, response.Cert, nil
}
