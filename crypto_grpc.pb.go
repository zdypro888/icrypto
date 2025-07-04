// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.5.1
// - protoc             v5.29.3
// source: crypto.proto

package icrypto

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.64.0 or later.
const _ = grpc.SupportPackageIsVersion9

const (
	CryptService_Initialize_FullMethodName             = "/icrypto.CryptService/Initialize"
	CryptService_Finalize_FullMethodName               = "/icrypto.CryptService/Finalize"
	CryptService_ActivationDRMHandshake_FullMethodName = "/icrypto.CryptService/ActivationDRMHandshake"
	CryptService_ActivationDRMProcess_FullMethodName   = "/icrypto.CryptService/ActivationDRMProcess"
	CryptService_ActivationDRMSignature_FullMethodName = "/icrypto.CryptService/ActivationDRMSignature"
	CryptService_ActivationDeprecated_FullMethodName   = "/icrypto.CryptService/ActivationDeprecated"
	CryptService_ActivationRecord_FullMethodName       = "/icrypto.CryptService/ActivationRecord"
	CryptService_ADIStartProvisioning_FullMethodName   = "/icrypto.CryptService/ADIStartProvisioning"
	CryptService_ADIEndProvisioning_FullMethodName     = "/icrypto.CryptService/ADIEndProvisioning"
	CryptService_ADIGenerateLoginCode_FullMethodName   = "/icrypto.CryptService/ADIGenerateLoginCode"
	CryptService_AbsintheHello_FullMethodName          = "/icrypto.CryptService/AbsintheHello"
	CryptService_AbsintheAddOption_FullMethodName      = "/icrypto.CryptService/AbsintheAddOption"
	CryptService_AbsintheAtivateSession_FullMethodName = "/icrypto.CryptService/AbsintheAtivateSession"
	CryptService_AbsintheSignData_FullMethodName       = "/icrypto.CryptService/AbsintheSignData"
	CryptService_IndentitySession_FullMethodName       = "/icrypto.CryptService/IndentitySession"
	CryptService_IndentityValidation_FullMethodName    = "/icrypto.CryptService/IndentityValidation"
	CryptService_SAPExchange_FullMethodName            = "/icrypto.CryptService/SAPExchange"
	CryptService_SAPSignPrime_FullMethodName           = "/icrypto.CryptService/SAPSignPrime"
	CryptService_SAPVerifyPrime_FullMethodName         = "/icrypto.CryptService/SAPVerifyPrime"
	CryptService_SAPSign_FullMethodName                = "/icrypto.CryptService/SAPSign"
	CryptService_SAPVerify_FullMethodName              = "/icrypto.CryptService/SAPVerify"
)

// CryptServiceClient is the client API for CryptService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type CryptServiceClient interface {
	Initialize(ctx context.Context, in *InitializeRequest, opts ...grpc.CallOption) (*InitializeResponse, error)
	Finalize(ctx context.Context, in *FinalizeRequest, opts ...grpc.CallOption) (*FinalizeResponse, error)
	ActivationDRMHandshake(ctx context.Context, in *ActivationDRMHandshakeRequest, opts ...grpc.CallOption) (*ActivationDRMHandshakeResponse, error)
	ActivationDRMProcess(ctx context.Context, in *ActivationDRMProcessRequest, opts ...grpc.CallOption) (*ActivationDRMProcessResponse, error)
	ActivationDRMSignature(ctx context.Context, in *ActivationDRMSignatureRequest, opts ...grpc.CallOption) (*ActivationDRMSignatureResponse, error)
	ActivationDeprecated(ctx context.Context, in *ActivationDeprecatedRequest, opts ...grpc.CallOption) (*ActivationDeprecatedResponse, error)
	ActivationRecord(ctx context.Context, in *ActivationRecordRequest, opts ...grpc.CallOption) (*ActivationRecordResponse, error)
	ADIStartProvisioning(ctx context.Context, in *ADIStartProvisioningRequest, opts ...grpc.CallOption) (*ADIStartProvisioningResponse, error)
	ADIEndProvisioning(ctx context.Context, in *ADIEndProvisioningRequest, opts ...grpc.CallOption) (*ADIEndProvisioningResponse, error)
	ADIGenerateLoginCode(ctx context.Context, in *ADIGenerateLoginCodeRequest, opts ...grpc.CallOption) (*ADIGenerateLoginCodeResponse, error)
	AbsintheHello(ctx context.Context, in *AbsintheHelloRequest, opts ...grpc.CallOption) (*AbsintheHelloResponse, error)
	AbsintheAddOption(ctx context.Context, in *AbsintheAddOptionRequest, opts ...grpc.CallOption) (*AbsintheAddOptionResponse, error)
	AbsintheAtivateSession(ctx context.Context, in *AbsintheAtivateSessionRequest, opts ...grpc.CallOption) (*AbsintheAtivateSessionResponse, error)
	AbsintheSignData(ctx context.Context, in *AbsintheSignDataRequest, opts ...grpc.CallOption) (*AbsintheSignDataResponse, error)
	IndentitySession(ctx context.Context, in *IndentitySessionRequest, opts ...grpc.CallOption) (*IndentitySessionResponse, error)
	IndentityValidation(ctx context.Context, in *IndentityValidationRequest, opts ...grpc.CallOption) (*IndentityValidationResponse, error)
	SAPExchange(ctx context.Context, in *SAPExchangeRequest, opts ...grpc.CallOption) (*SAPExchangeResponse, error)
	SAPSignPrime(ctx context.Context, in *SAPSignPrimeRequest, opts ...grpc.CallOption) (*SAPSignPrimeResponse, error)
	SAPVerifyPrime(ctx context.Context, in *SAPVerifyPrimeRequest, opts ...grpc.CallOption) (*SAPVerifyPrimeResponse, error)
	SAPSign(ctx context.Context, in *SAPSignRequest, opts ...grpc.CallOption) (*SAPSignResponse, error)
	SAPVerify(ctx context.Context, in *SAPVerifyRequest, opts ...grpc.CallOption) (*SAPVerifyResponse, error)
}

type cryptServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewCryptServiceClient(cc grpc.ClientConnInterface) CryptServiceClient {
	return &cryptServiceClient{cc}
}

func (c *cryptServiceClient) Initialize(ctx context.Context, in *InitializeRequest, opts ...grpc.CallOption) (*InitializeResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(InitializeResponse)
	err := c.cc.Invoke(ctx, CryptService_Initialize_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *cryptServiceClient) Finalize(ctx context.Context, in *FinalizeRequest, opts ...grpc.CallOption) (*FinalizeResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(FinalizeResponse)
	err := c.cc.Invoke(ctx, CryptService_Finalize_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *cryptServiceClient) ActivationDRMHandshake(ctx context.Context, in *ActivationDRMHandshakeRequest, opts ...grpc.CallOption) (*ActivationDRMHandshakeResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(ActivationDRMHandshakeResponse)
	err := c.cc.Invoke(ctx, CryptService_ActivationDRMHandshake_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *cryptServiceClient) ActivationDRMProcess(ctx context.Context, in *ActivationDRMProcessRequest, opts ...grpc.CallOption) (*ActivationDRMProcessResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(ActivationDRMProcessResponse)
	err := c.cc.Invoke(ctx, CryptService_ActivationDRMProcess_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *cryptServiceClient) ActivationDRMSignature(ctx context.Context, in *ActivationDRMSignatureRequest, opts ...grpc.CallOption) (*ActivationDRMSignatureResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(ActivationDRMSignatureResponse)
	err := c.cc.Invoke(ctx, CryptService_ActivationDRMSignature_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *cryptServiceClient) ActivationDeprecated(ctx context.Context, in *ActivationDeprecatedRequest, opts ...grpc.CallOption) (*ActivationDeprecatedResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(ActivationDeprecatedResponse)
	err := c.cc.Invoke(ctx, CryptService_ActivationDeprecated_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *cryptServiceClient) ActivationRecord(ctx context.Context, in *ActivationRecordRequest, opts ...grpc.CallOption) (*ActivationRecordResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(ActivationRecordResponse)
	err := c.cc.Invoke(ctx, CryptService_ActivationRecord_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *cryptServiceClient) ADIStartProvisioning(ctx context.Context, in *ADIStartProvisioningRequest, opts ...grpc.CallOption) (*ADIStartProvisioningResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(ADIStartProvisioningResponse)
	err := c.cc.Invoke(ctx, CryptService_ADIStartProvisioning_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *cryptServiceClient) ADIEndProvisioning(ctx context.Context, in *ADIEndProvisioningRequest, opts ...grpc.CallOption) (*ADIEndProvisioningResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(ADIEndProvisioningResponse)
	err := c.cc.Invoke(ctx, CryptService_ADIEndProvisioning_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *cryptServiceClient) ADIGenerateLoginCode(ctx context.Context, in *ADIGenerateLoginCodeRequest, opts ...grpc.CallOption) (*ADIGenerateLoginCodeResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(ADIGenerateLoginCodeResponse)
	err := c.cc.Invoke(ctx, CryptService_ADIGenerateLoginCode_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *cryptServiceClient) AbsintheHello(ctx context.Context, in *AbsintheHelloRequest, opts ...grpc.CallOption) (*AbsintheHelloResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(AbsintheHelloResponse)
	err := c.cc.Invoke(ctx, CryptService_AbsintheHello_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *cryptServiceClient) AbsintheAddOption(ctx context.Context, in *AbsintheAddOptionRequest, opts ...grpc.CallOption) (*AbsintheAddOptionResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(AbsintheAddOptionResponse)
	err := c.cc.Invoke(ctx, CryptService_AbsintheAddOption_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *cryptServiceClient) AbsintheAtivateSession(ctx context.Context, in *AbsintheAtivateSessionRequest, opts ...grpc.CallOption) (*AbsintheAtivateSessionResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(AbsintheAtivateSessionResponse)
	err := c.cc.Invoke(ctx, CryptService_AbsintheAtivateSession_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *cryptServiceClient) AbsintheSignData(ctx context.Context, in *AbsintheSignDataRequest, opts ...grpc.CallOption) (*AbsintheSignDataResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(AbsintheSignDataResponse)
	err := c.cc.Invoke(ctx, CryptService_AbsintheSignData_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *cryptServiceClient) IndentitySession(ctx context.Context, in *IndentitySessionRequest, opts ...grpc.CallOption) (*IndentitySessionResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(IndentitySessionResponse)
	err := c.cc.Invoke(ctx, CryptService_IndentitySession_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *cryptServiceClient) IndentityValidation(ctx context.Context, in *IndentityValidationRequest, opts ...grpc.CallOption) (*IndentityValidationResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(IndentityValidationResponse)
	err := c.cc.Invoke(ctx, CryptService_IndentityValidation_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *cryptServiceClient) SAPExchange(ctx context.Context, in *SAPExchangeRequest, opts ...grpc.CallOption) (*SAPExchangeResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(SAPExchangeResponse)
	err := c.cc.Invoke(ctx, CryptService_SAPExchange_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *cryptServiceClient) SAPSignPrime(ctx context.Context, in *SAPSignPrimeRequest, opts ...grpc.CallOption) (*SAPSignPrimeResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(SAPSignPrimeResponse)
	err := c.cc.Invoke(ctx, CryptService_SAPSignPrime_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *cryptServiceClient) SAPVerifyPrime(ctx context.Context, in *SAPVerifyPrimeRequest, opts ...grpc.CallOption) (*SAPVerifyPrimeResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(SAPVerifyPrimeResponse)
	err := c.cc.Invoke(ctx, CryptService_SAPVerifyPrime_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *cryptServiceClient) SAPSign(ctx context.Context, in *SAPSignRequest, opts ...grpc.CallOption) (*SAPSignResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(SAPSignResponse)
	err := c.cc.Invoke(ctx, CryptService_SAPSign_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *cryptServiceClient) SAPVerify(ctx context.Context, in *SAPVerifyRequest, opts ...grpc.CallOption) (*SAPVerifyResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(SAPVerifyResponse)
	err := c.cc.Invoke(ctx, CryptService_SAPVerify_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CryptServiceServer is the server API for CryptService service.
// All implementations must embed UnimplementedCryptServiceServer
// for forward compatibility.
type CryptServiceServer interface {
	Initialize(context.Context, *InitializeRequest) (*InitializeResponse, error)
	Finalize(context.Context, *FinalizeRequest) (*FinalizeResponse, error)
	ActivationDRMHandshake(context.Context, *ActivationDRMHandshakeRequest) (*ActivationDRMHandshakeResponse, error)
	ActivationDRMProcess(context.Context, *ActivationDRMProcessRequest) (*ActivationDRMProcessResponse, error)
	ActivationDRMSignature(context.Context, *ActivationDRMSignatureRequest) (*ActivationDRMSignatureResponse, error)
	ActivationDeprecated(context.Context, *ActivationDeprecatedRequest) (*ActivationDeprecatedResponse, error)
	ActivationRecord(context.Context, *ActivationRecordRequest) (*ActivationRecordResponse, error)
	ADIStartProvisioning(context.Context, *ADIStartProvisioningRequest) (*ADIStartProvisioningResponse, error)
	ADIEndProvisioning(context.Context, *ADIEndProvisioningRequest) (*ADIEndProvisioningResponse, error)
	ADIGenerateLoginCode(context.Context, *ADIGenerateLoginCodeRequest) (*ADIGenerateLoginCodeResponse, error)
	AbsintheHello(context.Context, *AbsintheHelloRequest) (*AbsintheHelloResponse, error)
	AbsintheAddOption(context.Context, *AbsintheAddOptionRequest) (*AbsintheAddOptionResponse, error)
	AbsintheAtivateSession(context.Context, *AbsintheAtivateSessionRequest) (*AbsintheAtivateSessionResponse, error)
	AbsintheSignData(context.Context, *AbsintheSignDataRequest) (*AbsintheSignDataResponse, error)
	IndentitySession(context.Context, *IndentitySessionRequest) (*IndentitySessionResponse, error)
	IndentityValidation(context.Context, *IndentityValidationRequest) (*IndentityValidationResponse, error)
	SAPExchange(context.Context, *SAPExchangeRequest) (*SAPExchangeResponse, error)
	SAPSignPrime(context.Context, *SAPSignPrimeRequest) (*SAPSignPrimeResponse, error)
	SAPVerifyPrime(context.Context, *SAPVerifyPrimeRequest) (*SAPVerifyPrimeResponse, error)
	SAPSign(context.Context, *SAPSignRequest) (*SAPSignResponse, error)
	SAPVerify(context.Context, *SAPVerifyRequest) (*SAPVerifyResponse, error)
	mustEmbedUnimplementedCryptServiceServer()
}

// UnimplementedCryptServiceServer must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedCryptServiceServer struct{}

func (UnimplementedCryptServiceServer) Initialize(context.Context, *InitializeRequest) (*InitializeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Initialize not implemented")
}
func (UnimplementedCryptServiceServer) Finalize(context.Context, *FinalizeRequest) (*FinalizeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Finalize not implemented")
}
func (UnimplementedCryptServiceServer) ActivationDRMHandshake(context.Context, *ActivationDRMHandshakeRequest) (*ActivationDRMHandshakeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ActivationDRMHandshake not implemented")
}
func (UnimplementedCryptServiceServer) ActivationDRMProcess(context.Context, *ActivationDRMProcessRequest) (*ActivationDRMProcessResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ActivationDRMProcess not implemented")
}
func (UnimplementedCryptServiceServer) ActivationDRMSignature(context.Context, *ActivationDRMSignatureRequest) (*ActivationDRMSignatureResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ActivationDRMSignature not implemented")
}
func (UnimplementedCryptServiceServer) ActivationDeprecated(context.Context, *ActivationDeprecatedRequest) (*ActivationDeprecatedResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ActivationDeprecated not implemented")
}
func (UnimplementedCryptServiceServer) ActivationRecord(context.Context, *ActivationRecordRequest) (*ActivationRecordResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ActivationRecord not implemented")
}
func (UnimplementedCryptServiceServer) ADIStartProvisioning(context.Context, *ADIStartProvisioningRequest) (*ADIStartProvisioningResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ADIStartProvisioning not implemented")
}
func (UnimplementedCryptServiceServer) ADIEndProvisioning(context.Context, *ADIEndProvisioningRequest) (*ADIEndProvisioningResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ADIEndProvisioning not implemented")
}
func (UnimplementedCryptServiceServer) ADIGenerateLoginCode(context.Context, *ADIGenerateLoginCodeRequest) (*ADIGenerateLoginCodeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ADIGenerateLoginCode not implemented")
}
func (UnimplementedCryptServiceServer) AbsintheHello(context.Context, *AbsintheHelloRequest) (*AbsintheHelloResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AbsintheHello not implemented")
}
func (UnimplementedCryptServiceServer) AbsintheAddOption(context.Context, *AbsintheAddOptionRequest) (*AbsintheAddOptionResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AbsintheAddOption not implemented")
}
func (UnimplementedCryptServiceServer) AbsintheAtivateSession(context.Context, *AbsintheAtivateSessionRequest) (*AbsintheAtivateSessionResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AbsintheAtivateSession not implemented")
}
func (UnimplementedCryptServiceServer) AbsintheSignData(context.Context, *AbsintheSignDataRequest) (*AbsintheSignDataResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AbsintheSignData not implemented")
}
func (UnimplementedCryptServiceServer) IndentitySession(context.Context, *IndentitySessionRequest) (*IndentitySessionResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method IndentitySession not implemented")
}
func (UnimplementedCryptServiceServer) IndentityValidation(context.Context, *IndentityValidationRequest) (*IndentityValidationResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method IndentityValidation not implemented")
}
func (UnimplementedCryptServiceServer) SAPExchange(context.Context, *SAPExchangeRequest) (*SAPExchangeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SAPExchange not implemented")
}
func (UnimplementedCryptServiceServer) SAPSignPrime(context.Context, *SAPSignPrimeRequest) (*SAPSignPrimeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SAPSignPrime not implemented")
}
func (UnimplementedCryptServiceServer) SAPVerifyPrime(context.Context, *SAPVerifyPrimeRequest) (*SAPVerifyPrimeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SAPVerifyPrime not implemented")
}
func (UnimplementedCryptServiceServer) SAPSign(context.Context, *SAPSignRequest) (*SAPSignResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SAPSign not implemented")
}
func (UnimplementedCryptServiceServer) SAPVerify(context.Context, *SAPVerifyRequest) (*SAPVerifyResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SAPVerify not implemented")
}
func (UnimplementedCryptServiceServer) mustEmbedUnimplementedCryptServiceServer() {}
func (UnimplementedCryptServiceServer) testEmbeddedByValue()                      {}

// UnsafeCryptServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to CryptServiceServer will
// result in compilation errors.
type UnsafeCryptServiceServer interface {
	mustEmbedUnimplementedCryptServiceServer()
}

func RegisterCryptServiceServer(s grpc.ServiceRegistrar, srv CryptServiceServer) {
	// If the following call pancis, it indicates UnimplementedCryptServiceServer was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&CryptService_ServiceDesc, srv)
}

func _CryptService_Initialize_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(InitializeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CryptServiceServer).Initialize(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CryptService_Initialize_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CryptServiceServer).Initialize(ctx, req.(*InitializeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CryptService_Finalize_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(FinalizeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CryptServiceServer).Finalize(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CryptService_Finalize_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CryptServiceServer).Finalize(ctx, req.(*FinalizeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CryptService_ActivationDRMHandshake_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ActivationDRMHandshakeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CryptServiceServer).ActivationDRMHandshake(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CryptService_ActivationDRMHandshake_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CryptServiceServer).ActivationDRMHandshake(ctx, req.(*ActivationDRMHandshakeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CryptService_ActivationDRMProcess_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ActivationDRMProcessRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CryptServiceServer).ActivationDRMProcess(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CryptService_ActivationDRMProcess_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CryptServiceServer).ActivationDRMProcess(ctx, req.(*ActivationDRMProcessRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CryptService_ActivationDRMSignature_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ActivationDRMSignatureRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CryptServiceServer).ActivationDRMSignature(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CryptService_ActivationDRMSignature_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CryptServiceServer).ActivationDRMSignature(ctx, req.(*ActivationDRMSignatureRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CryptService_ActivationDeprecated_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ActivationDeprecatedRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CryptServiceServer).ActivationDeprecated(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CryptService_ActivationDeprecated_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CryptServiceServer).ActivationDeprecated(ctx, req.(*ActivationDeprecatedRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CryptService_ActivationRecord_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ActivationRecordRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CryptServiceServer).ActivationRecord(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CryptService_ActivationRecord_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CryptServiceServer).ActivationRecord(ctx, req.(*ActivationRecordRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CryptService_ADIStartProvisioning_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ADIStartProvisioningRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CryptServiceServer).ADIStartProvisioning(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CryptService_ADIStartProvisioning_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CryptServiceServer).ADIStartProvisioning(ctx, req.(*ADIStartProvisioningRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CryptService_ADIEndProvisioning_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ADIEndProvisioningRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CryptServiceServer).ADIEndProvisioning(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CryptService_ADIEndProvisioning_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CryptServiceServer).ADIEndProvisioning(ctx, req.(*ADIEndProvisioningRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CryptService_ADIGenerateLoginCode_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ADIGenerateLoginCodeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CryptServiceServer).ADIGenerateLoginCode(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CryptService_ADIGenerateLoginCode_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CryptServiceServer).ADIGenerateLoginCode(ctx, req.(*ADIGenerateLoginCodeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CryptService_AbsintheHello_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AbsintheHelloRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CryptServiceServer).AbsintheHello(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CryptService_AbsintheHello_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CryptServiceServer).AbsintheHello(ctx, req.(*AbsintheHelloRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CryptService_AbsintheAddOption_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AbsintheAddOptionRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CryptServiceServer).AbsintheAddOption(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CryptService_AbsintheAddOption_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CryptServiceServer).AbsintheAddOption(ctx, req.(*AbsintheAddOptionRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CryptService_AbsintheAtivateSession_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AbsintheAtivateSessionRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CryptServiceServer).AbsintheAtivateSession(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CryptService_AbsintheAtivateSession_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CryptServiceServer).AbsintheAtivateSession(ctx, req.(*AbsintheAtivateSessionRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CryptService_AbsintheSignData_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AbsintheSignDataRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CryptServiceServer).AbsintheSignData(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CryptService_AbsintheSignData_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CryptServiceServer).AbsintheSignData(ctx, req.(*AbsintheSignDataRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CryptService_IndentitySession_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(IndentitySessionRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CryptServiceServer).IndentitySession(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CryptService_IndentitySession_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CryptServiceServer).IndentitySession(ctx, req.(*IndentitySessionRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CryptService_IndentityValidation_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(IndentityValidationRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CryptServiceServer).IndentityValidation(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CryptService_IndentityValidation_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CryptServiceServer).IndentityValidation(ctx, req.(*IndentityValidationRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CryptService_SAPExchange_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SAPExchangeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CryptServiceServer).SAPExchange(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CryptService_SAPExchange_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CryptServiceServer).SAPExchange(ctx, req.(*SAPExchangeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CryptService_SAPSignPrime_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SAPSignPrimeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CryptServiceServer).SAPSignPrime(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CryptService_SAPSignPrime_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CryptServiceServer).SAPSignPrime(ctx, req.(*SAPSignPrimeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CryptService_SAPVerifyPrime_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SAPVerifyPrimeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CryptServiceServer).SAPVerifyPrime(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CryptService_SAPVerifyPrime_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CryptServiceServer).SAPVerifyPrime(ctx, req.(*SAPVerifyPrimeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CryptService_SAPSign_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SAPSignRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CryptServiceServer).SAPSign(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CryptService_SAPSign_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CryptServiceServer).SAPSign(ctx, req.(*SAPSignRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CryptService_SAPVerify_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SAPVerifyRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CryptServiceServer).SAPVerify(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CryptService_SAPVerify_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CryptServiceServer).SAPVerify(ctx, req.(*SAPVerifyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// CryptService_ServiceDesc is the grpc.ServiceDesc for CryptService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var CryptService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "icrypto.CryptService",
	HandlerType: (*CryptServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Initialize",
			Handler:    _CryptService_Initialize_Handler,
		},
		{
			MethodName: "Finalize",
			Handler:    _CryptService_Finalize_Handler,
		},
		{
			MethodName: "ActivationDRMHandshake",
			Handler:    _CryptService_ActivationDRMHandshake_Handler,
		},
		{
			MethodName: "ActivationDRMProcess",
			Handler:    _CryptService_ActivationDRMProcess_Handler,
		},
		{
			MethodName: "ActivationDRMSignature",
			Handler:    _CryptService_ActivationDRMSignature_Handler,
		},
		{
			MethodName: "ActivationDeprecated",
			Handler:    _CryptService_ActivationDeprecated_Handler,
		},
		{
			MethodName: "ActivationRecord",
			Handler:    _CryptService_ActivationRecord_Handler,
		},
		{
			MethodName: "ADIStartProvisioning",
			Handler:    _CryptService_ADIStartProvisioning_Handler,
		},
		{
			MethodName: "ADIEndProvisioning",
			Handler:    _CryptService_ADIEndProvisioning_Handler,
		},
		{
			MethodName: "ADIGenerateLoginCode",
			Handler:    _CryptService_ADIGenerateLoginCode_Handler,
		},
		{
			MethodName: "AbsintheHello",
			Handler:    _CryptService_AbsintheHello_Handler,
		},
		{
			MethodName: "AbsintheAddOption",
			Handler:    _CryptService_AbsintheAddOption_Handler,
		},
		{
			MethodName: "AbsintheAtivateSession",
			Handler:    _CryptService_AbsintheAtivateSession_Handler,
		},
		{
			MethodName: "AbsintheSignData",
			Handler:    _CryptService_AbsintheSignData_Handler,
		},
		{
			MethodName: "IndentitySession",
			Handler:    _CryptService_IndentitySession_Handler,
		},
		{
			MethodName: "IndentityValidation",
			Handler:    _CryptService_IndentityValidation_Handler,
		},
		{
			MethodName: "SAPExchange",
			Handler:    _CryptService_SAPExchange_Handler,
		},
		{
			MethodName: "SAPSignPrime",
			Handler:    _CryptService_SAPSignPrime_Handler,
		},
		{
			MethodName: "SAPVerifyPrime",
			Handler:    _CryptService_SAPVerifyPrime_Handler,
		},
		{
			MethodName: "SAPSign",
			Handler:    _CryptService_SAPSign_Handler,
		},
		{
			MethodName: "SAPVerify",
			Handler:    _CryptService_SAPVerify_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "crypto.proto",
}
