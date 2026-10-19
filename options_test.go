package icrypto

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

func TestDeletedInitializationFlagsAreRejected(t *testing.T) {
	// 旧协议 type=IOSDRM 的实际 wire 字节；禁止被新服务静默忽略成普通初始化。
	request := &InitializeRequest{}
	if err := proto.Unmarshal([]byte{0x08, 0x01}, request); err != nil {
		t.Fatal(err)
	}
	if _, err := request.Options(); err == nil {
		t.Fatal("deleted type field silently became AUTO")
	}
}

func TestInitializeOptionsRejectBeforeRPC(t *testing.T) {
	client := &CryptorGRPC{} // 无连接，验证必须先于网络操作。
	for _, options := range []InitializeOptions{
		{MacOSRuntime: 99},
		{IOSDRM: true, MacOSRuntime: MacOSRuntime_MACOS_COMPATIBLE},
	} {
		if err := client.Initialize(context.Background(), options, nil); err == nil {
			t.Fatal("invalid options accepted")
		}
	}
}

// 缺少身份必须在创建 RPC 元数据及访问连接前失败，不能发起空设备初始化。
func TestInitializeRejectsMissingDeviceBeforeRPC(t *testing.T) {
	client := &CryptorGRPC{}
	if err := client.Initialize(context.Background(), InitializeOptions{}, nil); err == nil {
		t.Fatal("missing device accepted")
	}
}

type drmInitializeClient struct {
	CryptServiceClient
	request *InitializeRequest
}

func (c *drmInitializeClient) Initialize(_ context.Context, r *InitializeRequest, _ ...grpc.CallOption) (*InitializeResponse, error) {
	c.request = r
	data, _ := (&syncDeviceTestObject{APTicket: []byte("changed")}).Marshal()
	return &InitializeResponse{Device: data}, nil
}

// 指定物理计算设备必须通过同一初始化契约传递，不能只在业务层看见。
func TestDRMComputeUDIDTransport(t *testing.T) {
	r := &InitializeRequest{IosDrm: true, SepDeviceUdid: "phone-a"}
	raw, err := proto.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	decoded := new(InitializeRequest)
	if err := proto.Unmarshal(raw, decoded); err != nil {
		t.Fatal(err)
	}
	options, err := decoded.Options()
	if err != nil || options.SEPDeviceUDID != "phone-a" {
		t.Fatalf("lost UDID: %v", err)
	}
	client := &drmInitializeClient{}
	cryptor := &CryptorGRPC{Client: client, ClientId: "route-test"}
	if err := cryptor.Initialize(context.Background(), InitializeOptions{IOSDRM: true, SEPDeviceUDID: "phone-a"}, &syncDeviceTestObject{}); err != nil {
		t.Fatal(err)
	}
	if client.request.SepDeviceUdid != "phone-a" {
		t.Fatal("RPC dropped compute UDID")
	}
	if err := (InitializeOptions{SEPDeviceUDID: "phone-a"}).Validate(); err == nil {
		t.Fatal("UDID accepted without DRM")
	}
}
