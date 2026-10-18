package icrypto

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
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
	mode    DRMUIKMode
	request *InitializeRequest
}

func (c *drmInitializeClient) Initialize(_ context.Context, r *InitializeRequest, _ ...grpc.CallOption) (*InitializeResponse, error) {
	c.request = r
	data, _ := (&syncDeviceTestObject{APTicket: []byte("changed")}).Marshal()
	return &InitializeResponse{Device: data, DrmUikMode: c.mode}, nil
}

// 模式经 protobuf 往返保持原值；不支持的 proposed 不能成为默认 committed。
func TestDRMUIKOptionsContract(t *testing.T) {
	for _, mode := range []DRMUIKMode{DRMUIKMode_DRM_UIK_AUTO, DRMUIKMode_DRM_UIK_COMMITTED, DRMUIKMode_DRM_UIK_PROPOSED, 99} {
		raw, err := proto.Marshal(&InitializeRequest{IosDrm: true, DrmUikMode: mode})
		if err != nil {
			t.Fatal(err)
		}
		r := new(InitializeRequest)
		if err = proto.Unmarshal(raw, r); err != nil {
			t.Fatal(err)
		}
		options, err := r.Options()
		valid := mode == DRMUIKMode_DRM_UIK_AUTO || mode == DRMUIKMode_DRM_UIK_COMMITTED
		if (err == nil) != valid {
			t.Fatalf("mode %v: %v", mode, err)
		}
		if valid && options.DRMUIKMode != mode {
			t.Fatal("mode lost")
		}
	}
	if err := (InitializeOptions{DRMUIKMode: DRMUIKMode_DRM_UIK_COMMITTED}).Validate(); err == nil {
		t.Fatal("mode accepted without DRM")
	}
}

// 旧服务未确认模式时，不允许把它返回的设备材料提交到调用方。
func TestDRMUIKModeAcknowledgement(t *testing.T) {
	for _, mode := range []DRMUIKMode{DRMUIKMode_DRM_UIK_AUTO, DRMUIKMode_DRM_UIK_COMMITTED} {
		client := &drmInitializeClient{mode: mode}
		cryptor := &CryptorGRPC{Client: client, ClientId: "drm-test"}
		device := &syncDeviceTestObject{APTicket: []byte("original")}
		err := cryptor.Initialize(context.Background(), InitializeOptions{IOSDRM: true, DRMUIKMode: DRMUIKMode_DRM_UIK_COMMITTED}, device)
		if client.request.DrmUikMode != DRMUIKMode_DRM_UIK_COMMITTED {
			t.Fatal("mode not sent")
		}
		if mode == DRMUIKMode_DRM_UIK_AUTO {
			if err == nil || string(device.APTicket) != "original" {
				t.Fatal("unconfirmed state committed")
			}
		} else if err != nil || string(device.APTicket) != "changed" {
			t.Fatalf("confirmed mode: %v", err)
		}
	}
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
	client := &drmInitializeClient{mode: DRMUIKMode_DRM_UIK_COMMITTED}
	cryptor := &CryptorGRPC{Client: client, ClientId: "route-test"}
	if err := cryptor.Initialize(context.Background(), InitializeOptions{IOSDRM: true, DRMUIKMode: DRMUIKMode_DRM_UIK_COMMITTED, SEPDeviceUDID: "phone-a"}, &syncDeviceTestObject{}); err != nil {
		t.Fatal(err)
	}
	if client.request.SepDeviceUdid != "phone-a" {
		t.Fatal("RPC dropped compute UDID")
	}
	if err := (InitializeOptions{SEPDeviceUDID: "phone-a"}).Validate(); err == nil {
		t.Fatal("UDID accepted without DRM")
	}
}

func TestDRMReuseErrorSurvivesRPC(t *testing.T) {
	reuse := &DRMUIKReuseError{Reason: "changed"}
	rpc := reuse.GRPCStatus().Err()
	if !IsDRMUIKReuseUnavailable(fmt.Errorf("core: %w", rpc)) {
		t.Fatal("lost reason")
	}
	if IsDRMUIKReuseUnavailable(errors.Join(reuse, errors.New("cleanup failed"))) {
		t.Fatal("cleanup failure permitted fallback")
	}
	if IsDRMUIKReuseUnavailable(status.Error(9, "DRM UIK reuse unavailable")) {
		t.Fatal("matched arbitrary error text")
	}
}
