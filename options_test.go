package icrypto

import (
	"context"
	"google.golang.org/protobuf/proto"
	"testing"
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
