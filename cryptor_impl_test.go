package icrypto

import (
	"context"
	"testing"
	"time"

	"github.com/zdypro888/go-plist"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type syncDeviceTestObject struct {
	APTicket []byte `plist:"APTicket,omitempty"`
}

func TestMetaContextPreservesCallerMetadataAndDeadline(t *testing.T) {
	parent, cancelParent := context.WithTimeout(context.Background(), time.Second)
	defer cancelParent()
	parent = metadata.NewOutgoingContext(parent, metadata.Pairs("trace-id", "trace", "client_id", "old", "x-api-key", "old-key"))
	cryptor := &CryptorGRPC{ClientId: "new", APIKey: "new-key"}
	ctx, cancel := cryptor.metaContext(parent)
	defer cancel()
	md, _ := metadata.FromOutgoingContext(ctx)
	for key, want := range map[string]string{"trace-id": "trace", "client_id": "new", "x-api-key": "new-key"} {
		got := md.Get(key)
		if len(got) != 1 || got[0] != want {
			t.Fatalf("%s: got %v, want %s", key, got, want)
		}
	}
	original, _ := metadata.FromOutgoingContext(parent)
	if original.Get("client_id")[0] != "old" || original.Get("x-api-key")[0] != "old-key" {
		t.Fatal("mutated caller metadata")
	}
	deadline, _ := ctx.Deadline()
	parentDeadline, _ := parent.Deadline()
	if !deadline.Equal(parentDeadline) {
		t.Fatal("extended caller deadline")
	}
}

func (object *syncDeviceTestObject) Marshal() ([]byte, error) {
	return plist.Marshal(object, plist.BinaryFormat)
}

func (object *syncDeviceTestObject) Unmarshal(data []byte) error {
	_, err := plist.Unmarshal(data, object)
	return err
}

type syncDeviceClientSpy struct {
	CryptServiceClient
	request *SyncDeviceRequest
}

func (client *syncDeviceClientSpy) SyncDevice(_ context.Context, request *SyncDeviceRequest, _ ...grpc.CallOption) (*SyncDeviceResponse, error) {
	client.request = request
	return &SyncDeviceResponse{}, nil
}

func TestCryptorGRPCSyncDeviceSendsCurrentSnapshot(t *testing.T) {
	client := &syncDeviceClientSpy{}
	cryptor := &CryptorGRPC{ClientId: "test-client", Client: client}
	device := &syncDeviceTestObject{}

	device.APTicket = []byte{1, 2, 3, 4}
	if err := cryptor.SyncDevice(context.Background(), device); err != nil {
		t.Fatalf("SyncDevice: %v", err)
	}
	if client.request == nil {
		t.Fatal("SyncDevice RPC was not called")
	}
	var snapshot syncDeviceTestObject
	if _, err := plist.Unmarshal(client.request.Device, &snapshot); err != nil {
		t.Fatalf("unmarshal synchronized snapshot: %v", err)
	}
	if string(snapshot.APTicket) != string(device.APTicket) {
		t.Fatalf("synchronized AP ticket = %x, want %x", snapshot.APTicket, device.APTicket)
	}
}
