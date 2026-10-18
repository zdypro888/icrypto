package icrypto

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/zdypro888/go-plist"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
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

// Init and NewCryptorGRPC may run concurrently; a cryptor must always see the
// client and API key of the same Init call.
func TestInitGRPCConcurrentWithNewCryptor(t *testing.T) {
	t.Cleanup(func() { _ = CloseGRPC() })
	if err := InitGRPCWithAPIKey("127.0.0.1:1", "key-0"); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		for i := 0; i < 50; i++ {
			if err := InitGRPCWithAPIKey("127.0.0.1:1", "key-1"); err != nil {
				t.Error(err)
			}
		}
	})
	for range 4 {
		wg.Go(func() {
			for i := 0; i < 2000; i++ {
				c := NewCryptorGRPC().(*CryptorGRPC)
				if c.Client == nil || (c.APIKey != "key-0" && c.APIKey != "key-1") {
					t.Errorf("inconsistent cryptor: %+v", c)
					return
				}
			}
		})
	}
	wg.Wait()
}

func TestCloseGRPCReleasesSupersededConns(t *testing.T) {
	if err := InitGRPC("127.0.0.1:1"); err != nil {
		t.Fatal(err)
	}
	first := cryptoState.Load().conn
	if err := InitGRPC("127.0.0.1:1"); err != nil {
		t.Fatal(err)
	}
	second := cryptoState.Load().conn
	// a superseded connection stays usable for cryptors created before re-init
	if first.GetState() == connectivity.Shutdown {
		t.Fatal("re-init must not close the previous connection")
	}
	if err := CloseGRPC(); err != nil {
		t.Fatal(err)
	}
	for _, conn := range []interface{ GetState() connectivity.State }{first, second} {
		if conn.GetState() != connectivity.Shutdown {
			t.Errorf("connection not closed: %v", conn.GetState())
		}
	}
	if c := NewCryptorGRPC().(*CryptorGRPC); c.Client != nil {
		t.Error("cryptor created after CloseGRPC still has a client")
	}
}
