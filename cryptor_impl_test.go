package icrypto

import (
	"context"
	"testing"

	"github.com/zdypro888/go-plist"
	"google.golang.org/grpc"
)

type syncDeviceTestObject struct {
	APTicket []byte `plist:"APTicket,omitempty"`
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
