package icrypto

import (
	"sync"
	"testing"

	"google.golang.org/grpc/connectivity"
)

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
