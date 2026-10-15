package icrypto

import (
	"errors"
	"fmt"
	"google.golang.org/grpc/status"
	"testing"
)

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
