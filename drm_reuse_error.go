package icrypto

import (
	"errors"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const drmReuseUnavailableReason = "DRM_UIK_REUSE_UNAVAILABLE"

// DRMUIKReuseError 表示初始化时已确认旧 UIK 无法复用；不是网络或服务器激活失败。
// 以结构化 gRPC detail 跨 core/代理传递，禁止按错误文字判断是否重新发起激活。
type DRMUIKReuseError struct{ Reason string }

func (e *DRMUIKReuseError) Error() string { return "DRM UIK reuse unavailable: " + e.Reason }
func (e *DRMUIKReuseError) GRPCStatus() *status.Status {
	s := status.New(codes.FailedPrecondition, e.Error())
	detailed, err := s.WithDetails(&errdetails.ErrorInfo{Domain: "icrypto", Reason: drmReuseUnavailableReason})
	if err != nil {
		return s
	}
	return detailed
}

// IsDRMUIKReuseUnavailable 只识别可清理后回退的初始化错误；联合清理失败时不能继续。
func IsDRMUIKReuseUnavailable(err error) bool {
	if err == nil {
		return false
	}
	if multi, ok := err.(interface{ Unwrap() []error }); ok {
		children := multi.Unwrap()
		if len(children) != 1 {
			return false
		}
		return IsDRMUIKReuseUnavailable(children[0])
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		return IsDRMUIKReuseUnavailable(wrapped.Unwrap())
	}
	var reuse *DRMUIKReuseError
	if errors.As(err, &reuse) {
		return true
	}
	s, ok := status.FromError(err)
	if !ok || s.Code() != codes.FailedPrecondition {
		return false
	}
	for _, d := range s.Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok && info.Domain == "icrypto" && info.Reason == drmReuseUnavailableReason {
			return true
		}
	}
	return false
}
