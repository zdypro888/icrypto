package icrypto

import "fmt"

// InitializeOptions 选择计算能力与运行环境，不包含设备身份或传统激活签名方式。
// 零值按设备选择默认环境；该结构可比较，业务层可据此判断缓存会话能否复用。
type InitializeOptions struct {
	// IOSDRM 请求初始化 iOS 的 SEP/DRM 能力；不是将所有操作切换到 DRM 协议。
	IOSDRM bool
	// MacOSRuntime 只对 macOS 身份有效；AUTO 自动选择，COMPATIBLE 使用兼容环境。
	// 该值不修改设备上报的系统版本，也不指定 iOS 的 Legacy 签名方式。
	MacOSRuntime MacOSRuntime
}

// Validate 拒绝未知选项，不能把未知数值当作默认实现。
func (o InitializeOptions) Validate() error {
	if o.IOSDRM && o.MacOSRuntime != MacOSRuntime_MACOS_AUTO {
		return fmt.Errorf("IOSDRM cannot be combined with a macOS runtime preference")
	}
	return ValidateMacOSRuntime(o.MacOSRuntime)
}

// ValidateMacOSRuntime 同时用于初始化与单次签名参数。
func ValidateMacOSRuntime(runtime MacOSRuntime) error {
	switch runtime {
	case MacOSRuntime_MACOS_AUTO, MacOSRuntime_MACOS_COMPATIBLE:
		return nil
	default:
		return fmt.Errorf("unsupported macOS runtime: %d", runtime)
	}
}

// Options 解码当前契约；已删除的旧标志不能被忽略后悄悄按默认环境执行。
func (request *InitializeRequest) Options() (InitializeOptions, error) {
	if request == nil {
		return InitializeOptions{}, fmt.Errorf("initialize request is nil")
	}
	if len(request.ProtoReflect().GetUnknown()) != 0 {
		return InitializeOptions{}, fmt.Errorf("unsupported initialization fields; update the caller")
	}
	options := InitializeOptions{IOSDRM: request.IosDrm, MacOSRuntime: request.MacosRuntime}
	return options, options.Validate()
}
