package icrypto

import "fmt"

// InitializeOptions 配置计算会话：是否连接 SEP 执行 iOS DRM、加载哪个 macOS 镜像。
// 待激活设备信息另由 Initialize 的 device 参数提供；不会根据这些选项改写设备身份。
// 零值使用普通计算流程和默认镜像；本结构可比较，用于判断已有会话能否复用。
type InitializeOptions struct {
	// IOSDRM=true 时连接真实 SEP 并初始化 iOS DRM 所需密钥上下文，仅支持 iOS。
	// 默认 false；开启后仍需调用 DRM 握手、响应处理和签名方法，不会自动执行激活。
	IOSDRM bool
	// MacOSRuntime 选择服务端 macOS 计算镜像，不改变 device 上报的系统版本。
	// AUTO：当前对 15.5 使用 macOS15 镜像，其余使用原有 Intel 镜像；
	// COMPATIBLE：强制使用原有 Intel 镜像。iOS DRM 保持默认 AUTO。
	MacOSRuntime MacOSRuntime
	// SEPDeviceUDID 指定 SEP 计算设备，可与待激活 Device 的 UDID 不同，仅用于 IOSDRM。
	// 空值沿用已有计算绑定；没有绑定则由服务端调度。指定值不得与已有计算绑定冲突。
	SEPDeviceUDID string
}

// Validate 拒绝未知选项，不能把未知数值当作默认实现。
func (o InitializeOptions) Validate() error {
	if o.SEPDeviceUDID != "" && !o.IOSDRM {
		return fmt.Errorf("SEP device UDID requires IOSDRM")
	}
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
	options := InitializeOptions{IOSDRM: request.IosDrm, MacOSRuntime: request.MacosRuntime, SEPDeviceUDID: request.SepDeviceUdid}
	return options, options.Validate()
}
