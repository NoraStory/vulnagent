//go:build !linux && !windows

package collect

// collectLinuxTelemetry 非 Linux 平台占位，保证调度函数可编译。
func collectLinuxTelemetry(t Telemetry) (Telemetry, []string) {
	return t, []string{"当前平台不支持 Linux 遥测"}
}

// collectWindowsTelemetry 非 Windows 平台占位，保证调度函数可编译。
func collectWindowsTelemetry(t Telemetry) (Telemetry, []string) {
	return t, []string{"当前平台不支持 Windows 遥测"}
}
