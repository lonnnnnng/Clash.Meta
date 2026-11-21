package outbound

import "testing"

type resetTestWireGuardDevice struct {
	bindUpdates int
}

func (*resetTestWireGuardDevice) Close()              {}
func (*resetTestWireGuardDevice) IpcSet(string) error { return nil }
func (d *resetTestWireGuardDevice) BindUpdate() error { d.bindUpdates++; return nil }

func TestWireGuardResetNetworkRebindsInitializedDevice(t *testing.T) {
	device := &resetTestWireGuardDevice{}
	proxy := &WireGuard{device: device, option: WireGuardOption{Name: "test"}}

	proxy.ResetNetwork()

	if device.bindUpdates != 1 {
		t.Fatalf("BindUpdate calls=%d, want 1", device.bindUpdates)
	}
}

func TestWireGuardResetNetworkIgnoresUninitializedDevice(t *testing.T) {
	proxy := &WireGuard{}
	proxy.ResetNetwork()
}
