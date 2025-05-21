package icrypto

import (
	"crypto/sha1"
	"fmt"
)

func (device *Device) BootManifestHash() []byte {
	hash := sha1.Sum(device.APTicket)
	return hash[:]
}

func (device *Device) ChipId() uint32 {
	switch device.ProductType {
	case "iPhone5,1", "iPhone5,2", "iPhone5,3", "iPhone5,4":
		return 0x8950
	default:
		return 0
	}
}

// ChipString chipId = CPUID
func (device *Device) ChipString() string {
	return fmt.Sprintf("%08X-%016X", device.ChipId(), device.UniqueChipID)
}
