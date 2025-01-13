package decoder

import (
	"fmt"
	"strconv"

	"github.com/noovertime7/cilium-ebpf-exporters/config"
)

// PCIVendor is a decoder that transforms PCI vendor id into a name
type PCIVendor struct{}

// Decode transforms PCI vendor id into a name
func (d *PCIVendor) Decode(in []byte, _ config.Decoder) ([]byte, error) {
	if pci == nil {
		return []byte(missingPciIDsText), nil
	}

	num, err := strconv.Atoi(string(in))
	if err != nil {
		return nil, err
	}

	key := fmt.Sprintf("%02x", num)

	if vendor, ok := pci.Vendors[key]; ok {
		return []byte(vendor.Name), nil
	}

	return []byte("unknown pci vendor: 0x" + key), nil
}
