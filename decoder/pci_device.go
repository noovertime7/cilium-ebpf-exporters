package decoder

import (
	"fmt"
	"strconv"

	"github.com/noovertime7/cilium-ebpf-exporters/config"
)

// PCIDevice is a decoder that transforms PCI device id into a name
type PCIDevice struct{}

// Decode transforms PCI device id into a name
func (d *PCIDevice) Decode(in []byte, _ config.Decoder) ([]byte, error) {
	if pci == nil {
		return []byte(missingPciIDsText), nil
	}

	num, err := strconv.Atoi(string(in))
	if err != nil {
		return nil, err
	}

	key := fmt.Sprintf("%04x", num)

	if device, ok := pci.Products[key]; ok {
		return []byte(device.Name), nil
	}

	return []byte("unknown pci device: 0x" + key), nil
}
