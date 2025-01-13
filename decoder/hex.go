package decoder

import (
	"encoding/hex"

	"github.com/noovertime7/cilium-ebpf-exporters/config"
)

// Hex is a decoder that decodes raw bytes into their hex string representation
type Hex struct{}

// Decode transforms bytes into their hex string representation
func (u *Hex) Decode(in []byte, _ config.Decoder) ([]byte, error) {
	return []byte(hex.EncodeToString(in)), nil
}
