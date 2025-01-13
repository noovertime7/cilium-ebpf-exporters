package decoder

import (
	"fmt"
	"strconv"

	"github.com/noovertime7/cilium-ebpf-exporters/config"
	"github.com/noovertime7/cilium-ebpf-exporters/util"
)

// UInt is a decoder that transforms unsigned integers into their string values
type UInt struct{}

// Decode transforms unsigned integers into their string values
func (u *UInt) Decode(in []byte, _ config.Decoder) ([]byte, error) {
	byteOrder := util.GetHostByteOrder()

	result := uint64(0)

	switch len(in) {
	case 8:
		result = byteOrder.Uint64(in)
	case 4:
		result = uint64(byteOrder.Uint32(in))
	case 2:
		result = uint64(byteOrder.Uint16(in))
	case 1:
		result = uint64(in[0])
	default:
		return nil, fmt.Errorf("unknown value length %d for %#v", len(in), in)
	}

	return []byte(strconv.FormatUint(result, 10)), nil
}
