package decoder

import (
	"fmt"

	"github.com/noovertime7/cilium-ebpf-exporters/config"
	"github.com/noovertime7/cilium-ebpf-exporters/kallsyms"
	"github.com/noovertime7/cilium-ebpf-exporters/util"
)

// KSym is a decoder that transforms kernel address to a function name
type KSym struct {
	decoder *kallsyms.Decoder
}

// Decode transforms kernel address to a function name
func (k *KSym) Decode(in []byte, _ config.Decoder) ([]byte, error) {
	ptr := util.GetHostByteOrder().Uint64(in)

	sym := k.decoder.Sym(uintptr(ptr))
	if sym == "" {
		sym = fmt.Sprintf("unknown_addr:0x%x", ptr)
	}

	return []byte(sym), nil
}
