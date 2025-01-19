package decoder

import (
	"encoding/binary"
	"fmt"

	"github.com/noovertime7/cilium-ebpf-exporters/config"
)

// Port is a decoder that handles network port conversion from network byte order
type Port struct{}

// Decode transforms network byte order port into host byte order
func (p *Port) Decode(in []byte, cfg config.Decoder) ([]byte, error) {
	if len(in) < 2 { // 端口需要 2 字节
		return nil, fmt.Errorf("input too short, expected 2 bytes for port, got %d", len(in))
	}

	// 从网络字节序（大端序）转换为主机字节序
	port := binary.BigEndian.Uint16(in[0:2])

	return []byte(fmt.Sprintf("%d", port)), nil
}
