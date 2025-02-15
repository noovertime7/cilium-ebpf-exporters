package decoder

import (
	"net"

	"github.com/noovertime7/cilium-ebpf-exporters/config"
)

// InetIP is a decoder that transforms an ip byte representation into a string
type InetIP struct{}

// Decode transforms an ip byte representation into a string
func (i *InetIP) Decode(in []byte, _ config.Decoder) ([]byte, error) {
	ip := net.IP(in)
	return []byte(ip.String()), nil
}
