package decoder

import (
	"bytes"
	"testing"

	"github.com/noovertime7/cilium-ebpf-exporters/config"
)

func testPCIMissing(t *testing.T, d Decoder, cases [][]byte) {
	if pci != nil {
		t.Skip("PCI DB is available")
	}

	for _, c := range cases {
		out, err := d.Decode(c, config.Decoder{})
		if err != nil {
			t.Errorf("Error decoding %#v: %v", c, err)
		}

		if !bytes.Equal(out, []byte(missingPciIDsText)) {
			t.Errorf("Expected %q, got %s", missingPciIDsText, out)
		}
	}
}

type pciCase struct {
	in  []byte
	out []byte
}

func testPCIPresent(t *testing.T, d Decoder, cases []pciCase) {
	if pci == nil {
		t.Skip("PCI DB is not available")
	}

	for _, c := range cases {
		out, err := d.Decode(c.in, config.Decoder{})
		if err != nil {
			t.Errorf("Error decoding %#v: %v", c.in, err)
		}

		if !bytes.Equal(out, c.out) {
			t.Errorf("Expected %q, got %q", c.out, out)
		}
	}
}
