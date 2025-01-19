package decoder

import (
	"encoding/binary"
	"testing"

	"github.com/noovertime7/cilium-ebpf-exporters/config"
)

func TestPortDecoder(t *testing.T) {
	cases := []struct {
		name    string
		in      []byte
		want    string
		wantErr bool
	}{
		{
			name: "port 80",
			in: func() []byte {
				b := make([]byte, 2)
				binary.BigEndian.PutUint16(b, 80)
				return b
			}(),
			want:    "80",
			wantErr: false,
		},
		{
			name: "port 443",
			in: func() []byte {
				b := make([]byte, 2)
				binary.BigEndian.PutUint16(b, 443)
				return b
			}(),
			want:    "443",
			wantErr: false,
		},
		{
			name:    "input too short",
			in:      []byte{0x01},
			want:    "",
			wantErr: true,
		},
	}

	decoder := &Port{}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decoder.Decode(tc.in, config.Decoder{})
			if (err != nil) != tc.wantErr {
				t.Errorf("Decode() error = %v, wantErr %v", err, tc.wantErr)
				return
			}
			if !tc.wantErr && string(got) != tc.want {
				t.Errorf("Decode() = %v, want %v", string(got), tc.want)
			}
		})
	}
}
