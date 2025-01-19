package util

import (
	"encoding/binary"
	"golang.org/x/sys/unix"
	"syscall"
	"unsafe"
)

func OpenRawSock(index int) (int, error) {
	sock, err := unix.Socket(unix.AF_PACKET,
		unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, int(Htons(unix.ETH_P_ALL)))
	if err != nil {
		return 0, err
	}

	sll := syscall.SockaddrLinklayer{}
	sll.Protocol = Htons(unix.ETH_P_ALL)
	sll.Ifindex = index
	if err := syscall.Bind(sock, &sll); err != nil {
		return 0, err
	}

	return sock, nil
}

// Htons converts the unsigned short integer hostshort from host byte order to network byte order.
func Htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}
