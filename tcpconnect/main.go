package main

import (
	"fmt"
	"log"
	"os"
	"path"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -Wall -g -Werror -D __TARGET_ARCH_x86" tcpconnect tcpconnect.c

func main() {

	bpfFSPath := "/sys/fs/bpf"
	pinPath := path.Join(bpfFSPath, "tcpconnect")
	if err := os.MkdirAll(pinPath, os.ModePerm); err != nil {
		log.Fatalf("failed to create bpf fs subpath: %+v", err)
	}

	// Load pre-compiled programs into the kernel.
	bpfObjs := tcpconnectObjects{}
	if err := loadTcpconnectObjects(&bpfObjs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: pinPath,
		},
	}); err != nil {
		log.Fatalf("load object: %s", err)
	}
	defer bpfObjs.Close()

	// if err := bpfObjs.XdpProgram.Pin(path.Join(pinPath, "xdp_program")); err != nil {
	// 	log.Fatalf("could not pin program: %s", err)
	// }

	// Attach the program.
	kp, err := link.Kprobe("tcp_v4_connect", bpfObjs.TcpV4Connect, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	// Print the contents of the BPF hash map (source IP address -> packet count).
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s, err := formatMapContents(bpfObjs.PktCounter)
		if err != nil {
			log.Printf("Error reading map: %s", err)
			continue
		}
		log.Printf("Map contents:\n%s", s)
	}

}

func formatMapContents(m *ebpf.Map) (string, error) {
	var (
		sb  strings.Builder
		key uint32
		val uint32
	)

	iter := m.Iterate()
	for iter.Next(&key, &val) {
		packetCount := val
		sb.WriteString(fmt.Sprintf("\t%d => %d\n", key, packetCount))
	}
	return sb.String(), iter.Err()
}
