package main

import (
	"fmt"
	"log"
	"net/netip"
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
	kp, err := link.Kprobe("tcp_v4_connect", bpfObjs.KprobeTcpV4Connect, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()
	krp, err := link.Kretprobe("tcp_v4_connect", bpfObjs.KretprobeTcpV4Connect, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer krp.Close()

	// Print the contents of the BPF hash map (source IP address -> packet count).
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s, err := formatMapContents(bpfObjs.ConnStats)
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
		key tcpconnectConnTupleT
		val tcpconnectConnStatsTsT
	)

	iter := m.Iterate()
	for iter.Next(&key, &val) {
		saddr := formatIPv4Address(key.SaddrL)
		daddr := formatIPv4Address(key.DaddrL)
		sb.WriteString(
			fmt.Sprintf("\tPID:%d\t%s\t%s:%d => %s:%d\n",
				key.Pid,
				formatTimestamp(val.Timestamp),
				saddr,
				key.Sport,
				daddr,
				key.Dport,
			))
	}

	return sb.String(), iter.Err()
}

func formatIPv4Address(addr uint64) string {
	return netip.AddrFrom4([4]byte{
		uint8(addr),
		uint8(addr >> 8),
		uint8(addr >> 16),
		uint8(addr >> 24),
	}).String()
}

func formatTimestamp(ts uint64) string {
	fmt.Printf("%v\n", ts)
	t := time.Unix(0, int64(ts)) // TODO boot時刻と足す
	return t.Format("2006-01-02T15:04:05Z07:00")
}
