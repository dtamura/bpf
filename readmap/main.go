package main

import (
	"fmt"
	"log"
	"path"
	"strings"
	"time"

	"github.com/cilium/ebpf"
)

func main() {

	bpfFSPath := "/sys/fs/bpf"
	pinPath := path.Join(bpfFSPath, "simple_xdp/pkt_counter")
	m, err := ebpf.LoadPinnedMap(pinPath, &ebpf.LoadPinOptions{
		ReadOnly: true,
	})
	if err != nil {
		log.Fatalf("could not load map: %s", err)
	}

	// Print the contents of the BPF hash map (source IP address -> packet count).
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s, err := formatMapContents(m)
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
