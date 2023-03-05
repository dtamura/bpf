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
	"github.com/shirou/gopsutil/v3/host"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -Wall -g -Werror -D __TARGET_ARCH_x86" tcpconnect tcpconnect.c

var (
	bootTimeSec uint64 // BPFで記録されるtimestampはboot時からのnsecなので
)

func main() {

	bootTimeSec, _ = host.BootTime()

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
	kp1, err := link.Kprobe("tcp_finish_connect", bpfObjs.KprobeTcpFinishConnect, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp1.Close()
	kp2, err := link.Kprobe("tcp_set_state", bpfObjs.KprobeTcpSetState, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp2.Close()
	kp3, err := link.Kprobe("tcp_sendmsg", bpfObjs.KprobeTcpSendmsg, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp3.Close()
	krp1, err := link.Kretprobe("tcp_sendmsg", bpfObjs.KretprobeTcpSendmsg, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer krp1.Close()
	kp4, err := link.Kprobe("tcp_close", bpfObjs.KprobeTcpClose, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp4.Close()

	// Print the contents of the BPF hash map (source IP address -> packet count).
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s, err := formatMapContents(&bpfObjs)
		if err != nil {
			log.Printf("Error reading map: %s", err)
			continue
		}
		log.Printf("Map contents:\n%s", s)
	}

}

func formatMapContents(o *tcpconnectObjects) (string, error) {
	var (
		sb  strings.Builder
		key tcpconnectConnTupleT
		val tcpconnectConnStatsTsT
	)

	cm := o.ConnStats
	tm := o.TcpStats
	iter := cm.Iterate()

	for iter.Next(&key, &val) {
		saddr := formatIPv4Address(key.SaddrL)
		daddr := formatIPv4Address(key.DaddrL)

		var rtt uint32
		tm.Lookup(&key, &rtt)

		sb.WriteString(
			fmt.Sprintf("\tPID:%d\t%s\t%s:%d => %s:%d RTT: %dnsec\n",
				key.Pid,
				formatTimestamp(val.Timestamp),
				saddr,
				key.Sport,
				daddr,
				key.Dport,
				rtt,
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
	t := time.Unix(int64(bootTimeSec), int64(ts))
	return t.Format(time.RFC3339Nano)
}
