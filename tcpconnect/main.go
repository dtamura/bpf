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

// ref: net/tcp_state.h
// https://elixir.bootlin.com/linux/latest/source/include/net/tcp_states.h
const (
	TCP_ESTABLISHED = iota
	TCP_SYN_SENT
	TCP_SYN_RECV
	TCP_FIN_WAIT1
	TCP_FIN_WAIT2
	TCP_TIME_WAIT
	TCP_CLOSE
	TCP_CLOSE_WAIT
	TCP_LAST_ACK
	TCP_LISTEN
	TCP_CLOSING
	TCP_NEW_SYN_RECV
	TCP_MAX_STATES
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
	// kp1, err := link.Kprobe("tcp_finish_connect", bpfObjs.KprobeTcpFinishConnect, nil)
	// if err != nil {
	// 	log.Fatalf("opening kprobe: %s", err)
	// }
	// defer kp1.Close()
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
	kp5, err := link.Kprobe("tcp_recvmsg", bpfObjs.KprobeTcpRecvmsg, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp5.Close()
	krp2, err := link.Kretprobe("tcp_recvmsg", bpfObjs.KretprobeTcpRecvmsg, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer krp2.Close()

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

		var tcpStats tcpconnectTcpStatsT
		tm.Lookup(&key, &tcpStats)

		var connStats tcpconnectConnStatsTsT
		cm.Lookup(&key, &connStats)

		sb.WriteString(
			fmt.Sprintf("\tPID:%d (%s)\t%s\t%s:%d => %s:%d (%s) RTT: %dnsec Send: %dbyte Recv: %dbyte\n",
				key.Pid,
				key.Comm,
				formatTimestamp(val.Timestamp),
				saddr,
				key.Sport,
				daddr,
				key.Dport,
				getTcpStateById(tcpStats.State),
				tcpStats.Rtt,
				connStats.SentBytes,
				connStats.RecvBytes,
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

func getTcpStateById(state uint16) string {
	switch state {
	case TCP_ESTABLISHED:
		return "ESTABLISHED"
	case TCP_SYN_SENT:
		return "SYN_SENT"
	case TCP_SYN_RECV:
		return "SYN_RECV"
	case TCP_FIN_WAIT1:
		return "FIN_WAIT1"
	case TCP_FIN_WAIT2:
		return "FIN_WAIT2"
	case TCP_TIME_WAIT:
		return "TIME_WAIT"
	case TCP_CLOSE:
		return "CLOSE"
	case TCP_CLOSE_WAIT:
		return "CLOSE_WAIT"
	case TCP_LAST_ACK:
		return "LAST_ACK"
	case TCP_LISTEN:
		return "LISTEN"
	case TCP_CLOSING:
		return "CLOSING"
	case TCP_NEW_SYN_RECV:
		return "NEW_SYN_RECV"
	case TCP_MAX_STATES:
		return "MAX_STATES"
	}
	return "UNKN"
}
