package main

import (
	"fmt"
	"log"
	"strings"
	"time"

	"flag"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"os"
	"sort"
)

var device string
var dport int
var cmd_len int
var top int

func init() {
	flag.StringVar(&device, "i", "", "设备")
	flag.IntVar(&dport, "dport", 80, "目的端口")
	flag.IntVar(&cmd_len, "l", 20, "命令长度")
	flag.IntVar(&top, "t", 10, "top n")
	flag.Parse()
	if device == "" {
		flag.Usage()
		os.Exit(2)
	}
}

var (
	snapshotLen int32 = 1024
	promiscuous bool  = false
	err         error
	timeout     time.Duration = 30 * time.Second
	handle      *pcap.Handle
	counter     map[string]int64
)

func main() {
	// Open device
	handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	counter = make(map[string]int64)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	go print_counter()
	for packet := range packetSource.Packets() {
		printPacketInfo(packet)
	}
}

func Split(s, sep string) []string {
	return strings.Split(s, sep)
}

func print_counter() {
	now := time.Now().Local()
	var diff int64
	for {
		diff = 60 - (now.Unix() % 60)
		select {
		case now = <-time.After(time.Duration(diff) * time.Second):
			// fmt.Println(counter)
			type kv struct {
				Key   string
				Value int64
			}

			var ss []kv
			for k, v := range counter {
				ss = append(ss, kv{k, v})
			}

			sort.Slice(ss, func(i, j int) bool {
				return ss[i].Value > ss[j].Value
			})

			fmt.Println(time.Now().Format("2006-01-02 15:04:05"))
			for i, kv := range ss {
				if i >= top {
					break
				}
				fmt.Printf("%s, %d\n", kv.Key, kv.Value)
			}
			counter = make(map[string]int64)

		}
		now = time.Now().Local()
	}

}

func printPacketInfo(packet gopacket.Packet) {

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)

		if tcp.DstPort == layers.TCPPort(dport) {

			applicationLayer := packet.ApplicationLayer()
			if applicationLayer != nil {
				str := string(applicationLayer.Payload()[:])
				arr := Split(str, "\r\n")
				if len(arr) >= 5 {
					cmd := arr[2]
					key := arr[4]
					l := len(key)
					if l >= cmd_len {
						l = cmd_len
					}
					redis_cmd := cmd + " " + key[:l]
					if v, ok := counter[redis_cmd]; ok {
						counter[redis_cmd] = v + 1
					} else {
						counter[redis_cmd] = 1
					}
				}

			}
		}

	}

}
