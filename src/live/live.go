package live

import (
	"flag"
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var (
	Intf = *flag.String("intf", "eth0", "interface to monitor")
)

func initInterface(intf string) (*pcap.Handle, error) {
	handle, err := pcap.OpenLive(intf, 65535, false, 10*time.Second)
	if err != nil {
		return nil, err
	}
	return handle, nil
}

func Process() {
	handle, err := initInterface(Intf)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range source.Packets() {
		fmt.Println(packet)
	}
}
