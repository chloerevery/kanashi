package live

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func InitInterface(intf string) (*pcap.Handle, error) {
	handle, err := pcap.OpenLive(intf, 65535, false, 10*time.Second)
	if err != nil {
		return nil, err
	}
	return handle, nil
}

func Process(intf string) {
	handle, err := InitInterface(intf)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range source.Packets() {
		fmt.Println(packet)
	}
}
