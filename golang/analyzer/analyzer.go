package analyzer

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	// Read packets in via a PacketSource:
	// 1. Construct an object that implements the PacketDataSource interface.
	// 2. Once you have a PacketDataSource, you can pass it into NewPacketSource, along with a Decoder of your choice, to create a PacketSource.

	// Read data from a pcap file:
	if handle, err := pcap.OpenOffline("/path/to/my/file"); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType()) // construct packetSource using pcap or pfring
		for packet := range packetSource.Packets() {
			decode(packet) // do something with each packet
		}
	}
}

// decode takes in packet data as a []byte and decodes it into a packet with a non-zero number of "layers".
func decode(myPacketData []byte) {
	// Decode a packet
	packet := gopacket.NewPacket(myPacketData, layers.LayerTypeEthernet, gopacket.Default)
	// Get the TCP layer from this packet
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		fmt.Println("This is a TCP packet!")
		// Get actual TCP data from this layer
		tcp, _ := tcpLayer.(*layers.TCP)
		fmt.Printf("From src port %d to dst port %d\n", tcp.SrcPort, tcp.DstPort)
	}
	// Iterate over all layers, printing out each layer type
	for _, layer := range packet.Layers() {
		// TODO: Decode each layer.
		fmt.Println("PACKET LAYER:", layer.LayerType())
	}
}
