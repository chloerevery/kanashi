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
			// Packets fn returns a channel, then asynchronously writes new packets into that channel, closing the channel if the packetSource hits an end-of-file.
			handlePacket(packet) // do something with each packet
		}
	}
}

// handlePacket takes in a packet with a non-zero number of "layers".
func handlePacket(packet gopacket.Packet) {
	// Sample: Get the TCP layer from this packet
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		fmt.Println("This is a TCP packet!")
		// Get actual TCP data from this layer
		tcp, _ := tcpLayer.(*layers.TCP)
		fmt.Printf("From src port %d to dst port %d\n", tcp.SrcPort, tcp.DstPort)
	}
	// TODO: Get data from other layers.
}
