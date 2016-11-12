package analyzer

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// PeelLayers takes in a packet with a non-zero number of "layers" and iterates through each layer, collecting data.
func PeelLayers(packet gopacket.Packet) {
	/*
		Things to look for:
		-DNS requests: read the IP address of every DNS destination.
	*/

	for _, onionLayer := range packet.Layers() {

		switch onionLayer.LayerType() {
		case layers.LayerTypeTCP:
			fmt.Println("This is a TCP packet!")
			// Get actual TCP data from this layer
			tcp, _ := onionLayer.(*layers.TCP)

			// Decode a TCP header and its payload (CHLOE: What does this do?)
			// TODO: Determine if below code is needed.
			// tcpP := gopacket.NewPacket(packet, layers.LayerTypeTCP, gopacket.Default)

			fmt.Printf("TCP: From src port %d to dst port %d\n", tcp.SrcPort, tcp.DstPort)
		case layers.LayerTypeIPv4:
			fmt.Println("This is an ipv4 packet!")
			// Get actual IP header + data from this layer
			ip, _ := onionLayer.(*layers.IPv4)

			// Decode an IPv4 header and everything it contains (CHLOE: What does this do?)
			// TODO: Determine if below code is needed.
			// ipP := gopacket.NewPacket(packet, layers.LayerTypeIPv4, gopacket.Default)

			fmt.Printf("IPv4: From src ip %d to dst ip %d\n", ip.SrcIP, ip.DstIP)
		case layers.LayerTypeIPv6:
			fmt.Println("This is an ipv6 packet!")
			// Get actual IP header + data from this layer
			ip, _ := onionLayer.(*layers.IPv6)

			// Decode an IPv6 header and everything it contains (CHLOE: What does this do?)
			// TODO: Determine if below code is needed.
			// ipP := gopacket.NewPacket(packet, layers.LayerTypeIPv6, gopacket.Default)

			fmt.Printf("IPv6: From src ip %d to dst ip %d\n", ip.SrcIP, ip.DstIP)
		}

	}

	// TODO: Get data from other layers.
}
