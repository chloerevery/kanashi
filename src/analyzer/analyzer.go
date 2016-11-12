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

			fmt.Printf("TCP: From src port %d to dst port %d\n", tcp.SrcPort, tcp.DstPort)
		case layers.LayerTypeIPv4:
			fmt.Println("This is an ipv4 packet!")
			// Get actual IP header + data from this layer
			ip, _ := onionLayer.(*layers.IPv4)

			fmt.Printf("IPv4: From src ip %d to dst ip %d\n", ip.SrcIP, ip.DstIP)
		case layers.LayerTypeUDP:
			fmt.Println("This is a UDP packet!")
			// Get actual IP header + data from this layer
			udp, _ := onionLayer.(*layers.UDP)

			fmt.Printf("UDP: From src port %d to dst port %d\n", udp.SrcPort, udp.DstPort)
			// TODO: UDP

		}

		// TODO: Get data from other layers.
	}
}
