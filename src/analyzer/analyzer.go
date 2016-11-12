package analyzer

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"net"
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

			fmt.Println("CHLOE, src ip:", ip.SrcIP)

			// Chloe would like someone to confirm that these are the correct values.
			ipOKMask := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
			ipOK := net.ParseIP("192.168.0.0")

			IpNetOK := &net.IPNet{
				IP:   ipOK,     // network number
				Mask: ipOKMask, // network mask
			}

			IpMalicious := IpNetOK.Contains(ip.SrcIP)

			fmt.Println("IS IP PACKET MALICIOUS?", IpMalicious)

			// If src IP is in range 192.168.0.0 - 192.168.1.16 (?) it's likely ok.

			fmt.Printf("IPv4: From src ip %d to dst ip %d\n", ip.SrcIP, ip.DstIP)
		case layers.LayerTypeUDP:
			fmt.Println("This is a UDP packet!")

			// Get UDP packet data from this layer.
			udp, _ := onionLayer.(*layers.UDP)

			fmt.Printf("UDP: From src port %d to dst port %d\n", udp.SrcPort, udp.DstPort)
			// TODO: UDP

		}

		// TODO: Get data from other layers.
	}
}
