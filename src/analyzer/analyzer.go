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

    // Check for malicious TCP.
	for _, onionLayer := range packet.Layers() {
        if onionLayer.LayerType() == layers.LayerTypeIPv4 {
            ip, _ := onionLayer.(*layers.IPv4)
            
            if ip.Protocol == layers.IPProtocolTCP {
                fmt.Println("Uses TCP as protocol!")
                fmt.Printf("SrcIP: %+v *** DstIP: %+v\n", ip.SrcIP, ip.DstIP)
                for _, maliciousIP := range maliciousIPs {
                    if ip.DstIP.String() == maliciousIP {
                        fmt.Println("SHIT SHIT SHIT")
                    }
                }
            }
        }
   }
}
