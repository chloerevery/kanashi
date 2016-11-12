package analyzer

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"net"
	"sync"
	"time"
)

var DestIPs *UniqueDestIps

const (
	SUSPICIOUS_DEST_IP_INCREASE_THRESHOLD = 200
	MALICIOUS                             = "malicious"
	SAFE                                  = "safe"
)

type Empty struct{}

type UniqueDestIps struct {
	m            *sync.Mutex
	ips          map[string]Empty
	lastSecCount int
}

func SetDestIPsTracker(uniqueDestIps *UniqueDestIps) {
	DestIPs = &UniqueDestIps{
		m:            &sync.Mutex{},
		ips:          make(map[string]Empty),
		lastSecCount: -1,
	}
	DestIPs.RunUniqueDestIpSync()
}

func NewUniqueDestIps() *UniqueDestIps {
	return &UniqueDestIps{m: &sync.Mutex{}}
}

// PeelLayers takes in a packet with a non-zero number of "layers" and iterates through each layer, collecting data.
func PeelLayer(onionLayer gopacket.Layer) string {

	switch onionLayer.LayerType() {
	case layers.LayerTypeTCP:

		// Get actual TCP data from this layer
		tcp, _ := onionLayer.(*layers.TCP)

		fmt.Printf("TCP: From src port %d to dst port %d\n", tcp.SrcPort, tcp.DstPort)

		// If the request is coming from the outside world, we care about this check.
		// TODO: Only perform the below check if request is incoming and not from in-network.
		// if tcp.DstPort == 22 || tcp.DstPort == 23 {

		// 	fmt.Println("This TCP packet is malicious.")
		// 	return MALICIOUS // TODO: Return packet + device information.
		// }

	case layers.LayerTypeIPv4:
		fmt.Println("This is an ipv4 packet!")
		// Get actual IP header + data from this layer
		ip, _ := onionLayer.(*layers.IPv4)

		// CHECK IF PACKET IS BEING SENT TO A MALICIOUS DESTINATION.
		fmt.Printf("SrcIP: %+v *** DstIP: %+v\n", ip.SrcIP, ip.DstIP)
		for _, maliciousIP := range maliciousIPs {
			if ip.DstIP.String() == maliciousIP {
				fmt.Println("Packet being sent to a malicious destination...")
			}
		}

		// Note: Chloe would like someone to confirm that these are the correct values.
		ipOK := net.ParseIP("192.168.0.0")
		ipOKMask := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}

		IpNetOK := &net.IPNet{
			IP:   ipOK,     // network number
			Mask: ipOKMask, // network mask
		}

		IpMalicious := IpNetOK.Contains(ip.SrcIP)

		if IpMalicious {
			fmt.Println("This IPv4 packet is malicious.")
			return MALICIOUS // TODO: Return info about packet.
		}

		fmt.Printf("IPv4: From src ip %d to dst ip %d\n", ip.SrcIP, ip.DstIP)

		fmt.Println("DestIPs.ips", DestIPs.ips)
		fmt.Println("DestIPs.lastSecCount", DestIPs.lastSecCount)

		// When we receive a packet, add the dest ip to the set of unique dest ips.
		if _, exists := DestIPs.ips[ip.DstIP.String()]; !exists {
			DestIPs.m.Lock()
			DestIPs.ips[ip.DstIP.String()] = Empty{}
			DestIPs.m.Unlock()
		}

	case layers.LayerTypeUDP:
		// TODO: Do we want to do any validation in this layer?
		// fmt.Println("This is a UDP packet!")

		// Get UDP packet data from this layer.
		// udp, _ := onionLayer.(*layers.UDP)

		// fmt.Printf("UDP: From src port %d to dst port %d\n", udp.SrcPort, udp.DstPort)
		// TODO: UDP

	}

	return SAFE

}

// Runs DestIps sync every second and on startup.
func (uDestIps *UniqueDestIps) RunUniqueDestIpSync() error {
	fmt.Println("Starting UniqueDestIps goroutine.")

	go func() {
		for {
			start := time.Now()
			fmt.Println("Started UniqueDestIps sync.")

			result := uDestIps.checkAndUpdateUniqueDestIps()

			fmt.Println("result of checkAndUpdateUniqueDestIps:", result)
			// TODO: Do something if result is MALICIOUS.

			fmt.Println("Finished checkAndUpdateUniqueDestIps.", "duration", time.Since(start).Seconds())
			time.Sleep(time.Second)
		}
	}()

	return nil
}

// syncUniqueDestIps checks UniqueDestIps for suspicious patterns and updates UniqueDestIps with new data.
func (uDestIps *UniqueDestIps) checkAndUpdateUniqueDestIps() string {

	uDestIps.m.Lock()
	lastSecCount := uDestIps.lastSecCount
	ips := uDestIps.ips
	uDestIps.m.Unlock()

	if lastSecCount != -1 && lastSecCount != 0 {

		percentIncrease := (len(ips) - lastSecCount) / lastSecCount // Is this integer division? Is that bad?

		if percentIncrease > SUSPICIOUS_DEST_IP_INCREASE_THRESHOLD {
			return MALICIOUS // TODO: return packet + device information. // Todo: Implement different response codes for this check, as it doesn't relate to a single packet.
		}
	}

	// Update uDestIps.lastSecCount and clear out uDestIps.ips
	uDestIps.m.Lock()

	uDestIps.lastSecCount = len(ips)
	uDestIps.ips = make(map[string]Empty)
	fmt.Println("NEW DestIPs.ips", uDestIps.ips)
	fmt.Println("NEW DestIPs.lastSecCount", uDestIps.lastSecCount)

	uDestIps.m.Unlock()

	return SAFE // Todo: Implement different response codes for this check, as it doesn't relate to a single packet.
}
