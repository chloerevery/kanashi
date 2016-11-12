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

// PeelLayers takes in a packet with a non-zero number of "layers" and iterates through each layer, collecting data.
func PeelLayers(packet gopacket.Packet) {

	for _, onionLayer := range packet.Layers() {

		switch onionLayer.LayerType() {
		case layers.LayerTypeTCP:
			// fmt.Println("This is a TCP packet!")
			// Get actual TCP data from this layer
			// tcp, _ := onionLayer.(*layers.TCP)

			// fmt.Printf("TCP: From src port %d to dst port %d\n", tcp.SrcPort, tcp.DstPort)
		case layers.LayerTypeIPv4:
			fmt.Println("This is an ipv4 packet!")
			// Get actual IP header + data from this layer
			ip, _ := onionLayer.(*layers.IPv4)

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
				dropPacket()
				logDroppedPacket()
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
			// fmt.Println("This is a UDP packet!")

			// Get UDP packet data from this layer.
			// udp, _ := onionLayer.(*layers.UDP)

			// fmt.Printf("UDP: From src port %d to dst port %d\n", udp.SrcPort, udp.DstPort)
			// TODO: UDP

		}

		// TODO: Get data from other layers.
	}
}

// TODO: Implement
func dropPacket() {

}

// TODO: Implement
func logDroppedPacket() {

}

func NewUniqueDestIps() *UniqueDestIps {
	return &UniqueDestIps{m: &sync.Mutex{}}
}

// Runs DestIps sync every second and on startup.
func (uDestIps *UniqueDestIps) RunUniqueDestIpSync() error {
	fmt.Println("Starting UniqueDestIps goroutine.")

	go func() {
		for {
			start := time.Now()
			fmt.Println("Started UniqueDestIps sync.")

			err := uDestIps.checkAndUpdateUniqueDestIps()
			if err != nil {
				fmt.Println("Error during checkAndUpdateUniqueDestIps:", err)
			}
			fmt.Println("Finished checkAndUpdateUniqueDestIps.", "duration", time.Since(start).Seconds())
			time.Sleep(time.Second)
		}
	}()

	return nil
}

// syncUniqueDestIps checks UniqueDestIps for suspicious patterns and updates UniqueDestIps with new data.
func (uDestIps *UniqueDestIps) checkAndUpdateUniqueDestIps() error {

	uDestIps.m.Lock()
	lastSecCount := uDestIps.lastSecCount
	ips := uDestIps.ips
	uDestIps.m.Unlock()

	if lastSecCount != -1 && lastSecCount != 0 {

		percentIncrease := (len(ips) - lastSecCount) / lastSecCount // Is this integer division? Is that bad?

		if percentIncrease > SUSPICIOUS_DEST_IP_INCREASE_THRESHOLD {
			sendNoMorePacketsFromThisIP()
			return nil
		}
	}

	// Update uDestIps.lastSecCount and clear out uDestIps.ips
	uDestIps.m.Lock()

	uDestIps.lastSecCount = len(ips)
	uDestIps.ips = make(map[string]Empty)
	fmt.Println("NEW DestIPs.ips", uDestIps.ips)
	fmt.Println("NEW DestIPs.lastSecCount", uDestIps.lastSecCount)

	uDestIps.m.Unlock()

	return nil
}

// TODO: Implement, and check with JR if this is what we want to do in this case.
func sendNoMorePacketsFromThisIP() {

}
