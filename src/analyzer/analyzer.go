package analyzer

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	// Consts representing packet status after analysis.
	MALICIOUS = "malicious"
	SAFE      = "safe"

	// Percent increase in Unique DstIPs that will denote suspicious activity.
	SUSPICIOUS_DEST_IP_INCREASE_THRESHOLD = 200

	subnet = "192.168.1.0/24"
)

var (
	DestIPs *UniqueDestIps

	// Note: Please confirm that these are the correct values.
	ipOK     = net.ParseIP("192.168.0.0")
	ipOKMask = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}

	IpNetOK = &net.IPNet{
		IP:   ipOK,     // Network address.
		Mask: ipOKMask, // Network mask.
	}

	subnetIPNet *net.IPNet
	PacketSrcIP net.IP
	PacketDstIP net.IP
)

// Empty struct for existence map.
type Empty struct{}

// UniqueDestIps represents unique destination traffic in the last second.
type UniqueDestIps struct {
	Mutex        *sync.Mutex
	IPs          map[string]Empty
	LastSecCount int
}

// Result describes the result of a packet analysis.
type Result struct {
	Compromised string // Do we believe that packet indicates that a device is compromise
	Reason      string // If so, why do we think so?
	Action      string
	Success     string
}

func init() {
	_, ipnet, err := net.ParseCIDR(subnet)
	if err != nil {
		panic(err)
	}

	subnetIPNet = ipnet
}

// SetDestIPsTracker assigns a new UniqueDestIps struct for traffic analysis.
func SetDestIPsTracker(uniqueDestIps *UniqueDestIps) {
	DestIPs = uniqueDestIps
	DestIPs.RunUniqueDestIpSync()
}

// Handles a single layer of a gopacket.Packet.
func PeelLayer(onionLayer gopacket.Layer) (*Result, net.IP, net.IP) {
	// Act based on onionLayer.LayerType.
	switch onionLayer.LayerType() {
	case layers.LayerTypeIPv4:
		ip, _ := onionLayer.(*layers.IPv4)

		if string(ip.DstIP) == "111.222.33.44" {
			fmt.Println("SPOOFED SOURCE")
			PacketSrcIP = ip.SrcIP
			PacketDstIP = ip.DstIP
			return &Result{
				Compromised: "True",
				Reason:      "Spoofed Source IP",
				Action:      "",
				Success:     "",
			}, PacketDstIP, PacketSrcIP
		}

		if maliciousDstIP(ip.DstIP) {
			fmt.Println("MALICIOUS DESTINATION")
			PacketSrcIP = ip.SrcIP
			PacketDstIP = ip.DstIP
			return &Result{
				Compromised: "True",
				Reason:      "Malicious destination.",
				Action:      "",
				Success:     "",
			}, PacketDstIP, PacketSrcIP
		}

		logPacketDestination(ip.DstIP)

		PacketSrcIP = ip.SrcIP
		PacketDstIP = ip.DstIP

		// TODO: Do we want to do any validation in the TCP layer?
	case layers.LayerTypeTCP:
		tcp, _ := onionLayer.(*layers.TCP)

		// TODO: Only perform the below check if request is not from in-network.
		if PacketSrcIP != nil && !subnetIPNet.Contains(PacketSrcIP) {
			if tcp.DstPort == 22 || tcp.DstPort == 23 {
				// TODO: Return packet + device information.
				fmt.Println("PORT SCANNING DETECTED")
				return &Result{
					Compromised: "True",
					Reason:      "Port scanning detected",
				}, PacketDstIP, PacketSrcIP
			}
		}

		// TODO: Do we want to do any validation in the UDP layer?
	case layers.LayerTypeUDP:
		// udp, _ := onionLayer.(*layers.UDP)

	}

	return &Result{
		Compromised: "False",
		Reason:      "",
		Action:      "",
		Success:     "",
	}, PacketDstIP, PacketSrcIP

}

func maliciousDstIP(dstIP net.IP) bool {
	for _, maliciousIP := range maliciousIPs {
		if dstIP.String() == maliciousIP {
			return true
		}
	}
	return false
}

func spoofedSrcIP(srcIP net.IP) bool {
	return IpNetOK.Contains(srcIP)
}

// Add DstIP to DestIPs.ips if it is a unique IP within the last second.
func logPacketDestination(dstIP net.IP) {
	if _, exists := DestIPs.IPs[dstIP.String()]; !exists {
		DestIPs.Mutex.Lock()
		DestIPs.IPs[dstIP.String()] = Empty{}
		DestIPs.Mutex.Unlock()
	}
}

// Runs DestIps sync every second and on startup.
func (uDestIps *UniqueDestIps) RunUniqueDestIpSync() {
	fmt.Println("Starting UniqueDestIps monitoring.")

	go func() {
		for {
			result := uDestIps.checkAndUpdateUniqueDestIps()
			if result.Compromised == "True" {
				fmt.Println("TRAFFIC SPIKE")
			}

			time.Sleep(time.Second)
		}
	}()
}

// Checks UniqueDestIps for suspicious patterns and updates its fields.
func (uDestIps *UniqueDestIps) checkAndUpdateUniqueDestIps() Result {
	var result Result
	result.Compromised = "False"

	uDestIps.Mutex.Lock()
	lastSecCount := float64(uDestIps.LastSecCount)
	ips := uDestIps.IPs
	uDestIps.Mutex.Unlock()

	if lastSecCount != -1 && lastSecCount != 0 {
		trafficDifference := float64(len(ips)) - lastSecCount
		percentIncrease := (trafficDifference / lastSecCount) * 100

		if percentIncrease > SUSPICIOUS_DEST_IP_INCREASE_THRESHOLD {
			// TODO: return packet + device information.
			// TODO: Implement different response codes for this check.
			result.Compromised = "True"
		}
	}

	// Update uDestIps.lastSecCount and clear out uDestIps.ips
	uDestIps.Mutex.Lock()
	uDestIps.LastSecCount = len(ips)
	uDestIps.IPs = make(map[string]Empty)
	uDestIps.Mutex.Unlock()

	// TODO: Implement different response codes for this check.
	return result
}
