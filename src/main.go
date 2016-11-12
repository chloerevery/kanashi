package main

import (
    "fmt"
    "math/rand"
    "sync"
	"time"
	
	"kanashi/src/analyzer"
	
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

const (
    pcapFileSrc = "../testdata/test_pcap.pcap"
    
    SECOND_FRAC = 10
)

func init() {
    rand.Seed(time.Now().UTC().UnixNano())
}

func main() {
    // Initialize traffic analysis struct to check for destination IP spikes.
	uniqueDestIps := &analyzer.UniqueDestIps{
		Mutex:        &sync.Mutex{},
		IPs:          make(map[string]analyzer.Empty),
		LastSecCount: -1,
	}
	analyzer.SetDestIPsTracker(uniqueDestIps)

	// Read data from a pcap file.
	handle, err := pcap.OpenOffline(pcapFileSrc)
	if err != nil {
		panic(err)
	}
	
	// Construct packetSource using pcap file.
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	
	for packet := range packetSource.Packets() {
		for _, packetLayer := range packet.Layers() {
			result := analyzer.PeelLayer(packetLayer)
			
			if result == analyzer.MALICIOUS {
			    err := logPacketAsMalicious(packet)
			    if err != nil {
			        panic(err)
			    }
			    
			    break
			}
		}
		
		err := logPacketInfo(packet)
		if err != nil {
		    panic(err)
		}
			
		err = sendPacketThru(packet)
		if err != nil {
		    panic(err)
		}

        // FOR STATIC PCAP TESTING PURPOSES.
        // Generates a random sleep duration between (1/(SECOND_FRAC+1)) and 1s.
        sleepDuration := time.Second / time.Duration(rand.Intn(SECOND_FRAC)+1)
		time.Sleep(sleepDuration)
	}
}

// Gens packet info, timestamp, success of packet drop, additional metadata..
func generatePacketInfo(packet gopacket.Packet) (string, error) {
    return "packet was good", nil
}

func logPacketInfo(packet gopacket.Packet) error {
    // TODO: Grab the first param, to-contain packet info.
    _, err := generatePacketInfo(packet)
    if err != nil {
        return err
    }
    
    // TODO: Hit analytics with this info.
    return nil
}

func logPacketAsMalicious(packet gopacket.Packet) error {
    // TODO: Grab the first param, to-contain packet info.
    _, err := generatePacketInfo(packet)
    if err != nil {
        return err
    }
    
    fmt.Printf("REJECTED PACKET: %+v\n", packet)
    
    // info = "packet was bad"
    
    // TODO: Hit analytics with this info.
    return nil
}

func sendPacketThru(packet gopacket.Packet) error {
    // TODO: Send packet to its destination.
    fmt.Printf("SENDING PACKET: %+v\n", packet)
    return nil
}


