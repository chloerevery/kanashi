package main

import (
	"fmt"
    "math/rand"
	"time"
	
	"kanashi/src/analyzer"
	
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {

	rand.Seed(time.Now().UTC().UnixNano())

	uniqueDestIps := &analyzer.UniqueDestIps{}

	analyzer.SetDestIPsTracker(uniqueDestIps)

	// Read data from a pcap file:
	if handle, err := pcap.OpenOffline("../testdata/test_pcap.pcap"); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType()) // construct packetSource using pcap or pfring
		for packet := range packetSource.Packets() {
			// Packets fn returns a channel, then asynchronously writes new packets into that channel, closing the channel if the packetSource hits an end-of-file.
			for _, onionLayer := range packet.Layers() {
				result := analyzer.PeelLayer(onionLayer)

				fmt.Println("Result of packet inspection", result)
				// TODO:
				// Record (flat file or db write):
				// -the packet information
				// -a timestamp
				// -whether the packet drop was successful(?)

				// TODO:
				// If result is MALICIOUS, do not send packet.
				// If result is not malicious, send packet.

			}

			time.Sleep(time.Second / time.Duration(rand.Intn(10)+1))
		}
	}

}
