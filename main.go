package main

import (
	"analyzer"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"math/rand"
	"time"
)

func main() {

	rand.Seed(time.Now().UTC().UnixNano())

	uniqueDestIps := &analyzer.UniqueDestIps{}

	analyzer.SetDestIPsTracker(uniqueDestIps)

	// Read data from a pcap file:
	if handle, err := pcap.OpenOffline("testdata/test_pcap.pcap"); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType()) // construct packetSource using pcap or pfring
		for packet := range packetSource.Packets() {
			// Packets fn returns a channel, then asynchronously writes new packets into that channel, closing the channel if the packetSource hits an end-of-file.
			analyzer.PeelLayers(packet) // do something with each packet

			time.Sleep(time.Second / time.Duration(rand.Intn(10)+1))
		}
	}

}
