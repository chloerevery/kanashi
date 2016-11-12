package main

import (
	"analyzer"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {
	// Read packets in via a PacketSource:
	// 1. Construct an object that implements the PacketDataSource interface.
	// 2. Once you have a PacketDataSource, you can pass it into NewPacketSource, along with a Decoder of your choice, to create a PacketSource.

	// Read data from a pcap file:
	if handle, err := pcap.OpenOffline("../../testdata/test_pcap.pcap"); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType()) // construct packetSource using pcap or pfring
		for packet := range packetSource.Packets() {
			// Packets fn returns a channel, then asynchronously writes new packets into that channel, closing the channel if the packetSource hits an end-of-file.
			analyzer.peelLayers(packet) // do something with each packet
		}
	}
}
