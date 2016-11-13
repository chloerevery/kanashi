package main

import (
	"database/sql"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"math/rand"
	"net"
	"strconv"
	"sync"
	"time"

	"kanashi/src/analyzer"
	"kanashi/src/live"

	database "kanashi/src/db"
)

var (
	Live = flag.Bool("live", false, "read real data")
	Intf = flag.String("intf", "eth0", "interface to monitor")
)

const (
	pcapFileSrc = "../testdata/test_pcap.pcap"

	SECOND_FRAC = 10
)

func init() {
	rand.Seed(time.Now().UTC().UnixNano())
}

func main() {
	flag.Parse()
	DB_DRIVER := database.CreateAndRegisterDriver()

	// Open database connection.
	db, err := sql.Open(DB_DRIVER, "mysqlite_3")

	// Empty database.
	// TODO: Make this less hacky.
	database.DropTable(db)

	if err != nil {
		panic(err)
	}
	if db == nil {
		panic("db nil")
	}
	defer db.Close()

	// Create table to store packet info and decisions.
	database.CreateTable(db)

	fmt.Println("CONTENTS OF DATABASE (SHOULD BE EMPTY)", database.ReadItem(db))
	// Initialize traffic analysis struct to check for destination IP spikes.
	uniqueDestIps := &analyzer.UniqueDestIps{
		Mutex:        &sync.Mutex{},
		IPs:          make(map[string]analyzer.Empty),
		LastSecCount: -1,
	}
	analyzer.SetDestIPsTracker(uniqueDestIps)

	// Read data from a pcap file.
	var handle *pcap.Handle
	if *Live {
		handle, err = live.InitInterface(*Intf)
	} else {
		handle, err = pcap.OpenOffline(pcapFileSrc)
	}
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	// Construct packetSource using pcap file.
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	var count int

	var result *analyzer.Result

	for packet := range packetSource.Packets() {
		analyzer.PacketSrcIP = nil
		analyzer.PacketDstIP = nil
		count++
		for _, packetLayer := range packet.Layers() {
			result, analyzer.PacketDstIP, analyzer.PacketSrcIP = analyzer.PeelLayer(packetLayer)

			if result.Compromised == "True" {
				err := logPacketAsMalicious(packet)
				if err != nil {
					panic(err)
				}
				break
			}

		}

		fmt.Printf("%+v\n", analyzer.PacketSrcIP)

		err := logPacketInfo(packet, result, analyzer.PacketDstIP, analyzer.PacketSrcIP, db)
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
		//fmt.Println("count:", count)
		//fmt.Println("CONTENTS OF DATABASE", database.ReadItem(db))
	}

	return
}

var count = 1

// Writes packet metadata to database.
func logPacketInfo(packet gopacket.Packet, result *analyzer.Result, packetDstIP, packetSrcIP net.IP, db *sql.DB) error {

	//fmt.Println("count:", count)
	item := &database.TestItem{
		DstIP:             packetDstIP.String(),
		SrcIP:             packetSrcIP.String(),
		Compromised:       result.Compromised,
		TimeClassifiedUTC: time.Now().Format(time.RFC3339),
		Description:       result.Reason,
		Action:            result.Action,
		Success:           result.Success,
		PacketID:          strconv.Itoa(count),
	}

	count++

	err := database.StoreItem(db, *item)
	if err != nil {
		return err
	}

	return nil
}

func logPacketAsMalicious(packet gopacket.Packet) error {
	// TODO: Grab the first param, to-contain packet info.

	//fmt.Printf("REJECTED PACKET: %+v\n", packet)

	// info = "packet was bad"

	// TODO: Hit analytics with this info.
	return nil
}

func sendPacketThru(packet gopacket.Packet) error {
	// TODO: Send packet to its destination.
	//fmt.Printf("SENDING PACKET: %+v\n", packet)
	return nil
}
