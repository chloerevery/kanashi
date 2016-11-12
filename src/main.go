package main

import (
	"database/sql"
	"fmt"
	"math/rand"
	"strconv"
	"sync"
	"time"

	"kanashi/src/analyzer"
	database "kanashi/src/db"

	//"analyzer"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"

	"github.com/mattn/go-sqlite3"
)

const (
	pcapFileSrc = "../testdata/test_pcap.pcap"

	SECOND_FRAC = 10
)

func init() {
	rand.Seed(time.Now().UTC().UnixNano())
}

func main() {

	// Register database driver.
	var DB_DRIVER string
	sql.Register(DB_DRIVER, &sqlite3.SQLiteDriver{})

	// Open database connection.
	db, err := sql.Open(DB_DRIVER, "mysqlite_3")
	if err != nil {
		panic(err)
	}
	if db == nil {
		panic("db nil")
	}
	defer db.Close()

	// Create table to store packet info and decisions.
	database.CreateTable(db)

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

	var count int

	for packet := range packetSource.Packets() {
		count++
		for _, packetLayer := range packet.Layers() {
			result := analyzer.PeelLayer(packetLayer)

			if result == analyzer.MALICIOUS {
				err := logPacketAsMalicious(packet)
				if err != nil {
					panic(err)
				}

				break
			}

			err := logPacketInfo(packet, result, db)
			if err != nil {
				panic(err)
			}

			err = sendPacketThru(packet)
			if err != nil {
				panic(err)
			}
		}

		// FOR STATIC PCAP TESTING PURPOSES.
		// Generates a random sleep duration between (1/(SECOND_FRAC+1)) and 1s.
		sleepDuration := time.Second / time.Duration(rand.Intn(SECOND_FRAC)+1)
		time.Sleep(sleepDuration)
		fmt.Println("count:", count)
		fmt.Println("CONTENTS OF DATABASE", database.ReadItem(db))
	}
}

var count = 1

// Writes packet metadata to database.
func logPacketInfo(packet gopacket.Packet, result string, db *sql.DB) error {

	fmt.Println("count:", count)
	item := &database.TestItem{
		MAC:               "TEST MAC",
		Compromised:       "false",
		TimeClassifiedUTC: "0",
		Description:       result,
		Action:            "TEST ACTION",
		Success:           "TEST SUCCESS",
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
