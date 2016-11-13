package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"analyzer"
	"live"

	database "db"
)

var (
	Live      = flag.Bool("live", false, "read real data")
	Intf      = flag.String("intf", "eth0", "interface to monitor")
	accountID = flag.String("accountID", "", "twilio account ID")
	authToken = flag.String("authToken", "", "twilio auth token")

	timeOfLastSMS = int64(0)
	oneMinuteNano = int64(60000000000)
)

const (
	pcapFileSrc = "../testdata/test_pcap.pcap"

	SECOND_FRAC = 10

	fromPhoneNumber = "+1 305-783-2802"
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
				sendSMSAlert(packet, result, analyzer.PacketDstIP, analyzer.PacketSrcIP)

				err = logPacketAsMalicious(packet)
				if err != nil {
					panic(err)
				}
				break
			}

		}

		fmt.Printf("%+v\n", analyzer.PacketSrcIP)

		// Log packet data.
		err := logPacketInfo(packet, result, analyzer.PacketDstIP, analyzer.PacketSrcIP, db)
		if err != nil {
			panic(err)
		}

		if result.Compromised == "False" {
			err = sendPacketThru(packet)
			if err != nil {
				panic(err)
			}
		}

		// FOR STATIC PCAP TESTING PURPOSES.
		// Generates a random sleep duration between (1/(SECOND_FRAC+1)) and 1s.
		sleepDuration := time.Second / time.Duration(rand.Intn(SECOND_FRAC)+1)
		time.Sleep(sleepDuration)
		//fmt.Println("count:", count)
		fmt.Println("CONTENTS OF DATABASE", database.ReadItem(db))
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

	fmt.Println("storing item", item)

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

func sendSMSAlert(packet gopacket.Packet, result *analyzer.Result, packetDstIP, packetSrcIP net.IP) error {
	timeStamp := time.Now().UTC()
	timeStampNanoseconds := timeStamp.UnixNano()

	if timeOfLastSMS == 0 {
		timeOfLastSMS = timeStampNanoseconds
	} else {
		if (timeStampNanoseconds - timeOfLastSMS) < oneMinuteNano {
			// Hasn't been a minute since last alert.
			return errors.New("text failed.. hasn't been a minute since last alert")
		}
		timeOfLastSMS = timeStampNanoseconds
	}

	urlStr := "https://api.twilio.com/2010-04-01/Accounts/" + *accountID + "/Messages.json"

	message := "KANASHI: MALICIOUS ACTIVITY RECORDED\n"
	message = message + "Successfully filtered packet.\n\n"
	message = message + "PROPERTIES:\n"
	message = message + "SrcIP: " + packetSrcIP.String() + "\n"
	message = message + "DstIP: " + packetDstIP.String() + "\n"
	message = message + "TimestampUTC: " + timeStamp.String() + "\n"
	message = message + "Description: " + result.Reason + "\n\n"
	message = message + "Take appropriate measures to ensure that " + packetSrcIP.String() + " is secured."

	// Build out the data for our message
	v := url.Values{}
	v.Set("To", "+1 727-422-4360")
	v.Set("From", fromPhoneNumber)
	v.Set("Body", message)
	rb := *strings.NewReader(v.Encode())

	// Create client
	client := &http.Client{}

	req, _ := http.NewRequest("POST", urlStr, &rb)
	req.SetBasicAuth(*accountID, *authToken)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	// Make request
	resp, _ := client.Do(req)
	fmt.Println(resp.Status)

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		var data map[string]interface{}
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		err := json.Unmarshal(bodyBytes, &data)
		if err == nil {
			fmt.Println(data["sid"])
			return nil
		}
	} else {
		fmt.Println(resp.Status)
	}

	return nil
}
