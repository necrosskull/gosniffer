package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

var (
	iface    = flag.String("i", "", "Network interface to capture packets on")
	filter   = flag.String("f", "", "BPF filter for capture")
	snaplen  = flag.Int("s", 1024, "Maximum size to read for each packet")
	promisc  = flag.Bool("p", false, "Enable promiscuous mode")
	timeoutT = flag.Int("t", 30, "Connection Timeout in seconds")
	saveDir  = flag.String("d", ".", "Directory to save pcap files")
)

var packetBuffer []gopacket.Packet

var device string = ""

func main() {
	flag.Parse()

	var timeout time.Duration = time.Duration(*timeoutT) * time.Second
	if *iface == "" {
		log.Fatal("Please provide a network interface to capture packets on using the --i flag")
	}

	netName, err := net.InterfaceByName(*iface)
	if err != nil {
		log.Fatalf("InterfaceByName: %v", err)
	}
	netAddrs, err := netName.Addrs()
	if err != nil {
		log.Fatalf("InterfaceAddrs: %v", err)
	}
	netIP, _, err := net.ParseCIDR(netAddrs[1].String())
	if err != nil {
		log.Fatalf("ParseCIDR: %v", err)
	}

	fmt.Printf("Interface: %v\n", netIP)

	allInterfaces, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatalf("FindAllDevs: %v", err)
	}

	for _, pcapiface := range allInterfaces {

		if len(pcapiface.Addresses) < 1 {
			continue
		}

		addr := pcapiface.Addresses[0].IP

		if addr.Equal(netIP) {
			device = pcapiface.Name
			break
		}

	}

	if device == "" {
		log.Fatalf("Could not find device with Name %v", *iface)

	}

	handle, err := pcap.OpenLive(device, int32(*snaplen), *promisc, timeout)
	if err != nil {
		log.Fatalf("OpenLive: %v", err)
	}
	defer handle.Close()

	if *filter != "" {
		log.Println("applying filter ", *filter)
		err := handle.SetBPFFilter(*filter)
		if err != nil {
			log.Fatal(err)

		}
	}

	pkgsrc := gopacket.NewPacketSource(handle, handle.LinkType())

	sigs := make(chan os.Signal, 1)

	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigs
		fileName := fmt.Sprintf("%s_%s.pcap", *iface, time.Now().Format("2006-01-02_15-04-05"))
		filePath := filepath.Join(*saveDir, fileName)
		f, err := os.Create(filePath)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()

		pcapw := pcapgo.NewWriter(f)
		if err := pcapw.WriteFileHeader(uint32(*snaplen), handle.LinkType()); err != nil {
			log.Fatalf("WriteFileHeader: %v", err)
		}

		for _, packet := range packetBuffer {
			if err := pcapw.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
				log.Fatalf("pcap.WritePacket(): %v", err)
			}
		}

		fmt.Printf("Packets written to file: %s. Exiting...\n", filePath)
		os.Exit(0)
	}()

	for packet := range pkgsrc.Packets() {
		packetBuffer = append(packetBuffer, packet)
	}
}
