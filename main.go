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
	iface    = flag.String("i", "", "Интерфейс для захвата пакетов")
	filter   = flag.String("f", "", "BPF фильтр для захвата пакетов")
	snaplen  = flag.Int("s", 1024, "Максимальный размер пакета для захвата")
	promisc  = flag.Bool("p", false, "Включить режим promiscuous")
	timeoutT = flag.Int("t", 0, "Таймаут захвата пакетов в секундах")
	saveDir  = flag.String("d", ".", "Директория для сохранения pcap файлов")
)

var packetBuffer []gopacket.Packet

var device string = ""

func main() {
	flag.Parse()

	_, err := os.Stat(*saveDir)
	if os.IsNotExist(err) {
		errDir := os.MkdirAll(*saveDir, 0755)
		if errDir != nil {
			log.Fatal("Ошибка при создании папки: ", errDir)
			return
		}
		log.Printf("Директория %s создана", *saveDir)
	} else if err != nil {
		log.Fatal("Ошибка при проверке папки: ", err)
		return
	}

	var timeout time.Duration

	if *timeoutT == 0 {
		timeout = -1
	} else {
		timeout = time.Duration(*timeoutT) * time.Second
	}

	if *iface == "" {
		log.Fatal("Укажите имя интерфейса --i параметр")
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

	log.Printf("Прослушивается Интерфейс: %s, IP: %s", *iface, netIP)

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
		log.Fatalf("Не найден интерфейс %v", *iface)

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

		log.Printf("pcap файл создан по пути: %s", filePath)
		os.Exit(0)
	}()

	for packet := range pkgsrc.Packets() {
		packetBuffer = append(packetBuffer, packet)
	}
}
