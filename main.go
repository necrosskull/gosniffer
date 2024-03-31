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

func init() {
	flag.Parse()
}

func main() {
	if *iface == "" {
		log.Fatal("Укажите имя интерфейса --i параметр")
	}

	netIP := getNetIP()
	device := findDevice(netIP)

	validateSaveDir()

	timeout := getTimeout()
	handle := openPcapHandle(device, timeout)

	applyFilter(handle)

	log.Printf("Прослушивается Интерфейс: %s, IP: %s", *iface, netIP)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go handleSignal(sigs, handle)

	pkgsrc := gopacket.NewPacketSource(handle, handle.LinkType())
	capturePackets(pkgsrc)
}

func validateSaveDir() {
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
}

func getTimeout() time.Duration {
	if *timeoutT == 0 {
		return -1
	}
	return time.Duration(*timeoutT) * time.Second
}

func getNetIP() net.IP {
	var netIP net.IP

	netName, err := net.InterfaceByName(*iface)
	if err != nil {
		log.Fatalf("InterfaceByName: %v: %v", err, *iface)
	}
	netAddrs, err := netName.Addrs()
	if err != nil {
		log.Fatalf("InterfaceAddrs: %v", err)
	}

	for _, addr := range netAddrs {
		ip, _, err := net.ParseCIDR(addr.String())
		if err != nil {
			continue
		}

		if ip.To4() != nil {
			netIP = ip
			break
		}
	}

	if netIP == nil {
		log.Fatalf("Не найден IPv4 адрес для интерфейса %v", *iface)
	}

	return netIP
}

func findDevice(netIP net.IP) string {
	allInterfaces, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatalf("FindAllDevs: %v", err)
	}

	for _, pcapiface := range allInterfaces {

		if len(pcapiface.Addresses) < 1 {
			continue
		}

		addrs := pcapiface.Addresses

		for _, addr := range addrs {
			if addr.IP.To4() != nil && addr.IP.Equal(netIP) {
				return pcapiface.Name
			}
		}
	}

	log.Fatalf("Не найден интерфейс %v", *iface)
	return ""
}

func openPcapHandle(device string, timeout time.Duration) *pcap.Handle {
	handle, err := pcap.OpenLive(device, int32(*snaplen), *promisc, timeout)
	if err != nil {
		log.Fatalf("OpenLive: %v", err)
	}
	return handle
}

func applyFilter(handle *pcap.Handle) {
	if *filter != "" {
		log.Println("applying filter ", *filter)
		err := handle.SetBPFFilter(*filter)
		if err != nil {
			log.Fatal(err)
		}
	}
}

func handleSignal(sigs chan os.Signal, handle *pcap.Handle) {
	<-sigs
	savePcapFile(handle)
	os.Exit(0)
}

func savePcapFile(handle *pcap.Handle) {
	fileName := fmt.Sprintf("%s_%s.pcap", *iface, time.Now().Format("2006-01-02_15-04-05"))
	filePath := filepath.Join(*saveDir, fileName)

	absFilePath, err := filepath.Abs(filePath)
	if err != nil {
		log.Fatalf("Failed to get absolute path: %v", err)
	}

	f, err := os.Create(filePath)
	if err != nil {
		log.Fatal(err)
	}

	defer f.Close()
	defer handle.Close()

	pcapw := pcapgo.NewWriter(f)
	if err := pcapw.WriteFileHeader(uint32(*snaplen), handle.LinkType()); err != nil {
		log.Fatalf("WriteFileHeader: %v", err)
	}

	for _, packet := range packetBuffer {
		if err := pcapw.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
			log.Fatalf("pcap.WritePacket(): %v", err)
		}
	}

	log.Printf("pcap файл создан по пути: %s", absFilePath)
}

func capturePackets(pkgsrc *gopacket.PacketSource) {
	for packet := range pkgsrc.Packets() {
		packetBuffer = append(packetBuffer, packet)
	}
}
