package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

type stringSlice []string

func (i *stringSlice) String() string {
	return fmt.Sprint(*i)
}

func (i *stringSlice) Set(value string) error {
	*i = append(*i, value)
	return nil
}

var (
	ifaces   stringSlice
	filter   = flag.String("f", "", "BPF фильтр для захвата пакетов")
	snaplen  = flag.Int("s", 1024, "Максимальный размер пакета для захвата")
	promisc  = flag.Bool("p", false, "Включить режим promiscuous")
	timeoutT = flag.Int("t", 0, "Таймаут захвата пакетов в секундах")
	saveDir  = flag.String("d", ".", "Директория для сохранения pcap файлов")
)

func init() {
	flag.Var(&ifaces, "i", "Интерфейсы для захвата пакетов, можно указать несколько")
	flag.Parse()
}

func main() {
	if len(ifaces) == 0 {
		log.Fatal("Укажите один или несколько интерфейсов с помощью --i параметра")
	}

	validateSaveDir()

	var wg sync.WaitGroup
	shutdownChan := make(chan struct{})

	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		<-c
		log.Println("Получен сигнал завершения.")
		close(shutdownChan)
	}()

	for _, iface := range ifaces {
		wg.Add(1)
		go func(currentIface string) {
			defer wg.Done()
			capturePacketsOnInterface(currentIface, shutdownChan)
		}(iface)
	}

	wg.Wait()
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

func capturePacketsOnInterface(iface string, shutdownChan <-chan struct{}) {
	netIP := getNetIP(iface)
	device := findDevice(netIP)

	validateSaveDir()

	timeout := getTimeout()
	handle := openPcapHandle(device, timeout)

	applyFilter(handle)

	log.Printf("Прослушивается интерфейс: %s, IP: %s", iface, netIP)

	pkgsrc := gopacket.NewPacketSource(handle, handle.LinkType())
	packetBuffer := make([]gopacket.Packet, 0)

CaptureLoop:
	for {
		select {
		case packet, ok := <-pkgsrc.Packets():
			if !ok {
				break CaptureLoop
			}
			packetBuffer = append(packetBuffer, packet)
		case <-shutdownChan:
			break CaptureLoop
		}
	}
	savePcapFile(iface, &packetBuffer, handle)

}

func getNetIP(iface string) net.IP {
	netName, err := net.InterfaceByName(iface)
	if err != nil {
		log.Fatalf("InterfaceByName: %v: %v", err, iface)
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
			return ip
		}
	}

	log.Fatalf("Не найден IPv4 адрес для интерфейса %v", iface)
	return nil
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

	log.Fatalf("Не найден интерфейс %v", ifaces)
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
		log.Println("применяется фильтр: ", *filter)
		err := handle.SetBPFFilter(*filter)
		if err != nil {
			log.Fatal(err)
		}
	}
}

func savePcapFile(iface string, packetBuffer *[]gopacket.Packet, handle *pcap.Handle) {
	fileName := fmt.Sprintf("%s_%s.pcap", iface, time.Now().Format("2006-01-02_15-04-05"))
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

	pcapw := pcapgo.NewWriter(f)
	if err := pcapw.WriteFileHeader(uint32(*snaplen), handle.LinkType()); err != nil {
		log.Fatalf("WriteFileHeader: %v", err)
	}

	for _, packet := range *packetBuffer {
		if err := pcapw.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
			log.Fatalf("pcap.WritePacket(): %v", err)
		}
	}

	handle.Close()

	log.Printf("pcap файл создан по пути: %s", absFilePath)
}

func getTimeout() time.Duration {
	if *timeoutT == 0 {
		return -1
	}
	return time.Duration(*timeoutT) * time.Second
}
