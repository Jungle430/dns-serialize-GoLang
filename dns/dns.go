package dns

import (
	"bytes"
	"dns-serialize/config"
	"fmt"
	"net"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/olekukonko/tablewriter"
)

// 构建DNS请求
func BuildRequest(domain string, srcMac net.HardwareAddr, srcIP net.IP, DNSServerIP net.IP, srcPort int) ([]byte, error) {
	// DNS
	dnsLayer := &layers.DNS{
		ID:      config.GetUDPId(),
		QR:      false,
		OpCode:  layers.DNSOpCodeQuery,
		RD:      true,
		QDCount: 1,

		Questions: []layers.DNSQuestion{
			{
				Name:  []byte(domain),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
			},
		},
	}

	// UDP
	udpLayer := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(53),
	}

	// 计算属性
	udpLength, err := getUDPLength(dnsLayer)
	if err != nil {
		return nil, err
	}
	udpLayer.Length = udpLength

	// IPv4
	ipLayer := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    srcIP.To4(),
		DstIP:    DNSServerIP.To4(),
		Length:   udpLength + 20,
		IHL:      5,
	}

	udpLayer.SetNetworkLayerForChecksum(ipLayer)
	// 创建以太网层
	ethernetLayer := &layers.Ethernet{
		SrcMAC:       srcMac,
		DstMAC:       config.BoardCASTMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	packet := []gopacket.SerializableLayer{ethernetLayer, ipLayer, udpLayer, dnsLayer}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths: true,
		// ComputeChecksums: true,
	}
	err = gopacket.SerializeLayers(buf, opts, packet...)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// 发送DNS请求
func SendRequest(DNSData []byte, device *pcap.Interface) error {
	handle, err := pcap.OpenLive(device.Name, 1600, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	defer handle.Close()
	err = handle.WritePacketData(DNSData)
	return err
}

// 获取DNS响应
func GetResponse(device *pcap.Interface, srcMac net.HardwareAddr, DNSServerIP net.IP) (*layers.Ethernet, *layers.IPv4, *layers.UDP, *layers.DNS, error) {
	handle, err := pcap.OpenLive(device.Name, 1600, true, pcap.BlockForever)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// 只接收DNS消息
		dnsLayer := packet.Layer(layers.LayerTypeDNS)
		if dnsLayer == nil {
			continue
		}
		udpLayer := packet.Layer(layers.LayerTypeUDP)

		dnsPacket := dnsLayer.(*layers.DNS)
		udpPacket := udpLayer.(*layers.UDP)

		// 判断数据包是否为目标MAC为本机MAC的以太网数据包
		ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethernetLayer == nil {
			continue
		}

		ethernetPacket, ok := ethernetLayer.(*layers.Ethernet)
		if !ok {
			continue
		}
		// 判断MAC是否相等
		if !bytes.Equal(ethernetPacket.DstMAC, srcMac) {
			continue
		}

		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			continue
		}
		ipPacket, ok := ipLayer.(*layers.IPv4)
		if !ok {
			continue
		}
		// 判断IP是否相等
		if !ipPacket.SrcIP.Equal(DNSServerIP) {
			continue
		}

		return ethernetPacket, ipPacket, udpPacket, dnsPacket, nil
	}

	return nil, nil, nil, nil, fmt.Errorf("can't find the response")
}

// 格式化打印DNS响应信息
func PrintResponse(ethernet_ *layers.Ethernet, ipv4_ *layers.IPv4, udp_ *layers.UDP, dns_ *layers.DNS) {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{
		"domain",
		"SrcIP",
		"SrcMAC",
		"DstIP",
		"DstMAC",
		"SrcPort",
		"DstPort",
		"ANS-IP",
	})
	data := make([][]string, 0)
	for _, ansIP := range dns_.Answers {
		data = append(data, []string{
			string(dns_.Answers[0].Name),
			ipv4_.SrcIP.String(),
			ethernet_.SrcMAC.String(),
			ipv4_.DstIP.String(),
			ethernet_.DstMAC.String(),
			udp_.SrcPort.String(),
			udp_.DstPort.String(),
			ansIP.String(),
		})
	}
	table.SetHeaderColor(
		tablewriter.Colors{tablewriter.Bold, tablewriter.BgGreenColor},
		tablewriter.Colors{tablewriter.FgHiRedColor, tablewriter.Bold, tablewriter.BgBlackColor},
		tablewriter.Colors{tablewriter.BgRedColor, tablewriter.FgWhiteColor},
		tablewriter.Colors{tablewriter.BgCyanColor, tablewriter.FgWhiteColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.BgGreenColor},
		tablewriter.Colors{tablewriter.FgHiRedColor, tablewriter.Bold, tablewriter.BgBlackColor},
		tablewriter.Colors{tablewriter.BgRedColor, tablewriter.FgWhiteColor},
		tablewriter.Colors{tablewriter.BgCyanColor, tablewriter.FgWhiteColor},
	)

	table.AppendBulk(data)
	table.Render()
}

// 获取DNS长度
func getUDPLength(dns *layers.DNS) (uint16, error) {
	buf := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(
		buf, gopacket.SerializeOptions{}, dns,
	)
	if err != nil {
		return 0, err
	}
	return uint16(8 + len(buf.Bytes())), nil
}
