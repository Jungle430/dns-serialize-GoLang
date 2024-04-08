package config

import (
	"hash/fnv"
	"net"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

// 日志初始化配置
func InitLog() {
	log.SetReportCaller(true)
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05",
	})
}

const (
	// 输出的pcap文件
	OUTPUT_PCAP_FILE = "pcapData/output.pcap"
)

var (
	// ARP广播MAC
	BoardCASTMAC = net.HardwareAddr{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
)

var (
	// 阿里巴巴DNS服务器IP
	ALIBABA_DNS_IP = net.IPv4(233, 5, 5, 5)

	// 百度DNS服务器IP
	BAIDU_DNS_IP = net.IPv4(180, 76, 76, 76)

	// GOOGLE DNS服务器IP1
	GOOGLE_DNS_IP_1 = net.IPv4(8, 8, 8, 8)

	// GOOGLE DNS服务器IP2(默认使用该DNS服务器)
	GOOGLE_DNS_IP_2 = net.IPv4(8, 8, 4, 4)

	// 360 DNS服务器IP1
	CN_360_DNS_IP_1 = net.IPv4(101, 226, 4, 6)

	// 360 DNS服务器IP2
	CN_360_DNS_IP_2 = net.IPv4(218, 30, 118, 6)
)

// 通过UUID+HASH随机生成UDP的ID
func GetUDPId() uint16 {
	uuidObj := uuid.New()
	hash := fnv.New32a()
	hash.Write([]byte(uuidObj.String()))
	hashSum := hash.Sum32()
	return uint16(hashSum & 0xFFFF)
}
