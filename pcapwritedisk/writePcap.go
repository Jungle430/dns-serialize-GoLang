package pcapwritedisk

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

const (
	// HEADER最大长度标识
	HEADER_MAX_LENGTH = 65536
)

// 将数据包信息写入PCAP文件
func Info(writer *pcapgo.Writer, pcapData []byte) error {
	// 头部
	writer.WriteFileHeader(HEADER_MAX_LENGTH, layers.LinkTypeEthernet)
	return writer.WritePacket(
		gopacket.CaptureInfo{
			CaptureLength: len(pcapData),
			Length:        len(pcapData),
		},
		pcapData)
}
