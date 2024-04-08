package device

import (
	"net"

	"github.com/google/gopacket/pcap"
)

// 获取第一张网卡
func New() (*pcap.Interface, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}
	return &devices[0], nil
}

// 获取网卡MAC地址
func GetMACByDevice(device *pcap.Interface) (net.HardwareAddr, error) {
	netInterface, err := net.InterfaceByName(device.Name)
	if err != nil {
		return nil, err
	}
	return netInterface.HardwareAddr, nil
}
