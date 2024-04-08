package main

import (
	"dns-serialize/command"
	"dns-serialize/config"
	"dns-serialize/device"
	"dns-serialize/dns"
	"dns-serialize/pcapwritedisk"
	"os"

	"github.com/google/gopacket/pcapgo"
	log "github.com/sirupsen/logrus"
)

func main() {
	config.InitLog()

	domain, err := command.GetDomain()
	if err != nil {
		log.Fatal(err)
	}

	device_, err := device.New()
	if err != nil {
		log.Fatal(err)
	}

	device_mac, err := device.GetMACByDevice(device_)
	if err != nil {
		log.Fatal(err)
	}

	dnsRequest, err := dns.BuildRequest(domain, device_mac, device_.Addresses[0].IP, config.GOOGLE_DNS_IP_2, 8080)
	if err != nil {
		log.Fatal(err)
	}

	pcap_file, err := os.Create(config.OUTPUT_PCAP_FILE)
	if err != nil {
		log.Fatal(err)
	}
	defer pcap_file.Close()

	w := pcapgo.NewWriter(pcap_file)
	pcapwritedisk.Info(w, dnsRequest)

	log.Info("Begin Send")
	err = dns.SendRequest(dnsRequest, device_)
	if err != nil {
		log.Fatal(err)
	}

	log.Info("Begin get")
	ethernet_, ipv4_, udp_, dns_, err := dns.GetResponse(device_, device_mac, config.GOOGLE_DNS_IP_2)
	if err != nil {
		log.Fatal(err)
	}

	log.Info("Print DNS MSG")
	dns.PrintResponse(ethernet_, ipv4_, udp_, dns_)
}
