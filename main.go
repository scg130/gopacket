package main

import (
	"bufio"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	device       string = "en0"
	snapshot_len int32  = 2048
	promiscuous  bool   = false
	err          error
	timeout      time.Duration = -1 * time.Second
	handle       *pcap.Handle
)

func main() {
	run()

	// req, _ := http.NewRequest("GET", "https://github.com", nil)
	// rsp, err := Request(req)
	// if err != nil {
	// 	panic(err)
	// }
	// fmt.Println(string(rsp))
}

func run() {
	// 打开某一网络设备
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// handle.SetBPFFilter("ip dst 220.181.38.251 or ip src 220.181.38.251")

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		for _, layer := range packet.Layers() {
			fmt.Printf("Layer Type: %s\n", layer.LayerType())
			fmt.Printf("Layer Payload: %x\n", layer.LayerPayload())
			fmt.Printf("Layer content: %x\n", layer.LayerContents())
		}

		// tlsLayer := packet.Layer(layers.LayerTypeTLS)
		// if tlsLayer != nil {
		// 	tls, _ := tlsLayer.(*layers.TLS)
		// 	fmt.Println(tls.AppData, tls.Contents, tls.Payload)
		// }

		// printInfo(packet)
		// printPacketInfo(packet)
	}
}

func handleTLSHandshake(record layers.TLSAppDataRecord) {
	// Here, record.Data will contain the raw bytes of the handshake message
	fmt.Printf("Handshake data: %x\n", record.Payload)
}

// Handle a TLS application data record (e.g., HTTP over TLS)
func handleTLSApplicationData(record layers.TLSAppDataRecord) {
	// Print raw application data (could be encrypted HTTP traffic)
	fmt.Printf("Application data (encrypted): %x\n", record.Payload)
}

func printInfo(packet gopacket.Packet) {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		// payload := string(tcpLayer.LayerPayload())
		applicationLayer := packet.ApplicationLayer()
		if applicationLayer != nil {
			payload := string(applicationLayer.Payload())
			data := packet.Data()
			fmt.Println(string(data))
			// Decode hex to bytes
			decodedData, err := hex.DecodeString(string(data))
			fmt.Println(decodedData)
			if err != nil {
				fmt.Println("Hex Decoding Error:", err)
				return
			}

			// Convert decoded data to string if it's valid UTF-8
			if utf8.Valid(decodedData) {
				plaintext := string(decodedData)
				fmt.Println("Readable Hex Decoded Text:")
				fmt.Println(plaintext)
			} else {
				fmt.Println("Decoded data is not valid UTF-8.")
			}

			if strings.HasPrefix(payload, "GET") || strings.HasPrefix(payload, "POST") {
				requestReader := strings.NewReader(payload)
				req, err := http.ReadRequest(bufio.NewReader(requestReader))
				if err != nil {
					fmt.Println(err)
					return
				}
				defer req.Body.Close()
				fmt.Println(req.Host, req.Method, req.Proto)
				rsp, err := Request(req)
				if err != nil {
					return
				}
				_ = rsp
				// fmt.Println(string(rsp))
			}
		}
	}
}

func Request(req *http.Request) ([]byte, error) {
	wr, _ := os.OpenFile("./data/sshkey.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, KeyLogWriter: wr}},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	bytes, _ := io.ReadAll(resp.Body)
	return bytes, nil
}

// printPacketInfo函数解析并打印数据包信息
// 参数: packet gopacket.Packet - 待解析的数据包
func printPacketInfo(packet gopacket.Packet) {
	// 检查数据包是否为以太网数据包
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		fmt.Println("检测到以太网层。")
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		fmt.Println("源MAC地址: ", ethernetPacket.SrcMAC)
		fmt.Println("目的MAC地址: ", ethernetPacket.DstMAC)
		fmt.Println("以太网类型: ", ethernetPacket.EthernetType)
		fmt.Println()
	}

	// 检查数据包是否为IPv4数据包
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		fmt.Println("检测到IPv4层。")
		ip, _ := ipLayer.(*layers.IPv4)

		// IP层变量：
		// Version (版本，可能是4或6)
		// IHL (IP头长度，以32位字为单位)
		// TOS (服务类型)，Length (总长度)，Id (标识符)，Flags (标志位)，FragOffset (片段偏移)，TTL (生存时间)，Protocol (协议，如TCP)
		// Checksum (校验和)，SrcIP (源IP地址)，DstIP (目标IP地址)
		fmt.Printf("从 %s 到 %s\n", ip.SrcIP, ip.DstIP)
		fmt.Println("协议: ", ip.Protocol)
		fmt.Println()
	}

	// 检查数据包是否为IPv6数据包
	ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
	if ipv6Layer != nil {
		fmt.Println("检测到IPv6层。")
		ipv6, _ := ipv6Layer.(*layers.IPv6)
		fmt.Printf("从 %s 到 %s\n", ipv6.SrcIP, ipv6.DstIP)
		fmt.Println("协议: ", ipv6.NextHeader)
		fmt.Println()
	}

	// 检查数据包是否为TCP数据包
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		fmt.Println("检测到TCP层。")
		tcp, _ := tcpLayer.(*layers.TCP)
		// TCP层变量：
		// SrcPort (源端口号)、DstPort (目标端口号)、Seq (序列号)、Ack (确认号)、DataOffset (数据偏移量)、Window (窗口大小)、Checksum (校验和)、Urgent (紧急指针)
		// 布尔标志位：FIN (结束标志)、SYN (同步标志)、RST (重置标志)、PSH (推送标志)、ACK (确认标志)、URG (紧急标志)、ECE (ECN回显标志)、CWR (拥塞窗口减少标志)、NS (无状态标志)
		fmt.Printf("从端口 %d 到 %d\n", tcp.SrcPort, tcp.DstPort)
		fmt.Println("序列号: ", tcp.Seq)
		fmt.Println("确认号: ", tcp.Ack)
		fmt.Println("数据偏移量: ", tcp.DataOffset)
		fmt.Println("窗口大小: ", tcp.Window)
		fmt.Println()
	}

	// 检查数据包是否为UDP数据包
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		fmt.Println("检测到UDP层。")
		udpPacket, ok := udpLayer.(*layers.UDP)
		if !ok {
			fmt.Println("无法转换为UDP层。")
			return
		}
		fmt.Printf("从端口 %d 到 %d\n", udpPacket.SrcPort, udpPacket.DstPort)
		fmt.Println("长度: ", udpPacket.Length)
		fmt.Println("校验和: ", udpPacket.Checksum)
		// 处理UDP负载
		fmt.Println("UDP负载：")
		fmt.Printf("%s\n", udpPacket.Payload)
		// 可以在这里添加更多的逻辑来处理负载
		fmt.Println()

	}

	// 打印数据包的所有层类型
	fmt.Println("所有数据包层：")
	for _, layer := range packet.Layers() {
		fmt.Println("- ", layer.LayerType())
	}

	// 当遍历 packet.Layers() 时，如果列表中包含 Payload 层，则该 Payload 层等同于 applicationLayer。
	// applicationLayer 包含了有效载荷。
	// 检查并处理应用层负载
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		fmt.Println("找到应用层/负载。")
		fmt.Printf("%s\n", applicationLayer.Payload())

		// 在负载中查找HTTP字符串
		if strings.Contains(string(applicationLayer.Payload()), "HTTP") {
			fmt.Println("找到HTTP！")
		}
	}

	// 检查解码过程中的错误
	if err := packet.ErrorLayer(); err != nil {
		fmt.Println("解码数据包的某部分时出错：", err)
	}
}

func getDevices() {
	// 得到所有的(网络)设备
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	// 打印设备信息
	fmt.Println("Devices found:")
	for _, device := range devices {
		fmt.Println("\nName: ", device.Name)
		fmt.Println("Description: ", device.Description)
		fmt.Println("Devices addresses: ", device.Description)
		for _, address := range device.Addresses {
			fmt.Println("- IP address: ", address.IP)
			fmt.Println("- Subnet mask: ", address.Netmask)
		}
	}
}
