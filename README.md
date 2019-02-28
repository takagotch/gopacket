### gopacket
---
https://github.com/google/gopacket

https://godoc.org/github.com/google/gopacket

```go
packet := gopacket.NewPacket(myPacketData, layers.LayerTypeEthernet, gopacket.Default)

if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
  fmt.Println("This is a TCP packet!")
  
  tcp, _ := tcpLayer.(*layers.TCP)
  fmt.Printf("From src port %d to dst port %d\n", tcp.SrcPort, tcp.DstPort)
}

for _, layer := range packer.Layers() {
  fmt.Println("PACKET LAYER:", layer.LayerType())
}

```

```
```

```
```



