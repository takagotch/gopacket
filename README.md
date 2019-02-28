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



ethP := gopacket.NewPacket(p1, layers.LayerTypeEthernet, gopacket.Default)

ipP := gopacket.NewPacket(p2, layers.LayerTypeIPv6, gopacket.Default)

tcpP := gopaket.NewPacket(p3, layers.LayerTypeTCP, gopacket.Default)

packetSource := ...
for packet := range packetSource.Packets() {
  handlePacket(packet)
}


packet := gopacket.NewPacket(myPacketData, layers.LayerTypeEthrnet, gopacket.Lazy)

ip4 := packet.Layer(layers.LayerTypeIPv4)

layers := packet.Layers()


for data := range myByteSliceChannel {
  p := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
  doSomethingPacket(p)
}


for packet := range someSource {
  if app := packet.ApplicationLayer(); app != nil {
    if strings.Contains(string(app.Payload()), "magic string") {
      fmt.Println("Found magic string in a packet!")
    }
  }
}


packet := gopacket.NewPacket(myPacketData, layers.LayerTypeEthernet, gopacket.Default)
if err := packet.ErrorLayer(); err != nil {
  fmt.Println("Error decoding some part of the packet:", err)
}


packet := gopacket.NewPacket(myPacketData, layers.LayerTypeEthernet, gopacket.Lazy)
netFlow := packet.NetworkLayer().NetworkFlow()
src, dst := netFlow.Endpoints()
reverseFlow := gopacket.NewFlow(dst, src)


flows := map[gopacket.Endpoint]chan gopacket.Packet
packet := gopacket.NewPacket(myPacketData, layers.LayerTypeEthernet, gopacket.Lazy)

if tcp := packet.Layer(layers.LayerTypeTCP); tcp != nil {
  flows[tcp.TransportFlow().Dst()] <- packet
}

if net := packet.NetworkLayer(); net != nil {
  src, dst := net.NetworkFlow().Endpoints()
  if src == dst {
    fmt.Println("Fishy packet has same network source and dst: %s", src)
  }
}

interestingFlow := gopacket.NewFlow(layers.NewUDPPortEndpoint(1000), layersUDPPortEndpoints(500))
if t := packet.NetworkLayer(); t != nil && t.TransportFlow() == interestingFlow {
  fmt.Println("Found that UDP flow I was looking for!")
}


channels := [8]chan gopacket.Packet
for i := 0; i < 8; i++ {
  channels[i] = make(chan gopacket.Packet)
  go packetHandler(channels[i])
}
for packet := range getPackets() {
  if net := packet.NetworkLayer(); net != nil {
    channels[int(net.NetworkFlow().FastHash()) & 0x7] <- packet
  }
}


var MyLayerType = gopacket.RegisterLayerType(12345, gopacket.LayerTypeMetadata{Name: "MyLayerType", Decoder: gopacket.DecodeFunc(decodeMyLayer)})

type MyLayer struct {
  StrangeHeader []byte
  payload []byte
}
func (m MyLayer) LayerType() gopacket.LayerType { return MyLayerType }
func (m MyLayer) LayerContents() []byte { return m.StrangeHeader }
func (m MyLayer) LayerPayload() []byte { return m.payload }

func decodeMyLayer(data []byte, p gopacket.PacketBuilder) error {
  p.AddLayer(&MyLayer{data[:4], data[4:]})
  
  return p.NextDecoder(layers.LayerTypeEthernet)
}

p := gopacket.Newpacket(data, MyLayerType, gopacket.Lazy)


func main() {
  var eth layers.Ethernet
  var ip4 layers.IPv4
  var ip6 layers.IPv6
  var tcp layers.TCP
  parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp)
  decoded := []gopacket.LayerType{}
  for packetData := range somehowGetPacketData() {
    if err := parser.DecodeLayers(packetData, &decoded); err != nil {
      fmt.Fprintf(os.Stderr, "Could not decode layers: %v\n", err)
      continue
    }
    for _, layerType := range decoded {
      switch layerType {
        case layers.LayerTypeIPv6:
          fmt.Println("  IP6 ", ip6.SrcIP, ip6.DstIP)
        case layers.LayerTypeIPv4:
          fmt.Println("  IP4 ", ip4.SrcIP, ip4.DstIP)
      }
    }
  }
}


ip := &layers.IPv4{
  SrcIP: net.IP{1, 2, 3, 4},
  DstIP: net.IP{5, 6, 7, 8}
}
buf := gopacket.NewSerializeBuffer()
opts := gopacket.SerializeOptions{}
err := ip.SerializeTo(buf, opts)
if err != nil { panic(err) }
fmt.Println(buf.Bytes())


buf := gopacket.NewSerializeBuffer()
opts := gopacket.SerializeOptions{}
gopacket.SerializeLayers(buf, opts,
  &layers.Ethernet{},
  &layers.IPv4{},
  &layers.TCP{},
  gopacket.Payload([]byte{1, 2, 3, 4}))
packetData := buf.Bytes()


import (
  _ "github.com/google/gopacket/layers"
)
```

```js
var DecodeStreamsAsDatagrams = DecodeOptions{DecodeStreamsAsDatagrams: true}

var DecodersByLayerName = map[string]Decoder{}

var Default = DecodeOptions{}

var EndpointInvalid = RegisterEndpointType(0, EndpointTypeNetadata{Nane: "invalid", Formatter: func(b []byte) string {
  return fmt.Sprintf("%v", b)
}})


var InvalidEndpoint = NewEndpoint(EndpoinInvalid, nil)

var InvalidFlow = NewFlow(EndpointInvalid, nil, nil)

var LayerTypeDecodeFailure = RegisterLayerType(1, LayerTypeMetadata{Name: "DecodeFailure", DecodeUnknown})

var LayerTypeFragment = RegisterLayerType(3, LayerTypeMetadata{Name: "Fragment", Decoder: DecodeFragment})

var LayerTypePayload = RegisterLayerType(2, LayerTypeMetadata{Name: "Payload", Decoder: DecodePayload})

var LayerTypeZero = RegisterLayerType(0, LayerTypeMeta{Name: "Unknown", Decoder: DecodeUnknown})

var Lazy = DecodeOptions{Lazy: true}

var NoCopy = DecodeOptions{NoCopy: true}

var TimestampResolutionCaptureInfo = TimestampResolutionNanosecond

var TimestampResolutionInvalid = TimestampResolution{}

var TimestampResolutionMicrosecond = TimestampResolution{10, -6}

var TimestampResolutionMillisecond = TimestampResolution{10, -3}

var TimestampResolutionNTP = TimestampResolution{2, -32}

var TimestampResolutionNanosecond = TimestampResolution{10, -9}

func LayerDump(1 Layer) string

func LayerGoString(l Layer) string

func LayerString(1 Layer) string

func LongBytesGoString(buf []byte) string


func SerializeLayers(w SerializeBuffer, opts SerializeOptions, layers ...SerializableLayer) error

buf := gopacket.NewSerializeBuffer()
opts := gopacket.SerializeOptions{}
gopacket.SerializeLayers(buf, opts, a, b, c)
firstPayload := buf.Bytes()
gopacket.SerializeLayers(buf, opts, d, e, f)
secondPayload := buf.Bytes()

func SerializePacket(buf SerializeBuffer, opts SerializeOptions, packet Packet) error

type ApplicationLayer interface {
  Layer
  Payload() []byte
}


type CaptureInfo struct {
  Timestamp time.Time
  CaptureLength int
  Length int
  InterfaceIndex int
  AncillaryData []interface{}
}

type DecodeFailure struct {
}

func (d *DecodeFailure) Dump() (s string)

func (d *DecodeFailure) LayerContents() []byte
func (d *DecodeFailure) LayerPayload() []byte
func (d *DecodeFailure) LayerType() LayerType
func (d *DecodeFailure) String() string

type DecodeFeedback interface {
  SetTruncate()
}

var NilDecodeFeedback DecodeFeedback = nilDecodeFeedback{}

type DecodeFunc func([]byte, p PacketBuilder) error
func (d DecodeFunc) Decode(data []byte, p PacketBuilder) error

typeDecodeOptions struct {
  Lazy bool
  NoCopy bool
  SkipDecodeRecovery bool
  DecodeStreamsAsDatagrams bool
}

type Decoder interface {
  Deode([]byte, PacketBuilder) error
}

var DecodeFragment Decoder = DecodeFunc(decodeFragment)
var DecodePayload Decoder = DecodeFunc(decodePayload)
var DecodeUnknow Decoder = DecodeFunc(decodeUnknown)

type DecodingLayer interface {
  DecodeFromBytes(data []byte, df DecodeFeedback) error
  CanDecode() LayerClass
  NextLayerType() LayerType
  LayerPayload() []byte
}

type DecodingLayerParser struct {
  DecodingLayerParserOptions
  Truncated bool
}


func NewDecodingLayerParser(first LayerType, decoders ...DecodingLayer) *DecodingLayerParser

func (1 *DecodingLayerParser) AddDecodingLayer(d DecodingLayer)

func (1 *DecodingLayerParser) DecodeLayers(data []byte, decoded *[]LayerType) (err error)

func main() {
  var eth layers.Ethernet
  var ip4 layers.IPv4
  var ip6 layersIPv6
  var tcp layers.TCP
  var udp layers.UDP
  var payload gopacket.Payload
  parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp, &udp, &payload)
  var source gopacket.PacketDataSource = getMyDataSource()
  decodedLayers := make([]gopacket.LayerType, 0, 10)
  for {
    data, _, err := source.ReadPacketData()
    if err != nil {
      fmt.Println("Error reading packet data: ", err)
      continue
    }
    fmt.Println("Decoding packet")
    err = parser.DecodeLayers(data, &decodedLayers)
    for _, typ := range decodedLayers {
      fmt.Println("  Successfully decoded layer type", typ)
      switch typ {
        case layers.LayerTypeEthernet:
          fmt.Println("  Eth ", eth.SrcMAC, eth.DstMAC)
        case layers.LayerTypeIPv4:
          fmt.Println("  IP4 ", ip4.SrcIP, ip4.DstIP)
        case layers.LayerTypeIPv6:
          fmt.Println("  IP6 ", ip6.SrcIp, ip6.DstIP)
        case layers.LayerTypeTCP:
          fmt.Println("  TCP ", tcp.SrcPort, tcp.DstPort)
        case layers.LayerTypeUDP:
          fmt.Println("  UDP ", udp.SrcPort, udp.DstPort)
      }
    }
    if decodedLayers.Truncated {
      fmt.Println(" Packet has been truncated")
    }
    if err != nil {
      fmt.Println("  Error encountered:", err)
    }
  }
}


func (1 *DecodingLayerParser) SetTruncated()

type DecodingLayerParserOptions struct {
  IgnorePanic bool
  IgnoreUnsupported bool
}

type Dumper interface {
  Dump() string
}

type Endpoint struct {
}

func NewEndpoint(typ EndpointType, raw []byte) (e Endpoint)

func (a Endpoint) EndpointType() EndpointType

func (a Endpoint) FastHash() (h uint64)

func (a Endpoint) LessThan(b Endpoint) bool

func (a Endpoint) Raw() []byte

func (a Endpoint) Stirng() string
type EndpoinType int64

func RegisterEndpoinType(num int, meta EndpointTypeMetadata) EndpointType
func (e EndpointType) String() string

type EndpointTypeMetadata struct {
  Name string
  Formatter func([]byte) string
}

type ErrorLayer interface {
  Layer
  Error() error
}

type Flow struct {
}

func FlowFromEndpoints(src, dst Endpoint) (_ Flow, err error)
```

```
```



