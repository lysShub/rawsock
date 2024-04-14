package test

import (
	"context"
	"os"
	"sync"
	"time"

	"github.com/pkg/errors"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/lysShub/sockit/conn"
	"github.com/lysShub/sockit/helper/ipstack"
	"github.com/lysShub/sockit/packet"
	"github.com/lysShub/sockit/test/debug"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type Pcap struct {
	mu   sync.RWMutex
	path string
	fh   *os.File
	w    *pcapgo.Writer
}

func NewPcap(file string) (*Pcap, error) {
	fh, err := os.Create(file)
	if err != nil {
		return nil, err
	}

	w := pcapgo.NewWriter(fh)
	err = w.WriteFileHeader(0xffff, layers.LinkTypeEthernet)
	if err != nil {
		return nil, err
	}

	return &Pcap{
		path: file,
		fh:   fh,
		w:    w,
	}, nil
}

func PcapIPs[T []byte | *packet.Packet](file string, ips ...T) error {
	if len(ips) == 0 {
		return nil
	}
	var ps [][]byte
	switch ips := any(ips).(type) {
	case [][]byte:
		ps = ips
	case []*packet.Packet:
		for _, e := range ips {
			ps = append(ps, e.Bytes())
		}
	default:
		panic("")
	}

	p, err := NewPcap(file)
	if err != nil {
		return errors.WithStack(err)
	}
	defer p.Close()

	for _, e := range ps {
		if err := p.WriteIP(e); err != nil {
			return err
		}
	}
	return nil
}

func (p *Pcap) Close() error { return p.fh.Close() }

func (p *Pcap) write(eth header.Ethernet) error {
	if debug.Debug() {
		ValidIP(T(), eth[header.EthernetMinimumSize:])
	}

	err := p.w.WritePacket(gopacket.CaptureInfo{
		Timestamp:      time.Now(),
		CaptureLength:  len(eth),
		Length:         len(eth),
		InterfaceIndex: 0,
	}, eth)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func (p *Pcap) Write(eth header.Ethernet) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.write(eth)
}

func (p *Pcap) WriteIP(ip []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	var eth []byte
	switch header.IPVersion(ip) {
	case 4:
		eth = append(eth,
			[]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x08, 0x00}...,
		)
	case 6:
		eth = append(eth,
			[]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x86, 0xdd}...,
		)
	}
	eth = append(eth, ip...)

	return p.write(eth)
}

type PcapWrap struct {
	conn.RawConn
	pcap    *Pcap
	ipstack *ipstack.IPStack
}

var _ conn.RawConn = (*PcapWrap)(nil)

// WrapPcap wrap a RawConn for capture packets
// NOTICE: write packet's ip header is mocked
func WrapPcap(child conn.RawConn, file string) (*PcapWrap, error) {
	s, err := ipstack.New(
		child.LocalAddr().Addr(),
		child.RemoteAddr().Addr(),
		header.TCPProtocolNumber, // todo: from RawConn
	)
	if err != nil {
		return nil, err
	}

	p, err := NewPcap(file)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return &PcapWrap{
		RawConn: child,
		pcap:    p,
		ipstack: s,
	}, nil
}

func (w *PcapWrap) Close() (err error) {
	if e := w.RawConn.Close(); e != nil {
		err = errors.WithStack(e)
	}
	if e := w.pcap.Close(); e != nil && err == nil {
		err = errors.WithStack(e)
	}
	return err
}

func (w *PcapWrap) Read(ctx context.Context, p *packet.Packet) (err error) {
	old := p.Head()
	err = w.RawConn.Read(ctx, p)
	if err != nil {
		return err
	}
	new := p.Head()

	p.SetHead(old)
	if debug.Debug() {
		ValidIP(T(), p.Bytes())
	}
	err = w.pcap.WriteIP(p.Bytes())
	p.SetHead(new)

	return err
}

func (w *PcapWrap) Write(ctx context.Context, pkt *packet.Packet) (err error) {
	clone := pkt.Clone()

	err = w.RawConn.Write(ctx, pkt)
	if err != nil {
		return err
	}

	w.ipstack.AttachOutbound(clone)
	if debug.Debug() {
		ValidIP(T(), clone.Bytes())
	}
	return w.pcap.WriteIP(clone.Bytes())
}
func (w *PcapWrap) Inject(ctx context.Context, pkt *packet.Packet) (err error) {
	clone := pkt.Clone()

	err = w.RawConn.Inject(ctx, pkt)
	if err != nil {
		return err
	}

	w.ipstack.AttachInbound(clone)
	if debug.Debug() {
		ValidIP(T(), clone.Bytes())
	}
	return w.pcap.WriteIP(clone.Bytes())
}
