package test

import (
	"context"
	"os"
	"time"

	"github.com/pkg/errors"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/lysShub/sockit/conn"
	"github.com/lysShub/sockit/packet"
	"github.com/lysShub/sockit/test/debug"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type Pcap struct {
	fh *os.File
	w  *pcapgo.Writer
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
		fh: fh,
		w:  w,
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

func (p *Pcap) Write(eth header.Ethernet) error {
	err := p.w.WritePacket(gopacket.CaptureInfo{
		Timestamp:      time.Now(),
		CaptureLength:  len(eth),
		Length:         len(eth),
		InterfaceIndex: 0,
	}, eth)
	return err
}

func (p *Pcap) WriteIP(ip []byte) error {
	if debug.Debug() {
		ValidIP(T(), ip)
	}

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
	return p.Write(eth)
}

type PcapWrap struct {
	conn.RawConn
	pcap *Pcap
}

var _ conn.RawConn = (*PcapWrap)(nil)

func WrapPcap(child conn.RawConn, file string) (*PcapWrap, error) {
	p, err := NewPcap(file)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return &PcapWrap{
		RawConn: child,
		pcap:    p,
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
	err = w.RawConn.Write(ctx, pkt)
	if err != nil {
		return err
	}

	// RawConn.Write will attach ip header.
	// NOTICE: without constraint must is ip packet
	if debug.Debug() {
		ValidIP(T(), pkt.Bytes())
	}
	return w.pcap.WriteIP(pkt.Bytes())
}
func (w *PcapWrap) Inject(ctx context.Context, p *packet.Packet) (err error) {
	err = w.RawConn.Inject(ctx, p)
	if err != nil {
		return err
	}

	return w.pcap.WriteIP(p.Bytes())
}
