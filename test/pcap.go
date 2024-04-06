package test

import (
	"context"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/lysShub/sockit/conn"
	"github.com/lysShub/sockit/packet"
	"github.com/lysShub/sockit/test/debug"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type pcap struct {
	fh *os.File
	w  *pcapgo.Writer
}

func NewPcap(file string) (*pcap, error) {
	fh, err := os.Create(file)
	if err != nil {
		return nil, err
	}

	w := pcapgo.NewWriter(fh)
	err = w.WriteFileHeader(65535, layers.LinkTypeEthernet)
	if err != nil {
		return nil, err
	}

	return &pcap{
		fh: fh,
		w:  w,
	}, nil
}

func (p *pcap) Write(eth header.Ethernet) error {
	err := p.w.WritePacket(gopacket.CaptureInfo{
		Timestamp:      time.Now(),
		CaptureLength:  len(eth),
		Length:         len(eth),
		InterfaceIndex: 0,
	}, eth)
	return err
}

func (p *pcap) WriteIP(ip []byte) error {
	var eth []byte
	switch header.IPVersion(ip) {
	case 4:
		eth = append(
			eth,
			[]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x08, 0x00}...,
		)
		eth = append(eth, ip...)

	case 6:
		eth = append(
			eth,
			[]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x86, 0xdd}...,
		)
	}
	return p.Write(eth)
}

type pcapWrap struct {
	conn.RawConn
	pcap *pcap
}

func WrapPcap(child conn.RawConn, file string) (*pcapWrap, error) {
	p, err := NewPcap(file)
	if err != nil {
		return nil, err
	}
	return &pcapWrap{
		RawConn: child,
		pcap:    p,
	}, nil
}

var _ conn.RawConn = (*pcapWrap)(nil)

func (w *pcapWrap) Read(ctx context.Context, p *packet.Packet) (err error) {
	oldH := p.Head()

	err = w.RawConn.Read(ctx, p)
	if err != nil {
		return err
	}
	newH := p.Head()

	p.SetHead(oldH)
	err = w.pcap.WriteIP(p.Bytes())
	if debug.Debug() {
		ValidIP(T(), p.Bytes())
	}
	p.SetHead(newH)

	return err
}
func (w *pcapWrap) Write(ctx context.Context, p *packet.Packet) (err error) {
	err = w.RawConn.Write(ctx, p)
	if err != nil {
		return err
	}

	// NOTICE: without constraint must is ip packet
	if debug.Debug() {
		ValidIP(T(), p.Bytes())
	}
	return w.pcap.WriteIP(p.Bytes())
}
func (w *pcapWrap) Inject(ctx context.Context, p *packet.Packet) (err error) {
	err = w.RawConn.Inject(ctx, p)
	if err != nil {
		return err
	}

	return w.pcap.WriteIP(p.Bytes())
}
