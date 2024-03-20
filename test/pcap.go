package test

import (
	"context"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/lysShub/rsocket"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type pcapWrap struct {
	rsocket.RawConn

	fh *os.File
	w  *pcapgo.Writer
}

func WrapPcap(child rsocket.RawConn, file string) (*pcapWrap, error) {
	fh, err := os.Create(file)
	if err != nil {
		return nil, err
	}

	w := pcapgo.NewWriter(fh)
	err = w.WriteFileHeader(65535, layers.LinkTypeEthernet)
	if err != nil {
		return nil, err
	}

	return &pcapWrap{
		RawConn: child,
		fh:      fh,
		w:       w,
	}, nil
}

var _ rsocket.RawConn = (*pcapWrap)(nil)

func (w *pcapWrap) Read(ctx context.Context, p *rsocket.Packet) (err error) {
	oldH := p.Head()

	err = w.RawConn.Read(ctx, p)
	if err != nil {
		return err
	}
	newH := p.Head()

	p.SetHead(oldH)
	w.writePacket(p.Data())
	p.SetHead(newH)

	return nil
}
func (w *pcapWrap) Write(ctx context.Context, p *rsocket.Packet) (err error) {
	err = w.RawConn.Write(ctx, p)
	if err != nil {
		return err
	}

	w.writePacket(p.Data())
	return nil
}
func (w *pcapWrap) Inject(ctx context.Context, p *rsocket.Packet) (err error) {
	err = w.RawConn.Inject(ctx, p)
	if err != nil {
		return err
	}

	w.writePacket(p.Data())
	return nil
}

func (w *pcapWrap) writePacket(ip []byte) {
	var p []byte
	switch header.IPVersion(ip) {
	case 4:
		p = append(
			p,
			[]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x08, 0x00}...,
		)
		p = append(p, ip...)

	case 6:
		p = append(
			p,
			[]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x86, 0xdd}...,
		)
	}
	err := w.w.WritePacket(gopacket.CaptureInfo{
		Timestamp:      time.Now(),
		CaptureLength:  len(p),
		Length:         len(p),
		InterfaceIndex: 0,
	}, p)
	if err != nil {
		panic(err)
	}
}
