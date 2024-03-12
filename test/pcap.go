package test

import (
	"context"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/lysShub/relraw"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type pcapWrap struct {
	relraw.RawConn

	fh *os.File
	w  *pcapgo.Writer
}

func WrapPcap(child relraw.RawConn, file string) (*pcapWrap, error) {
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

var _ relraw.RawConn = (*pcapWrap)(nil)

func (w *pcapWrap) Read(ip []byte) (n int, err error) {
	n, err = w.RawConn.Read(ip)
	if err != nil {
		return 0, err
	}
	w.writePacket(ip[:n])
	return n, nil
}
func (w *pcapWrap) ReadCtx(ctx context.Context, p *relraw.Packet) (err error) {
	oldH := p.Head()

	err = w.RawConn.ReadCtx(ctx, p)
	if err != nil {
		return err
	}
	newH := p.Head()

	p.SetHead(oldH)
	w.writePacket(p.Data())
	p.SetHead(newH)

	return nil
}

func (w *pcapWrap) Write(ip []byte) (n int, err error) {
	n, err = w.RawConn.Write(ip)
	if err != nil {
		return 0, err
	}
	w.writePacket(ip)
	return n, nil
}
func (w *pcapWrap) WriteCtx(ctx context.Context, p *relraw.Packet) (err error) {
	err = w.RawConn.WriteCtx(ctx, p)
	if err != nil {
		return err
	}

	w.writePacket(p.Data())
	return nil
}
func (w *pcapWrap) Inject(ip []byte) (err error) {
	err = w.RawConn.Inject(ip)
	if err != nil {
		return err
	}
	w.writePacket(ip)
	return nil
}
func (w *pcapWrap) InjectCtx(ctx context.Context, p *relraw.Packet) (err error) {
	err = w.RawConn.InjectCtx(ctx, p)
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
