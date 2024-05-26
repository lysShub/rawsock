package test

import (
	"github.com/pkg/errors"

	"github.com/lysShub/netkit/debug"
	"github.com/lysShub/netkit/packet"
	"github.com/lysShub/netkit/pcap"
	"github.com/lysShub/rawsock"
	"github.com/lysShub/rawsock/helper/ipstack"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type PcapWrap struct {
	rawsock.RawConn
	pcap    *pcap.Pcap
	ipstack *ipstack.IPStack
}

var _ rawsock.RawConn = (*PcapWrap)(nil)

// WrapPcap wrap a RawConn for capture packets
// NOTICE: write packet's ip header is mocked
func WrapPcap(child rawsock.RawConn, file string) (*PcapWrap, error) {
	s, err := ipstack.New(
		child.LocalAddr().Addr(),
		child.RemoteAddr().Addr(),
		header.TCPProtocolNumber, // todo: from RawConn
	)
	if err != nil {
		return nil, err
	}

	p, err := pcap.File(file)
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

func (w *PcapWrap) Read(pkt *packet.Packet) (err error) {
	old := pkt.Head()
	err = w.RawConn.Read(pkt)
	if err != nil {
		return err
	}
	new := pkt.Head()

	pkt.SetHead(old)
	if debug.Debug() {
		ValidIP(T(), pkt.Bytes())
	}
	err = w.pcap.WriteIP(pkt.Bytes())
	pkt.SetHead(new)

	return err
}

func (w *PcapWrap) Write(pkt *packet.Packet) (err error) {
	clone := pkt.Clone()

	err = w.RawConn.Write(pkt)
	if err != nil {
		return err
	}

	w.ipstack.AttachOutbound(clone)
	if debug.Debug() {
		ValidIP(T(), clone.Bytes())
	}
	return w.pcap.WriteIP(clone.Bytes())
}
func (w *PcapWrap) Inject(pkt *packet.Packet) (err error) {
	clone := pkt.Clone()

	err = w.RawConn.Inject(pkt)
	if err != nil {
		return err
	}

	w.ipstack.AttachInbound(clone)
	if debug.Debug() {
		ValidIP(T(), clone.Bytes())
	}
	return w.pcap.WriteIP(clone.Bytes())
}
