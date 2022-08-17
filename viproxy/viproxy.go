// Package viproxy implements a point-to-point TCP proxy that translates
// between AF_INET and AF_VSOCK.  This facilitates communication to and from an
// AWS Nitro Enclave which constrains I/O to a VSOCK interface.
package viproxy

import (
	"github.com/brodyxchen/aws-enclave-kms/log"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/mdlayher/vsock"
)

// Tuple contains two addresses; one to listen on for incoming TCP connections,
// and another one to forward TCP data to.
type Tuple struct {
	InAddr  net.Addr
	OutAddr net.Addr
}

// VIProxy implements a TCP proxy that translates between AF_INET and AF_VSOCK.
type VIProxy struct {
	tuples []*Tuple
}

// NewVIProxy returns a new VIProxy instance.
func NewVIProxy(tuples []*Tuple) *VIProxy {
	return &VIProxy{tuples: tuples}
}

// Start starts the TCP proxy along with all given connection forwarding
// tuples.  The function returns once all listeners are set up.  The function
// returns the first error that occurred (if any) while setting up the
// listeners.
func (p *VIProxy) Start() error {
	var err error
	for _, t := range p.tuples {
		if err = handleTuple(t); err != nil {
			return err
		}
	}
	return nil
}

func dial(addr net.Addr) (net.Conn, error) {
	var conn net.Conn
	var err error

	switch a := addr.(type) {
	case *vsock.Addr:
		conn, err = vsock.Dial(a.ContextID, a.Port, nil)
	case *net.TCPAddr:
		conn, err = net.DialTCP("tcp", nil, a)
	}
	if err != nil {
		return nil, err
	}

	return conn, nil
}

func listen(addr net.Addr) (net.Listener, error) {
	var ln net.Listener
	var err error

	switch a := addr.(type) {
	case *vsock.Addr:
		ln, err = vsock.ListenContextID(a.ContextID, a.Port, nil)
	case *net.TCPAddr:
		ln, err = net.ListenTCP(a.Network(), a)
	}
	if err != nil {
		return nil, err
	}

	return ln, nil
}

func handleTuple(tuple *Tuple) error {
	ln, err := listen(tuple.InAddr)
	if err != nil {
		return err
	}
	log.Infof("Listening for incoming connections on %s.", tuple.InAddr)

	go func() {
		for {
			inConn, err := ln.Accept()
			if err != nil {
				log.Errorf("Failed to accept incoming connection: %s", err)
				continue
			}
			log.Info("Accepted incoming connection from %s.", inConn.RemoteAddr())

			outConn, err := dial(tuple.OutAddr)
			if err != nil {
				log.Errorf("Failed to establish forwarding connection: %s", err)
				inConn.Close()
				continue
			}

			go forward(inConn, outConn)
			log.Info("Dispatched forwarders for %s <-> %s.", tuple.InAddr, tuple.OutAddr)
		}
	}()
	return nil
}

func forward(in, out net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	annoyingErr := "use of closed network connection"

	go func() {
		if _, err := io.Copy(in, out); err != nil && !strings.Contains(err.Error(), annoyingErr) {
			log.Errorf("Error while forwarding to %s, err: %s \n", in.RemoteAddr(), err)
		}
		in.Close()
		out.Close()
		wg.Done()
		log.Info("viproxy forward in-->out done")
	}()
	go func() {
		// read tcp 127.0.0.1:1080->127.0.0.1:45982: read: connection reset by peer
		if _, err := io.Copy(out, in); err != nil && !strings.Contains(err.Error(), annoyingErr) {
			log.Errorf("Error while forwarded to %s, err: %s \n", out.RemoteAddr(), err)
		}
		in.Close()
		out.Close()
		wg.Done()
		log.Info("viproxy forward out-->in done")
	}()
	wg.Wait()
	log.Infof("Closed connection tuple for %s <-> %s.", in.RemoteAddr(), out.RemoteAddr())
}
