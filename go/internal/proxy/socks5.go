// Package proxy provides a lightweight SOCKS5 client and probe helpers
// for testing connectivity through a FreedomNet proxy instance.
package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	socks5Version = 0x05
	cmdConnect    = 0x01
	atypDomain    = 0x03
	atypIPv4      = 0x01
	atypIPv6      = 0x04
	noAuth        = 0x00
)

// ErrAuth is returned when the proxy rejects the no-auth negotiation.
var ErrAuth = errors.New("socks5: authentication rejected")

// Dialer wraps a SOCKS5 proxy address and implements Dial.
type Dialer struct {
	ProxyAddr string
	Timeout   time.Duration
}

// Dial connects to the SOCKS5 proxy at d.ProxyAddr and asks it to connect to
// the given target address (host:port).
func (d *Dialer) Dial(network, target string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, target)
}

// DialContext is the context-aware version of Dial.
func (d *Dialer) DialContext(ctx context.Context, network, target string) (net.Conn, error) {
	timeout := d.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	var d2 net.Dialer
	conn, err := d2.DialContext(ctx, "tcp", d.ProxyAddr)
	if err != nil {
		return nil, fmt.Errorf("socks5 dial proxy: %w", err)
	}
	conn.SetDeadline(time.Now().Add(timeout))

	if err := negotiate(conn); err != nil {
		conn.Close()
		return nil, err
	}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 bad target %q: %w", target, err)
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 bad port %q: %w", portStr, err)
	}

	if err := sendConnect(conn, host, uint16(port)); err != nil {
		conn.Close()
		return nil, err
	}

	if err := readReply(conn); err != nil {
		conn.Close()
		return nil, err
	}

	conn.SetDeadline(time.Time{})
	return conn, nil
}

func negotiate(conn net.Conn) error {
	// client greeting: VER=5, NMETHODS=1, METHOD=NO_AUTH
	_, err := conn.Write([]byte{socks5Version, 1, noAuth})
	if err != nil {
		return fmt.Errorf("socks5 greeting write: %w", err)
	}

	var resp [2]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		return fmt.Errorf("socks5 greeting read: %w", err)
	}
	if resp[0] != socks5Version || resp[1] != noAuth {
		return ErrAuth
	}
	return nil
}

func sendConnect(conn net.Conn, host string, port uint16) error {
	// CONNECT request
	req := []byte{socks5Version, cmdConnect, 0x00, atypDomain}
	req = append(req, byte(len(host)))
	req = append(req, []byte(host)...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, port)
	req = append(req, portBytes...)

	_, err := conn.Write(req)
	return err
}

func readReply(conn net.Conn) error {
	// reply header: VER REP RSV ATYP
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return fmt.Errorf("socks5 reply header: %w", err)
	}
	if hdr[1] != 0x00 {
		return fmt.Errorf("socks5 connect failed: code %02x", hdr[1])
	}
	// drain bound address
	switch hdr[3] {
	case atypIPv4:
		io.ReadFull(conn, make([]byte, 4+2))
	case atypIPv6:
		io.ReadFull(conn, make([]byte, 16+2))
	case atypDomain:
		lenBuf := make([]byte, 1)
		io.ReadFull(conn, lenBuf)
		io.ReadFull(conn, make([]byte, int(lenBuf[0])+2))
	}
	return nil
}

// IsAlive checks that a FreedomNet proxy is listening at addr by opening a
// connection and completing the SOCKS5 greeting only (no target CONNECT).
func IsAlive(addr string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// Send greeting
	if _, err := conn.Write([]byte{socks5Version, 1, noAuth}); err != nil {
		return false
	}
	var resp [2]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		return false
	}
	return resp[0] == socks5Version && resp[1] == noAuth
}
