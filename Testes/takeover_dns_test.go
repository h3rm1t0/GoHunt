package testes

import (
	"GoHunt/DNS"
	"context"
	"encoding/binary"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDNSInspectorCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := (&dns.SystemCNAMEInspector{Servers: []string{"127.0.0.1:53"}, Timeout: time.Second}).Inspect(ctx, "orphan.example")
	if err == nil {
		t.Fatal("canceled DNS inspection succeeded")
	}
}

func TestDNSNXDOMAINRetainsCNAMEAnswers(t *testing.T) {
	aliases := []dnsmessage.Resource{cnameResource(t, "orphan.example", "middle.example"), cnameResource(t, "middle.example", "retired.github.io")}
	address, calls := fixtureDNS(t, func(query dnsmessage.Message, stream bool) dnsmessage.Message {
		return dnsmessage.Message{Header: dnsmessage.Header{ID: query.Header.ID, Response: true, RCode: dnsmessage.RCodeNameError}, Questions: query.Questions, Answers: aliases}
	})
	inspector := &dns.SystemCNAMEInspector{Servers: []string{address}, Timeout: time.Second}
	info, err := inspector.Inspect(context.Background(), "orphan.example")
	if err != nil || len(info.Chain) != 2 || info.Destination != "retired.github.io" || info.RCode != dnsmessage.RCodeNameError || info.Chain[0].TTL != 120 || calls.Load() != 1 {
		t.Fatalf("%+v err=%v calls=%d", info, err, calls.Load())
	}
}

func TestDNSRejectsMismatchedIDAndAliasCycles(t *testing.T) {
	for _, mode := range []string{"id", "cycle"} {
		t.Run(mode, func(t *testing.T) {
			aliases := []dnsmessage.Resource{cnameResource(t, "orphan.example", "middle.example"), cnameResource(t, "middle.example", "orphan.example")}
			address, _ := fixtureDNS(t, func(query dnsmessage.Message, stream bool) dnsmessage.Message {
				response := dnsmessage.Message{Header: dnsmessage.Header{ID: query.Header.ID, Response: true}, Questions: query.Questions}
				if mode == "id" {
					response.Header.ID++
				} else {
					response.Answers = aliases
				}
				return response
			})
			if _, err := (&dns.SystemCNAMEInspector{Servers: []string{address}, Timeout: time.Second}).Inspect(context.Background(), "orphan.example"); err == nil {
				t.Fatal("invalid DNS evidence accepted")
			}
		})
	}
}

func TestDNSTruncationFallsBackToTCP(t *testing.T) {
	aliases := []dnsmessage.Resource{cnameResource(t, "orphan.example", "retired.github.io")}
	address, calls := fixtureDNS(t, func(query dnsmessage.Message, stream bool) dnsmessage.Message {
		response := dnsmessage.Message{Header: dnsmessage.Header{ID: query.Header.ID, Response: true}, Questions: query.Questions}
		if !stream {
			response.Header.Truncated = true
		} else {
			response.Header.RCode = dnsmessage.RCodeNameError
			response.Answers = aliases
		}
		return response
	})
	info, err := (&dns.SystemCNAMEInspector{Servers: []string{address}, Timeout: time.Second}).Inspect(context.Background(), "orphan.example")
	if err != nil || info.Destination != "retired.github.io" || calls.Load() != 2 {
		t.Fatalf("%+v %v calls=%d", info, err, calls.Load())
	}
}

func cnameResource(t *testing.T, name, target string) dnsmessage.Resource {
	t.Helper()
	owner, err := dnsmessage.NewName(name + ".")
	if err != nil {
		t.Fatal(err)
	}
	dest, err := dnsmessage.NewName(target + ".")
	if err != nil {
		t.Fatal(err)
	}
	return dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: owner, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 120}, Body: &dnsmessage.CNAMEResource{CNAME: dest}}
}

func fixtureDNS(t *testing.T, reply func(dnsmessage.Message, bool) dnsmessage.Message) (string, *atomic.Int32) {
	t.Helper()
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenPacket("udp", tcp.Addr().String())
	if err != nil {
		tcp.Close()
		t.Fatal(err)
	}
	var calls atomic.Int32
	var workers sync.WaitGroup
	workers.Add(2)
	t.Cleanup(func() { udp.Close(); tcp.Close(); workers.Wait() })
	pack := func(packet []byte, stream bool) []byte {
		var query dnsmessage.Message
		if err := query.Unpack(packet); err != nil {
			t.Error(err)
			return nil
		}
		calls.Add(1)
		response := reply(query, stream)
		raw, err := response.Pack()
		if err != nil {
			t.Error(err)
		}
		return raw
	}
	go func() {
		defer workers.Done()
		packet := make([]byte, 65535)
		for {
			n, address, err := udp.ReadFrom(packet)
			if err != nil {
				return
			}
			raw := pack(packet[:n], false)
			udp.WriteTo(raw, address)
		}
	}()
	go func() {
		defer workers.Done()
		for {
			conn, err := tcp.Accept()
			if err != nil {
				return
			}
			func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(time.Second))
				var size [2]byte
				if _, err := io.ReadFull(conn, size[:]); err != nil {
					return
				}
				packet := make([]byte, int(binary.BigEndian.Uint16(size[:])))
				if _, err := io.ReadFull(conn, packet); err != nil {
					return
				}
				raw := pack(packet, true)
				framed := make([]byte, 2+len(raw))
				binary.BigEndian.PutUint16(framed[:2], uint16(len(raw)))
				copy(framed[2:], raw)
				conn.Write(framed)
			}()
		}
	}()
	return tcp.Addr().String(), &calls
}
