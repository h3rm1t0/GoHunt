package dns

import (
	"GoHunt/Escopo"
	"GoHunt/Monitoramento"
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

type CNAMEHop struct {
	Name   string `json:"name"`
	Target string `json:"target"`
	TTL    uint32 `json:"ttl"`
}

type CNAMEInfo struct {
	Chain       []CNAMEHop
	Destination string
	RCode       dnsmessage.RCode
}

func (i *SystemCNAMEInspector) Inspect(ctx context.Context, host string) (CNAMEInfo, error) {
	current := strings.ToLower(strings.TrimSuffix(host, "."))
	info := CNAMEInfo{Destination: current}
	seen := map[string]bool{current: true}
	for len(info.Chain) < 8 {
		response, err := i.query(ctx, current)
		if err != nil {
			return info, err
		}
		info.RCode = response.Header.RCode
		if info.RCode != dnsmessage.RCodeSuccess && info.RCode != dnsmessage.RCodeNameError {
			return info, fmt.Errorf("DNS respondeu %s para %s", RcodeLabel(info.RCode), current)
		}
		aliases := map[string]CNAMEHop{}
		for _, answer := range response.Answers {
			if answer.Header.Class != dnsmessage.ClassINET {
				continue
			}
			if cname, ok := answer.Body.(*dnsmessage.CNAMEResource); ok {
				name := strings.ToLower(strings.TrimSuffix(answer.Header.Name.String(), "."))
				target := strings.ToLower(strings.TrimSuffix(cname.CNAME.String(), "."))
				if !escopo.ValidHost(target) {
					return info, fmt.Errorf("destino CNAME inválido")
				}
				aliases[name] = CNAMEHop{Name: name, Target: target, TTL: answer.Header.TTL}
			}
		}
		changed := false
		for len(info.Chain) < 8 {
			hop, ok := aliases[current]
			if !ok {
				break
			}
			if seen[hop.Target] {
				return info, fmt.Errorf("ciclo CNAME detectado em %s", hop.Target)
			}
			info.Chain = append(info.Chain, hop)
			current = hop.Target
			seen[current] = true
			info.Destination = current
			changed = true
		}
		// NXDOMAIN can include the alias chain in Answers. Keep those records.
		if info.RCode == dnsmessage.RCodeNameError || !changed {
			return info, nil
		}
	}
	return info, fmt.Errorf("cadeia CNAME excede o limite de 8 saltos")
}

type CnameInspector interface {
	Inspect(context.Context, string) (CNAMEInfo, error)
}

func (i *SystemCNAMEInspector) exchange(ctx context.Context, server, network string, packet []byte) ([]byte, error) {
	if i.Before != nil {
		if err := i.Before(ctx); err != nil {
			return nil, err
		}
	}
	timeout := i.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	call, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	i.Log.Detail("Consulta DNS CNAME | resolvedor=%s | transporte=%s", server, network)
	conn, err := (&net.Dialer{}).DialContext(call, network, server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(call, func() { conn.Close() })
	defer stop()
	if deadline, ok := call.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	if network == "tcp" {
		framed := make([]byte, 2+len(packet))
		binary.BigEndian.PutUint16(framed[:2], uint16(len(packet)))
		copy(framed[2:], packet)
		if _, err = io.Copy(conn, bytes.NewReader(framed)); err != nil {
			return nil, err
		}
		var length [2]byte
		if _, err = io.ReadFull(conn, length[:]); err != nil {
			return nil, err
		}
		response := make([]byte, int(binary.BigEndian.Uint16(length[:])))
		_, err = io.ReadFull(conn, response)
		return response, err
	}
	if _, err = conn.Write(packet); err != nil {
		return nil, err
	}
	response := make([]byte, 65535)
	n, err := conn.Read(response)
	return response[:n], err
}

func (i *SystemCNAMEInspector) query(ctx context.Context, host string) (dnsmessage.Message, error) {
	servers := i.Servers
	if len(servers) == 0 {
		var err error
		servers, err = systemDNSServers()
		if err != nil {
			return dnsmessage.Message{}, err
		}
	}
	name, err := dnsmessage.NewName(host + ".")
	if err != nil {
		return dnsmessage.Message{}, err
	}
	var idBytes [2]byte
	if _, err = rand.Read(idBytes[:]); err != nil {
		return dnsmessage.Message{}, err
	}
	id := binary.BigEndian.Uint16(idBytes[:])
	question := dnsmessage.Question{Name: name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET}
	query := dnsmessage.Message{Header: dnsmessage.Header{ID: id, RecursionDesired: true}, Questions: []dnsmessage.Question{question}}
	packet, err := query.Pack()
	if err != nil {
		return dnsmessage.Message{}, err
	}
	var last error
	for _, server := range servers {
		raw, err := i.exchange(ctx, server, "udp", packet)
		if err != nil {
			last = err
			if ctx.Err() != nil {
				return dnsmessage.Message{}, ctx.Err()
			}
			continue
		}
		var parser dnsmessage.Parser
		header, err := parser.Start(raw)
		if err != nil || !header.Response || header.ID != id {
			last = fmt.Errorf("resposta DNS inválida de %s", server)
			continue
		}
		if header.Truncated {
			raw, err = i.exchange(ctx, server, "tcp", packet)
			if err != nil {
				last = err
				continue
			}
		}
		var response dnsmessage.Message
		if err = response.Unpack(raw); err != nil {
			last = err
			continue
		}
		if !response.Header.Response || response.Header.ID != id || response.Header.Truncated || len(response.Questions) != 1 || !strings.EqualFold(response.Questions[0].Name.String(), name.String()) || response.Questions[0].Type != dnsmessage.TypeCNAME || response.Questions[0].Class != dnsmessage.ClassINET {
			last = fmt.Errorf("resposta DNS não corresponde à consulta")
			continue
		}
		if response.Header.RCode == dnsmessage.RCodeServerFailure || response.Header.RCode == dnsmessage.RCodeRefused {
			last = fmt.Errorf("DNS %s: %s", server, RcodeLabel(response.Header.RCode))
			continue
		}
		return response, nil
	}
	return dnsmessage.Message{}, fmt.Errorf("consulta CNAME de %s falhou: %w", host, last)
}

func RcodeLabel(code dnsmessage.RCode) string {
	switch code {
	case dnsmessage.RCodeSuccess:
		return "NOERROR"
	case dnsmessage.RCodeNameError:
		return "NXDOMAIN"
	case dnsmessage.RCodeServerFailure:
		return "SERVFAIL"
	case dnsmessage.RCodeRefused:
		return "REFUSED"
	default:
		return fmt.Sprintf("RCODE %d", code)
	}
}

type SystemCNAMEInspector struct {
	Servers []string
	Timeout time.Duration
	Before  func(context.Context) error
	Log     *monitoramento.Console
}

func systemDNSServers() ([]string, error) {
	file, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var servers []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && fields[0] == "nameserver" {
			address := fields[1]
			plain := strings.Split(address, "%")[0]
			if net.ParseIP(plain) != nil {
				servers = append(servers, net.JoinHostPort(address, "53"))
			}
		}
	}
	if err = scanner.Err(); err != nil {
		return nil, err
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("nenhum resolvedor DNS em /etc/resolv.conf")
	}
	return servers, nil
}
