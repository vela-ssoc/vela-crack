package help

import (
	"fmt"
	strutil "github.com/vela-ssoc/vela-kit/auxlib"
	"github.com/vela-ssoc/vela-kit/exception"
	"github.com/vela-ssoc/vela-kit/kind"
	"net"
)

const (
	Succeed State = iota + 1
	Fail
	Unreachable
	Denied
)

type State int

func (s State) String() string {
	switch s {
	case Succeed:
		return "succeed"
	case Fail:
		return "fail"
	case Unreachable:
		return "unreachable"
	case Denied:
		return "Denied"
	default:
		return "unknown"
	}
}

type Poc struct {
	Username string
	Password string
	Payload  []string
}

type Encode struct {
	Username func(string) string
	Password func(string) string
	Payload  []func(string) string
}

type Metadata struct {
	Option   TaskOption
	Ping     *Ping
	Stat     State
	Poc      Poc
	Real     Poc
	Scheme   string
	Host     string
	Port     uint16
	Attack   string
	Request  string
	Response interface{}
	Cause    exception.Cause
	Raw      string //http
	Banner   string
	Happy    bool
	NetConn  net.Conn
}

func (m *Metadata) Bytes() []byte {
	enc := kind.NewJsonEncoder()
	enc.Tab("")
	enc.KV("state", m.Stat.String())
	enc.KV("uri", m.URI())
	enc.KV("username", m.Poc.Username)
	enc.KV("password", m.Poc.Password)
	enc.KV("response", m.Response)
	enc.KV("request", m.Request)
	if e := m.Cause.Wrap(); e != nil {
		enc.KV("cause", e.Error())
	}
	enc.End("}}")
	return enc.Bytes()
}

func (m *Metadata) URI() string {
	return fmt.Sprintf("%s://%s:%d", m.Scheme, m.Host, m.Port)
}

func (m *Metadata) Finish(s State, format string, v ...interface{}) {
	m.Stat = s
	if m.Stat != Succeed {
		m.Cause.Try(m.URI(), fmt.Errorf(format, v...))
		return
	}
	m.Banner = fmt.Sprintf(format, v...)
}

func (m *Metadata) Peer() string {
	return m.Host + ":" + strutil.ToString(m.Port)
}

func (m *Metadata) Select(i int) (string, bool) {
	if len(m.Poc.Payload)-1 >= i {
		return m.Poc.Payload[i], true
	}

	return "", false
}

func (m *Metadata) Backup() {
	m.Real = m.Poc
}

func (m *Metadata) Dail(network string) (net.Conn, error) {
	return net.Dial(network, m.Peer())
}
