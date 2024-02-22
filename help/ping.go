package help

import (
	"fmt"
	"net"
)

type Ping struct {
	Host string
	Port uint16
	Conn net.Conn
	Err  error
}

func NewPing(host string, port uint16) *Ping {
	return &Ping{
		Host: host,
		Port: port,
	}
}

func (p *Ping) Ok() bool {
	return p.Err == nil
}

func (p *Ping) Close() {
	if p.Conn != nil {
		p.Conn.Close()
	}
}

func (p *Ping) Exec(network string) *Ping {
	//switch network {
	//case "tcp":

	//}

	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", p.Host, p.Port))
	p.Conn = conn
	p.Err = err

	return p
}
