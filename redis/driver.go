package redis

import (
	"bytes"
	"github.com/vela-ssoc/vela-crack/help"
	"github.com/vela-ssoc/vela-kit/buffer"
	"github.com/vela-ssoc/vela-kit/strutil"
	"net"
	"time"
)

type Driver struct{}

func (d *Driver) Auth(pass string) *buffer.Byte {
	buf := buffer.Get()
	if pass != "" {
		buf.WriteString("AUTH ")
		buf.WriteString(pass)
	}
	buf.WriteString("\r\n*1\r\n$4\r\nPING\r\n")
	return buf
}

func (d *Driver) reset(mt *help.Metadata) {
	mt.Poc.Username = ""
}

func (d *Driver) Attack(mt *help.Metadata) {
	var conn net.Conn
	var err error
	if mt.NetConn != nil {
		conn = mt.NetConn
	} else {
		conn, err = net.Dial("tcp", mt.Peer())
		if err != nil {
			mt.Finish(help.Fail, "%v", err)
			return
		}
		defer conn.Close()
	}

	d.reset(mt)

	auth := d.Auth(mt.Poc.Password)
	defer func() {
		buffer.Put(auth)
	}()

	timeout := time.Now().Add(time.Millisecond * 1000)
	conn.SetWriteDeadline(timeout)
	_, err = conn.Write(auth.Bytes())
	if err != nil {
		mt.Finish(help.Fail, "%v", err)
		return
	}
	conn.SetReadDeadline(timeout)

	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		mt.Finish(help.Fail, "%v", err)
		return
	}
	buf = buf[:n]

	if len(mt.Poc.Password) == 0 && bytes.Contains(buf, []byte("+PONG")) {
		mt.Finish(help.Succeed, strutil.B2S(buf))
		return
	}

	if len(mt.Poc.Password) != 0 && bytes.Contains(buf, []byte("+OK")) {
		mt.Finish(help.Succeed, strutil.B2S(buf))
		return
	}
	mt.Finish(help.Fail, strutil.B2S(buf))
}
