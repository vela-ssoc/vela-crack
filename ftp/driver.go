package ftp

import (
	"github.com/vela-ssoc/vela-crack/help"
	"time"
)

type Driver struct{}

func (d *Driver) Attack(mt *help.Metadata) {
	c, err := Dial(mt.Peer(), DialWithTimeout(1000*time.Millisecond))
	if err != nil {
		mt.Finish(help.Fail, "connection fail %v", err)
		return
	}
	defer c.Quit()

	err = c.Login(mt.Poc.Username, mt.Poc.Password)
	if err != nil {
		mt.Finish(help.Fail, "login fail %v", err)
		return
	}
	mt.Finish(help.Succeed, "")
}
