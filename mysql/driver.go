package mysql

import (
	"fmt"
	"github.com/vela-ssoc/vela-crack/help"
)

type Driver struct{}

func (d *Driver) Attack(r *help.Metadata) {

	my := &Mysql{
		Addr:       fmt.Sprintf("%s:%d", r.Host, r.Port),
		Network:    "tcp",
		Username:   r.Poc.Username,
		Password:   r.Poc.Password,
		Attributes: encodeConnectionAttributes(""),
	}

	if err := my.Dail(); err != nil {
		r.Finish(help.Unreachable, "%v", err)
		return
	}

	defer my.Close()

	data, plugin, err := my.readHandshakePacket()
	if err != nil {
		r.Finish(help.Fail, "read handshake packet fail:%v", err)
		return
	}

	authRsp, err := my.auth(data, plugin)
	if err != nil {
		r.Finish(help.Fail, "auth %v", err)
		return
	}

	if err := my.WriteHandshakeResponsePacket(authRsp, plugin); err != nil {
		r.Finish(help.Fail, "write handshake response packet %v", err)
		return
	}

	if err := my.HandleAuthResult(data, plugin); err != nil {
		r.Finish(help.Fail, "handle auth result fail:%v", err)
		return
	}

	r.Finish(help.Succeed, "plugin:%s", plugin)
}
