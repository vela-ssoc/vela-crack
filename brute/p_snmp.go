package brute

import (
	"github.com/gosnmp/gosnmp"
	"github.com/spf13/cast"
	"github.com/vela-ssoc/vela-kit/lua"
	"time"
)

type snmp struct {
	timeout time.Duration
}

func newBruteSnmp(L *lua.LState) service {
	opt := L.CheckTable(1)
	port := cast.ToInt(opt.RawGetString("port").String())

	sv := &snmp{
		timeout: time.Duration(cast.ToInt(opt.RawGetString("timeout").String())),
	}
	return newService(L, sv, port)
}

func (s *snmp) Name() string {
	return "snmp"
}

func (s *snmp) Login(ev *event) {
	gosnmp.Default.Target = ev.Ip
	gosnmp.Default.Port = uint16(ev.Port)
	gosnmp.Default.Community = ev.Pass
	gosnmp.Default.Timeout = s.timeout

	err := gosnmp.Default.Connect()
	if err == nil {
		oids := []string{"1.3.6.1.2.1.1.4.0", "1.3.6.1.2.1.1.7.0"}
		_, err := gosnmp.Default.Get(oids)
		if err == nil {
			ev.Stat = Succeed
			ev.Banner = "SNMP HIT"
			return
			//println(pass)
			//o.ev(ip, user, pass, port, "redis hit")
		} else {
			ev.Stat = Fail
			ev.Banner = "SNMP fail"
			//println(ev.Ip, ev.User, ev.Pass, err.Error())
			return
		}
	} else {
		ev.Stat = Fail
		ev.Banner = "SNMP fail"
		//println(ev.Ip, ev.User, ev.Pass, err.Error())
		return
	}
}
