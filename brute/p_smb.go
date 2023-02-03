package brute

import (
	"github.com/spf13/cast"
	sm "github.com/stacktitan/smb/smb"
	"github.com/vela-ssoc/vela-kit/lua"
	"time"
)

type smb struct {
	timeout time.Duration
}

func newBruteSmb(L *lua.LState) service {
	opt := L.CheckTable(1)
	port := cast.ToInt(opt.RawGetString("port").String())

	sv := &smb{
		timeout: time.Duration(cast.ToInt(opt.RawGetString("timeout").String())),
	}
	return newService(L, sv, port)
}

func (s *smb) Name() string {
	return "smb"
}

func (s *smb) Login(ev *event) {
	options := sm.Options{
		Host:        ev.Ip,
		Port:        ev.Port,
		User:        ev.User,
		Password:    ev.Pass,
		Domain:      "",
		Workstation: "",
	}

	session, err := sm.NewSession(options, false)
	if err == nil {
		session.Close()
		if session.IsAuthenticated {
			ev.Stat = Succeed
			ev.Banner = "SMB HTI!"
			println("SMB HIT ", ev.Ip, ev.User, ev.Pass)
			return
			//o.ev(ip, user, pass, port, "smb hit")
		}
		ev.Stat = Fail
		ev.Banner = "SMB fail"
	} else {
		ev.Stat = Fail
		ev.Banner = "SMB fail"
		//println(pass,err.Error())
	}
}
