package brute

import (
	"fmt"
	"github.com/jlaffaye/ftp"
	"github.com/spf13/cast"
	"github.com/vela-ssoc/vela-kit/lua"
	"strings"
	"time"
)

type Ftp struct {
	timeout time.Duration
}

func newBruteFtp(L *lua.LState) service {
	val := L.CheckTable(1)
	port := cast.ToInt(val.RawGetString("port").String())

	e := &Ftp{
		timeout: time.Duration(cast.ToInt(val.RawGetString("timeout").String())),
	}
	if e.timeout == 0 {
		xEnv.Errorf("ftp timeout not set: %s , default 5", val.RawGetString("timeout").String())
		e.timeout = 5 * time.Second
	}

	//println("timeout: ", e.timeout)
	return newService(L, e, port)
}

func (f *Ftp) Name() string {
	return "ftp"
}

func (f *Ftp) Login(ev *event) {
	conn, err := ftp.DialTimeout(ev.Server(), f.timeout)

	if err != nil {
		ev.Stat = Fail
		ev.Banner = err.Error()
		return
	}

	err = conn.Login(ev.User, ev.Pass)
	if err != nil {
		//println("fail \n", ev.User,ev.Pass)
		ev.Banner = err.Error()
		if strings.Contains(ev.Banner, "Permission denied") {
			ev.Stat = Denied
			ev.Banner = fmt.Sprintf("FTP IP:%s,User:%s denied!", ev.Ip, ev.Pass)
		} else {
			ev.Stat = Fail
			ev.Banner = fmt.Sprintf("FTP IP:%s,User:%s denied!", ev.Ip, ev.Pass)
		}
		return
	}
	defer conn.Logout()

	ev.Stat = Succeed
	ev.Banner = "FTP!"
	println("success ", ev.User, ev.Pass)
}
