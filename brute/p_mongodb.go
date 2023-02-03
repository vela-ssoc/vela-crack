package brute

import (
	"fmt"
	"github.com/spf13/cast"
	"github.com/vela-ssoc/vela-kit/lua"
	"gopkg.in/mgo.v2"
	"time"
)

type mongodb struct {
	timeout time.Duration
}

func newBruteMongodb(L *lua.LState) service {
	opt := L.CheckTable(1)
	port := cast.ToInt(opt.RawGetString("port").String())

	sv := &mongodb{
		timeout: time.Duration(cast.ToInt(opt.RawGetString("timeout").String())),
	}
	if sv.timeout == 0 {
		xEnv.Errorf("mongodb timeout not set: %s , default 5", opt.RawGetString("timeout").String())
		sv.timeout = 5 * time.Second
	}
	return newService(L, sv, port)
}

func (m *mongodb) Name() string {
	return "mongodb"
}

func (m *mongodb) Login(ev *event) {
	url := fmt.Sprintf("mongodb://%v:%v@%v/%v", ev.User, ev.Pass, ev.Server(), "admin")
	session, err := mgo.DialWithTimeout(url, m.timeout)

	if err == nil {
		defer session.Close()
		err = session.Ping()
		if err == nil {
			ev.Stat = Succeed
			ev.Banner = "MONGODB HIT!"
			println("success", ev.User, ev.Pass)

		} else {
			ev.Stat = Fail
			ev.Banner = err.Error()
		}
	} else {
		ev.Stat = Unreachable
		ev.Banner = fmt.Sprintf("connect mongodb err : %s", err.Error())
	}
}
