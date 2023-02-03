package brute

import (
	"github.com/22ke/gordp/glog"
	gor "github.com/22ke/gordp/login"
	"github.com/spf13/cast"
	"github.com/vela-ssoc/vela-kit/lua"
)

type rdp struct {
}

func newBruteRdp(L *lua.LState) service {
	opt := L.CheckTable(1)
	port := cast.ToInt(opt.RawGetString("port").String())

	sv := &rdp{}
	return newService(L, sv, port)
}

func (r *rdp) Name() string {
	return "rdp"
}

func (r *rdp) Login(ev *event) {
	var err error
	g := gor.NewClient(ev.Server(), glog.NONE)

	err = g.LoginForSSL("", ev.User, ev.Pass)
	if err.Error() == "fail" {
		ev.Stat = Succeed
		ev.Banner = "RDP HIT"
		println("login success , ", ev.Ip, ev.User, ev.Pass)
		return
	}
	ev.Stat = Fail
	ev.Banner = "RDP fail"
	//SSL协议登录测试
	//err = g.LoginForRDP("", ev.User, ev.Pass)
	//if err == nil {
	//	println(ev.Ip, ev.User, ev.Pass)
	//	ev.Stat = Fail
	//	ev.Banner = "fail"
	//	return
	//}

	//println(err.Error())
	//if strings.Contains(err.Error(), "success") {
	//	ev.Stat = Succeed
	//	ev.Banner = "RDP HIT"
	//	println("login success , ", ev.User, ev.Pass)
	//	//o.ev(ip, user, pass, port, "rdp hit")
	//} else {
	//	println(err.Error(), ev.Server(), ev.User, ev.Pass)
	//}
}
