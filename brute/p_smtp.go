package brute

import (
	"crypto/tls"
	"github.com/spf13/cast"
	"github.com/vela-ssoc/vela-kit/lua"
	sm "net/smtp"
	"strings"
)

type smtp struct {
}

func newBruteSmtp(L *lua.LState) service {
	opt := L.CheckTable(1)
	port := cast.ToInt(opt.RawGetString("port").String())

	sv := &smtp{}
	return newService(L, sv, port)
}

func (s *smtp) Name() string {
	return "smtp"
}
func (s *smtp) Login(ev *event) {
	str := ev.Server()
	c, err := sm.Dial(str)
	if err != nil {
		//println("dial",err.Error())
		xEnv.Errorf("dial %s err : %s", ev.Ip, err.Error())
		return
	}
	auth := sm.PlainAuth("", ev.User, ev.Pass, ev.Ip)

	if ok, _ := c.Extension("STARTTLS"); ok {
		config := &tls.Config{ServerName: ev.Ip, InsecureSkipVerify: true}
		if err = c.StartTLS(config); err != nil {
			//println("call start tls")
			//return err
		}
	}
	if auth != nil {
		if ok, _ := c.Extension("AUTH"); ok {
			if err = c.Auth(auth); err != nil {
				if strings.Contains(err.Error(), "504 Unrecognized authentication type") {
					xEnv.Errorf("smtp crack error: 线程数量过多！ %s", err.Error())
					return
				}
				//xEnv.Errorf("smtp crack error:  %s,%s,%s,%s", err.Error(), ev.Ip, ev.User, ev.Pass)
				//密码错误
			} else {
				ev.Stat = Succeed
				ev.Banner = "SMTP HIT"
				println("SMTP HIT ", ev.Ip, ev.User, ev.Pass)
				return
				//println(user,pass)
				//o.ev(ip, user, pass, port, "smtp hit")
			}
		}

	}
}
