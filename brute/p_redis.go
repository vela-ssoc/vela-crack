package brute

import (
	red "github.com/go-redis/redis"
	"github.com/spf13/cast"
	"github.com/vela-ssoc/vela-kit/lua"
	"time"
)

type redis struct {
	timeout time.Duration
}

func newBruteRedis(L *lua.LState) service {
	opt := L.CheckTable(1)
	port := cast.ToInt(opt.RawGetString("port").String())

	sv := &redis{
		timeout: time.Duration(cast.ToInt(opt.RawGetString("timeout").String())),
	}
	return newService(L, sv, port)
}

func (r *redis) Name() string {
	return "redis"
}

func (r *redis) Login(ev *event) {
	opt := &red.Options{Addr: ev.Server(),
		Password:    ev.Pass,
		DB:          0,
		DialTimeout: r.timeout * time.Second}
	client := red.NewClient(opt)
	defer client.Close()
	_, err := client.Ping().Result()
	if err == nil {
		ev.Stat = Succeed
		ev.Banner = "REDIS HIT"
		println("redis success ", ev.Ip, ev.User, ev.Pass)
		//println(pass)
		//o.ev(ip, user, pass, port, "redis hit")

	} else {
		ev.Stat = Fail
		ev.Banner = "REDIS fail"
		//println("reids fail ", err.Error(), ev.Ip, ev.User, ev.Pass)
		//println(pass,err.Error())
	}
}
