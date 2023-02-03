package brute

import (
	"database/sql"
	"fmt"
	_ "github.com/netxfly/mysql"
	"github.com/spf13/cast"
	"github.com/vela-ssoc/vela-kit/lua"
)

type mysql struct {
}

func newBruteMysql(L *lua.LState) service {
	opt := L.CheckTable(1)
	port := cast.ToInt(opt.RawGetString("port").String())

	sv := &mysql{
		//timeout: time.Duration(cast.ToInt(opt.RawGetString("timeout").String())),
	}
	return newService(L, sv, port)
}

func (m *mysql) Name() string {
	return "mysql"
}

func (m *mysql) Login(ev *event) {
	source := fmt.Sprintf("%v:%v@tcp(%v:%v)/%v?charset=utf8", ev.User, ev.Pass, ev.Ip, ev.Port, "mysql")
	//fmt.Printf("mysql login user:%v,pass:%v\n", ev.User, ev.Pass)
	db, err := sql.Open("mysql", source)
	if err != nil {
		return
	}
	defer db.Close()

	if e := db.Ping(); e != nil {
		ev.Stat = Fail
		ev.Banner = err.Error()
		return
	}
	ev.Stat = Succeed
	ev.Banner = "MYSQL HIT!"
	xEnv.Debugf("success :", ev.User, ev.Pass)
}
