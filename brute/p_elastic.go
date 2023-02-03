package brute

import (
	"github.com/olivere/elastic/v7"
	"github.com/spf13/cast"
	"github.com/vela-ssoc/vela-kit/lua"
)

type Elastic struct {
	scheme string
}

func (ec *Elastic) Name() string {
	return "elastic"
}

func newBruteElastic(L *lua.LState) service {
	val := L.CheckTable(1)
	port := cast.ToInt(val.RawGetString("port").String())
	scheme := val.RawGetString("scheme").String()
	if scheme == "" {
		scheme = "http"
	}
	e := &Elastic{scheme: scheme}
	return newService(L, e, port)
}

func (ec *Elastic) Login(ev *event) {
	_, err := elastic.NewClient(elastic.SetURL(ec.scheme+"://"+ev.Server()),
		elastic.SetSniff(false),
		elastic.SetBasicAuth(ev.User, ev.Pass),
	)

	if err == nil {
		ev.Stat = Succeed
		ev.Banner = "ELASTIC"
		println("success: ", ev.User, ev.Pass)
	} else {
		ev.Stat = Fail
		ev.Banner = err.Error()
	}
}
