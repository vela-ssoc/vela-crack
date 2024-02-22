package crack

import (
	"github.com/vela-ssoc/vela-kit/lua"
	"github.com/vela-ssoc/vela-kit/vela"
)

var xEnv vela.Environment

/*
	local crack = vela.crack("crack")
	crack.start()

	crack.mysql("172.31.61.150").port(3306).u("user.txt").p("pass.txt").thread(200).run()
	crack.mysql("172.31.61.150").port(3306).u("user.txt").p("pass.txt").thread(200).run()
	crack.mysql("172.31.61.150").port(3306).u("user.txt").p("pass.txt").thread(200).run()
	crack.mysql("172.31.61.150").port(3306).u("user.txt").p("pass.txt").thread(200).run()
*/

/*

	POST /api/v1/{name}/mysql
	Host: x.x.x.x

	{
		"service":"mysql",
		"port": 3306,
		"user_file":"user.txt",
		"pass_file":"pass.txt",
		"user":"root",
		"pass":"123456",
		"thread": 100,
	}
*/

func newCrackL(L *lua.LState) int {
	cfg := NewConfig(L)
	vda := L.NewVelaData(cfg.Name(), typeof) //判断出 当前code 是否有相同的对象 名字和类型
	if vda.IsNil() {
		vda.Set(NewCrack(cfg))
		L.Push(vda)
	} else {
		old := vda.Data.(*Crack)
		old.cfg = cfg
		L.Push(vda)
	}
	return 1
}

func WithEnv(env vela.Environment) {
	xEnv = env
	xEnv.Set("crack", lua.NewExport("lua.crack.export", lua.WithFunc(newCrackL)))
}
