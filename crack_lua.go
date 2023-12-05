package crack

import (
	"github.com/vela-ssoc/vela-crack/help"
	"github.com/vela-ssoc/vela-kit/lua"
)

func (c *Crack) startL(L *lua.LState) int {
	xEnv.Start(L, c).From(L.CodeVM()).Err(func(err error) {
		L.RaiseError("%v", err)
	}).Do()
	return 0
}

func (c *Crack) NewTask(L *lua.LState) int {
	opt, err := help.NewTaskOption(L, xEnv)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.S2L(err.Error()))
		return 2
	}

	opt.Driver = ServiceMapping(opt.Target.Scheme)

	if e := opt.Check(); e != nil {
		L.Push(lua.LNil)
		L.Push(lua.S2L(e.Error()))
		return 2
	}

	vda := L.NewVelaData(opt.Target.URL(), taskTypeOf)
	if vda.IsNil() {
		vda.Set(NewTask(opt))
		L.Push(vda)
	} else {
		old := vda.Data.(*Task)
		old.option = opt
		L.Push(vda)
	}

	return 1
}

func (c *Crack) Index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "task":
		return lua.NewFunction(c.NewTask)
	case "start":
		return lua.NewFunction(c.startL)
	default:
		return lua.LNil
	}
}
