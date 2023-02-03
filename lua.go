package crack

import (
	"github.com/vela-ssoc/vela-crack/brute"
	"github.com/vela-ssoc/vela-crack/john"
	"github.com/vela-ssoc/vela-kit/lua"
	"github.com/vela-ssoc/vela-kit/vela"
)

var xEnv vela.Environment

func WithEnv(env vela.Environment) {
	xEnv = env
	kv := lua.NewUserKV()
	//xEnv.Set("john", lua.NewFunction(john.NewLuaCrackJohn))
	//xEnv.Set("brute", lua.NewFunction(brute.BruteL))
	//xEnv.Global()
	john.WithEnv(env, kv)
	brute.WithEnv(env, kv)
	xEnv.Set("crack", kv)
}
