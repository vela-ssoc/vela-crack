package crack

import "github.com/vela-ssoc/vela-kit/lua"

type Config struct {
	co *lua.LState
}

func NewConfig(L *lua.LState) *Config {
	return &Config{co: xEnv.Clone(L)}
}

func (cfg *Config) Name() string {
	return "crack"
}
