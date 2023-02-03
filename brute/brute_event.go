package brute

import (
	"github.com/vela-ssoc/vela-kit/lua"
	"strconv"
)

type event struct {
	Ip      string `json:"ip"`
	Port    int    `json:"port"`
	User    string `json:"user"`
	Pass    string `json:"pass"`
	Stat    State  `json:"stat"`
	Service string `json:"service"`
	Banner  string `json:"banner"`
}

func (ev *event) ToLValue() lua.LValue {
	return lua.NewAnyData(&ev)
}

func (ev *event) Server() string {
	return ev.Ip + ":" + strconv.Itoa(ev.Port)
}
