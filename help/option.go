package help

import (
	"fmt"
	strutil "github.com/vela-ssoc/vela-kit/auxlib"
	"github.com/vela-ssoc/vela-kit/iputil"
	"github.com/vela-ssoc/vela-kit/lua"
	"github.com/vela-ssoc/vela-kit/pipe"
	"github.com/vela-ssoc/vela-kit/vela"
	vswitch "github.com/vela-ssoc/vela-switch"
	"net/url"
	"time"
)

type Service interface {
	Attack(*Metadata)
}

type TaskOption struct {
	LState   *lua.LState
	Pool     int
	Once     bool
	Target   *Target
	Secret   *Secret
	Intruder *Intruder
	Chains   *pipe.Chains
	Switch   *vswitch.Switch
	Encode   *pipe.Chains
	Interval time.Duration
	Driver   Service
}

func (to *TaskOption) Check() error {
	if to.Driver == nil {
		return fmt.Errorf("not found %s driver", to.Target.Scheme)
	}

	_, _, err := iputil.NewIter(to.Target.Host)
	if err != nil {
		return err
	}

	return nil
}

func NewTaskOption(L *lua.LState, xEnv vela.Environment) (*TaskOption, error) {
	var scheme string
	var host string
	var port uint16
	n := L.GetTop()

	if n != 1 && n != 3 {
		return nil, fmt.Errorf("number of incorrect parameters")
	}

	if n == 1 {
		u, err := url.Parse(L.IsString(1))
		if err != nil {
			return nil, err
		}

		scheme = u.Scheme
		host = u.Hostname()
		port = uint16(strutil.ToInt(u.Port()))
		goto TARGET
	}

	if n == 3 {
		scheme = L.IsString(1)
		host = L.IsString(2)
		port = uint16(L.IsInt(3))
		goto TARGET
	}

TARGET:
	target := &Target{
		Scheme: scheme,
		Host:   host,
		Port:   port,
	}

	tv := &TaskOption{
		LState:   xEnv.Clone(L),
		Pool:     100,
		Target:   target,
		Switch:   vswitch.NewL(L),
		Chains:   pipe.New(pipe.Env(xEnv)),
		Encode:   pipe.New(pipe.Env(xEnv)),
		Interval: time.Millisecond * 10,
		Intruder: &Intruder{
			AttackType: "sniper",
		},
	}

	return tv, nil
}
