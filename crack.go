package crack

import (
	"context"
	"github.com/vela-ssoc/vela-crack/help"
	"github.com/vela-ssoc/vela-kit/lua"
	"reflect"
	"time"
)

var typeof = reflect.TypeOf((*Crack)(nil)).String()

type Service interface {
	Attack(request *help.Metadata)
}

type Crack struct {
	lua.SuperVelaData
	cfg    *Config
	ctx    context.Context
	cancel context.CancelFunc
}

func (c *Crack) Name() string {
	return c.cfg.Name()
}

func (c *Crack) Type() string {
	return typeof
}

func (c *Crack) Start() error {
	ctx, cancel := context.WithCancel(context.Background())

	c.ctx = ctx
	c.cancel = cancel
	c.V(lua.VTRun, time.Now())
	return nil
}

func (c *Crack) Close() error {
	c.cancel()
	return nil
}

func NewCrack(cfg *Config) *Crack {
	return &Crack{cfg: cfg}
}
