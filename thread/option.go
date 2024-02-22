package thread

import (
	"github.com/vela-ssoc/vela-crack/help"
	"github.com/vela-ssoc/vela-kit/vela"
	"sync"
)

type Option struct {
	size     int
	xEnv     vela.Environment
	wg       *sync.WaitGroup
	Callback func(*help.Metadata)
	Queue    chan *help.Metadata
}

func NewOption(xEnv vela.Environment, size int) *Option {
	return &Option{
		xEnv:  xEnv,
		size:  size,
		wg:    new(sync.WaitGroup),
		Queue: make(chan *help.Metadata, size/2),
	}
}
