package thread

import (
	"github.com/vela-ssoc/vela-crack/help"
	"github.com/vela-ssoc/vela-kit/vela"
	"net"
)

type Pool struct {
	option  *Option
	netPool []net.Conn
}

func (p *Pool) Invoke(m *help.Metadata) {
	p.option.Queue <- m
}

func (p *Pool) Add(delta int) {
	p.option.wg.Add(1)
}

func (p *Pool) Done() {
	p.option.wg.Done()
}

func (p *Pool) Wait() {
	p.option.wg.Wait()
}

func (p *Pool) NetPool(network, addr string) {
	for i := 0; i < p.option.size; i++ {
		p.netPool[i], _ = net.Dial(network, addr)
	}
}

func (p *Pool) Net(i int) net.Conn {
	n := len(p.netPool)
	if n == 0 {
		return nil
	}

	return p.netPool[i]
}

func (p *Pool) exec(i int) {

	//p.xEnv.Errorf("creak thread.%d start", i)
	for m := range p.option.Queue {
		p.Add(1)
		m.NetConn = p.Net(i)
		p.option.Callback(m)
	}
	//p.xEnv.Errorf("creak thread.%d exit", i)
}

func (p *Pool) Start() {
	for i := 0; i < p.option.size; i++ {
		go p.exec(i)
	}
}

func (p *Pool) Close() {
	close(p.option.Queue)
}

func New(xEnv vela.Environment, size int, callback func(*help.Metadata)) *Pool {
	opt := NewOption(xEnv, size)

	opt.Callback = func(v *help.Metadata) {
		callback(v)
		opt.wg.Done()
	}
	pool := &Pool{option: opt}
	pool.Start()
	return pool
}
