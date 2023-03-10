package brute

import (
	"fmt"
	"github.com/vela-ssoc/vela-kit/audit"
	"github.com/vela-ssoc/vela-kit/cidr"
	"github.com/vela-ssoc/vela-kit/lua"
	"gopkg.in/tomb.v2"
	"net"
)

type brute struct {
	lua.VelaEntry
	cfg      *config
	queue    chan Tx
	tom      *tomb.Tomb
	ipskip   map[string]bool
	userskip map[string]bool
}

func newBrute(cfg *config) *brute {
	b := &brute{cfg: cfg}
	return b
}

func (b *brute) Name() string {
	return b.cfg.name
}

func (b *brute) Type() string {
	return typeof
}

func (b *brute) State() lua.VelaState {
	return lua.VTRun
}

func (b *brute) append(s service) {
	b.cfg.service = append(b.cfg.service, s)
}

func (b *brute) succeed(ev *event) {
	e := audit.NewEvent("crackonline success").User(ev.User).Msg("ip:%s user:%s pass:%s port:%d", ev.Ip, ev.User, ev.Pass, ev.Port)
	e.Subject(ev.Banner).From(b.cfg.co.CodeVM()).High().Alert()

	b.cfg.pipe.Do(e, b.cfg.co, func(err error) {
		xEnv.Errorf("%s call succeed pipe fail %v", b.Name(), err)
	})
}

func (b *brute) verbose(ev *event) {
	e := audit.NewEvent("crackonline err").User(ev.User).Msg("ip:%s user:%s pass:%s port:%d", ev.Ip, ev.User, ev.Pass, ev.Port)
	e.Subject(ev.Banner).From(b.cfg.co.CodeVM()).High()
	b.cfg.pipe.Do(e, b.cfg.co, func(err error) {
		xEnv.Errorf("%s call verbose pipe fail %v", b.Name(), err)
	})
}

func (b *brute) help(s service) func(net.IP) {
	fn := func(ip net.IP) {
		//ip:port是否可达
		if !s.Ping(ip) {
			xEnv.Errorf("IP %v , port: %v can not connectted! ", ip, s.port)
			b.verbose(&event{
				Ip:     ip.String(),
				Port:   s.port,
				Stat:   Unreachable,
				Banner: "ip unreachable!",
			})
			return
		}

		//开始遍历字典
		iter := b.cfg.dict.Iterator()
		defer iter.Close()
		for info := iter.Next(); !info.over; info = iter.Next() {
			select {
			case <-b.tom.Dying():
				println("dying")
				return

			default:
				if b.ipskip[ip.String()] == true {
					iter.Skip()
					break
				}
				b.queue <- Tx{ip: ip, info: info, iter: iter, service: s}
			}
		}
	}

	return fn
}

func (b *brute) async() {
	n := len(b.cfg.service)
	if n == 0 {
		return
	}
	for i := 0; i < n; i++ {
		go func(s service) {
			cidr.Visit(b.tom, b.cfg.cidr, b.help(s)) //这里会阻塞
		}(b.cfg.service[i])
	}
}

func (b *brute) Start() error {
	b.tom = new(tomb.Tomb)
	b.queue = make(chan Tx, 2048)
	go b.async()

	for i := 0; i < b.cfg.thread; i++ {
		go b.thread(i)
	}

	return nil
}

func (b *brute) Close() error {
	xEnv.Errorf("close")
	b.tom.Kill(fmt.Errorf("close"))
	close(b.queue)
	return nil
}

func (b *brute) thread(idx int) {
	xEnv.Debugf("b thread %d start", idx)
	defer func() {
		xEnv.Debugf("b thread %d close", idx)
	}()
	for tx := range b.queue {
		ev := &event{
			Ip:      tx.ip.String(),
			User:    tx.info.name,
			Pass:    tx.info.pass,
			Port:    tx.service.port,
			Service: tx.service.auth.Name(),
		}
		tx.service.Do(ev)
		switch ev.Stat {
		case Succeed:
			b.succeed(ev)
			if tx.service.skip {
				tx.iter.Skip()
				goto done
			}
			//跳过当前用户名
			tx.iter.SkipU()
		case Denied:
			//用户被锁定 跳过
			tx.iter.SkipU()
		case Fail:
		case Unreachable:
			tx.iter.Skip()
		}
	done:
		//b.verbose(ev)
	}

}
