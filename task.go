package crack

import (
	"github.com/vela-ssoc/vela-crack/help"
	"github.com/vela-ssoc/vela-kit/dict"
	"github.com/vela-ssoc/vela-kit/iputil"
	"github.com/vela-ssoc/vela-kit/lua"
	"github.com/vela-ssoc/vela-kit/thread"
	"net"
	"sync/atomic"
)

/*


 */

const (
	Skip int = iota + 1
	SkipU
)

type Secret struct {
	Username dict.Dictionary
	Password dict.Dictionary
}

type Task struct {
	lua.SuperVelaData
	option *help.TaskOption
	skip   uint32
	handle func(r *help.Metadata)
}

func (t *Task) Call(v interface{}) {
	m := v.(*help.Metadata)

	xEnv.Errorf("%v", m.Poc.Payload)

	//备份数据
	m.Backup()

	// 加解密数据
	t.option.Encode.Do(m, t.option.LState, func(err error) {
		xEnv.Errorf("crack web encode call fail %v", err)
	})

	t.option.Driver.Attack(m)

	t.option.Chains.Do(v, t.option.LState, func(e error) {
		xEnv.Errorf("crack web pipe call fail %v", e)
	})

	t.option.Switch.Do(v)

	if t.handle != nil {
		t.handle(m)
	}

	if t.option.Once && m.Happy {
		atomic.AddUint32(&t.skip, 1)
	}
}

func (t *Task) Raw(raw string) {
	t.option.Target.Raw = raw
}

func (t *Task) NoPass(name string, host string) *help.Metadata {
	m := &help.Metadata{
		Scheme: t.option.Target.Scheme,
		Host:   host,
		Port:   t.option.Target.Port,
		Raw:    t.option.Target.Raw,
		Poc: help.Poc{
			Password: "",
			Username: name,
		},
	}

	return m
}

func (t *Task) Attack(ip net.IP, port uint16) {
	ut := t.option.Secret.Username.Iterator()
	if ut == nil {
		return
	}

	defer ut.Close()

	pool, err := thread.NewPoolWithFunc(t.option.Pool, t.Call)
	if err != nil {
		return
	}

	pt := t.option.Secret.Password.Iterator()
	if pt == nil {
		return
	}
	defer pt.Close()

	for ut.Next() {
		name := ut.Text()
		for pt.Reset(); pt.Next(); {
			pass := pt.Text()
			r := &help.Metadata{
				Scheme: t.option.Target.Scheme,
				Host:   ip.String(),
				Port:   port,
				Poc: help.Poc{
					Password: pass,
					Username: name,
				},
			}

			pool.Invoke(r)
		}
	}
}

func (t *Task) Crack() {
	if t.option.Driver == nil {
		return
	}

	it, _, err := iputil.NewIter(t.option.Target.Host)
	if err != nil {
		return
	}

	for i := uint64(0); i < it.TotalNum(); i++ { // ip index
		ip := make(net.IP, len(it.GetIpByIndex(0)))
		copy(ip, it.GetIpByIndex(i)) // Note: dup copy []byte when concurrent (GetIpByIndex not to do dup copy)
		t.Attack(ip, t.option.Target.Port)
	}
}

func (t *Task) U1(v []string) { //mem
	t.option.Secret.Username = dict.NewMemory(v)
}

func (t *Task) U2(f string) error { //file
	u := dict.NewFile(f)
	if e := u.Wrap(); e != nil {
		return e
	}
	t.option.Secret.Username = u
	return nil
}

func (t *Task) P1(v []string) {
	t.option.Secret.Password = dict.NewMemory(v)
}

func (t *Task) P2(f string) error {
	p := dict.NewFile(f)
	if e := p.Wrap(); e != nil {
		return e
	}
	t.option.Secret.Password = p
	return nil
}

func NewTask(option *help.TaskOption) *Task {
	return &Task{
		option: option,
		skip:   0,
	}
}
