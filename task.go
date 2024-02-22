package crack

import (
	"github.com/vela-ssoc/vela-crack/help"
	"github.com/vela-ssoc/vela-crack/thread"
	"github.com/vela-ssoc/vela-kit/audit"
	strutil "github.com/vela-ssoc/vela-kit/auxlib"
	"github.com/vela-ssoc/vela-kit/dict"
	"github.com/vela-ssoc/vela-kit/iputil"
	"github.com/vela-ssoc/vela-kit/lua"
	"net"
	"strings"
	"sync/atomic"
	"time"
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

func (t *Task) Call(m *help.Metadata) {

	//备份数据
	m.Backup()

	// 加解密数据
	t.option.Encode.Do(m, t.option.LState, func(err error) {
		xEnv.Errorf("crack web encode call fail %v", err)
	})

	t.option.Driver.Attack(m)

	t.option.Chains.Do(m, t.option.LState, func(e error) {
		xEnv.Errorf("crack web pipe call fail %v", e)
	})

	t.option.Switch.Do(m)

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

func (t *Task) Attack(host string, port uint16) {
	audit.Debug("%s://%s:%d crack start", t.option.Target.Scheme, host, port).From(t.option.LState.CodeVM()).Put()

	//detect host live
	ping := help.NewPing(host, port).Exec("tcp")
	if !ping.Ok() {
		audit.Debug("%s://%s:%d Unable to connect", t.option.Target.Scheme, host, port).From(t.option.LState.CodeVM()).Put()
		return
	}
	defer ping.Close()

	pool := thread.New(xEnv, t.option.Pool, t.Call)
	defer pool.Close()

	ut := t.option.Secret.Username.Iterator()
	if ut == nil {
		return
	}
	defer ut.Close()

	pt := t.option.Secret.Password.Iterator()
	if pt == nil {
		return
	}
	defer pt.Close()

	meta := func(name, pass string) *help.Metadata {
		return &help.Metadata{
			Scheme: t.option.Target.Scheme,
			Host:   host,
			Port:   port,
			Poc: help.Poc{
				Password: pass,
				Username: name,
			},
			Ping: ping,
		}
	}

	for ut.Next() && !t.Skip() {
		name := ut.Text()
		if t.option.Secret.NoPass {
			pool.Invoke(meta(name, ""))
		}

		for pt.Reset(); pt.Next() && !t.Skip(); {
			pass := pt.Text()
			time.Sleep(t.option.Interval)
			pool.Invoke(meta(name, pass))
		}
	}

	pool.Wait()
}

func (t *Task) Exploit() {
	if t.option.Driver == nil {
		return
	}

	//file exploit
	if t.option.Target.File != "" {
		iter := dict.NewFile(t.option.Target.File).Iterator()
		if iter == nil {
			audit.Debug("%s crack file fail", t.option.Target.URL()).From(t.option.LState.CodeVM()).Put()
			return
		}
		defer iter.Close()

		for iter.Next() && !t.Skip() {
			line := iter.Text()
			host, port, err := net.SplitHostPort(strings.TrimSpace(line))
			if err != nil {
				audit.Debug("%s crack parse fail:%v", line, err).From(t.option.LState.CodeVM()).Put()
				continue
			}

			if p := strutil.ToInt(port); p != 0 {
				t.Attack(host, uint16(p))
				continue
			}

			t.Attack(host, t.option.Target.Port)
			audit.Debug("%s crack end", t.option.Target.URL()).From(t.option.LState.CodeVM()).Put()
		}

		return
	}

	_, _, err := net.ParseCIDR(t.option.Target.Host)
	if err == nil {
		it, _, err := iputil.NewIter(t.option.Target.Host)
		if err != nil {
			audit.Debug("%s crack end", t.option.Target.URL()).From(t.option.LState.CodeVM()).Put()
			return
		}

		for i := uint64(0); i < it.TotalNum(); i++ { // ip index
			ip := make(net.IP, len(it.GetIpByIndex(0)))
			copy(ip, it.GetIpByIndex(i)) // Note: dup copy []byte when concurrent (GetIpByIndex not to do dup copy)
			t.Attack(ip.String(), t.option.Target.Port)
		}
		audit.Debug("%s crack end", t.option.Target.URL()).From(t.option.LState.CodeVM()).Put()
		return
	}

	t.Attack(t.option.Target.Host, t.option.Target.Port)
	audit.Debug("%s crack end", t.option.Target.URL()).From(t.option.LState.CodeVM()).Put()
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
