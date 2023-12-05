package crack

import (
	"github.com/vela-ssoc/vela-crack/help"
	"github.com/vela-ssoc/vela-kit/audit"
	"github.com/vela-ssoc/vela-kit/dict"
	"github.com/vela-ssoc/vela-kit/lua"
	"github.com/vela-ssoc/vela-kit/thread"
	"sync/atomic"
	"time"
)

func (t *Task) Payload1(v []string) {
	d := dict.NewMemory(v)
	t.option.Intruder.Payload = append(t.option.Intruder.Payload, d)
}

func (t *Task) Payload2(v string) {
	d := dict.NewFile(v)
	t.option.Intruder.Payload = append(t.option.Intruder.Payload, d)
}

func (t *Task) Skip() bool {
	if !t.option.Once {
		return false
	}

	return atomic.LoadUint32(&t.skip) > 1
}

func (t *Task) Loop(pi int, via []string, thread *Thread) {

	payload := t.option.Intruder.Payload[pi].Iterator()
	if payload == nil {
		return
	}
	defer payload.Close()

	n := len(t.option.Intruder.Payload)
	for payload.Next() && !t.Skip() {
		via[pi] = payload.Text()
		if pi == n-1 || t.option.Intruder.Single() {
			v2 := make([]string, pi+1)
			copy(v2, via)
			m := &help.Metadata{
				Scheme: t.option.Target.Scheme,
				Host:   t.option.Target.Host,
				Port:   t.option.Target.Port,
				Raw:    t.option.Target.Raw,
				Attack: t.option.Intruder.AttackType,
				Poc: help.Poc{
					Payload: v2,
				},
			}
			time.Sleep(t.option.Interval)
			thread.Invoke(m)
			continue
		}

		t.Loop(pi+1, via, thread)
	}
}

func (t *Task) doIntruder() {
	var pool *Thread

	pool = NewPoolThread(t.option.Pool, func(v interface{}) {
		t.Call(v)
		pool.Done()
	})

	defer thread.Release()

	via := make([]string, len(t.option.Intruder.Payload))

	t.Loop(0, via, pool)

	pool.Wait()

	audit.Debug("%s crack end", t.option.Target.URL()).From(t.option.LState.CodeVM()).Put()
}

func (t *Task) Intruder() {

	if len(t.option.Target.Raw) == 0 {
		return
	}

	if len(t.option.Intruder.Payload) == 0 {
		return
	}

	go t.doIntruder()

	t.V(lua.VTRun, time.Now())

}
