package crack

import (
	"github.com/vela-ssoc/vela-kit/thread"
	"sync"
)

type Thread struct {
	size int
	wg   *sync.WaitGroup
	pool *thread.PoolWithFunc
}

func (t *Thread) Invoke(v interface{}) {
	t.wg.Add(1)
	t.pool.Invoke(v)
}

func (t *Thread) Done() {
	t.wg.Done()
}

func (t *Thread) Wait() {
	t.wg.Wait()
}

func (t *Thread) Release() {
	t.pool.Release()
}

func NewPoolThread(size int, callback func(interface{})) *Thread {
	t := &Thread{
		size: size,
		wg:   new(sync.WaitGroup),
	}

	t.pool, _ = thread.NewPoolWithFunc(size, callback)

	return t
}
