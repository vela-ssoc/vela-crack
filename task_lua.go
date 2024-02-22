package crack

import (
	"github.com/vela-ssoc/vela-kit/auxlib"
	"github.com/vela-ssoc/vela-kit/lua"
	"github.com/vela-ssoc/vela-kit/pipe"
	"reflect"
	"sync/atomic"
	"time"
)

var taskTypeOf = reflect.TypeOf((*Task)(nil)).String()

func (t *Task) Start() error {
	return nil
}

func (t *Task) Close() error {
	atomic.AddUint32(&t.skip, 100)
	return nil
}

func (t *Task) Type() string {
	return taskTypeOf
}

func (t *Task) Name() string {
	return t.option.Target.URL()
}

func (t *Task) VelaData() *lua.VelaData {
	return lua.NewVelaData(t)
}

func (t *Task) attackL(L *lua.LState) int {
	go t.Exploit()
	t.V(lua.VTRun, time.Now())
	return 0
}

func (t *Task) usernameL(L *lua.LState) int {
	payload := auxlib.LToSS(L)
	t.U1(payload)
	L.Push(t.VelaData())
	return 1
}

func (t *Task) passwdL(L *lua.LState) int {
	payload := auxlib.LToSS(L)
	t.P1(payload)
	L.Push(t.VelaData())
	return 1
}

func (t *Task) usernameFileL(L *lua.LState) int {
	filename := L.IsString(1)
	err := t.U2(filename)
	if err != nil {
		L.RaiseError("%v", err)
	}

	L.Push(t.VelaData())
	return 1
}

func (t *Task) passwdFileL(L *lua.LState) int {
	filename := L.IsString(1)
	err := t.P2(filename)
	if err != nil {
		L.RaiseError("%v", err)
	}

	L.Push(t.VelaData())
	return 1
}

func (t *Task) payloadL(L *lua.LState) int {
	payload := auxlib.LToSS(L)
	t.Payload1(payload)
	L.Push(t.VelaData())
	return 1
}

func (t *Task) PayloadL(L *lua.LState) int {
	filename := L.IsString(1)
	if len(filename) == 0 {
		L.RaiseError("filename empty")
		return 0
	}

	_, _, _, err := auxlib.FileStatByFile(L.IsString(1))
	if err != nil {
		L.RaiseError("%v", err)
		return 0
	}

	t.Payload2(filename)
	L.Push(t.VelaData())
	return 1
}

func (t *Task) intruderL(L *lua.LState) int {
	t.Intruder()
	return 0
}

func (t *Task) rawL(L *lua.LState) int {
	raw := L.IsString(1)
	if len(raw) == 0 {
		L.RaiseError("raw empty")
		return 0
	}

	t.Raw(raw)
	L.Push(t.VelaData())
	return 1
}

func (t *Task) pipeL(L *lua.LState) int {
	chains := pipe.NewByLua(L)
	t.option.Chains.Merge(chains)
	L.Push(t.VelaData())
	return 1
}

func (t *Task) onceL(L *lua.LState) int {
	t.option.Once = true
	L.Push(t.VelaData())
	return 1
}

/*
	crack.task("https" , "192.168.100.10" , 80)
		 .u("admin" , "root" , "system")
         .payload("abc", "bcd" , "efe")
         .Payload("abc.txt")
         .sniper().intruder()
	task.encode(function(meta)
		meta.encode_md5()
		local v = vela.crypto.md5(u)
	end)
*/

func (t *Task) modeL(L *lua.LState) int {
	at := L.CheckString(1)

	t.option.Intruder.AttackType = at
	L.Push(t.VelaData())
	return 1
}

func (t *Task) encodeL(L *lua.LState) int {
	chains := pipe.NewByLua(L)
	t.option.Encode.Merge(chains)
	L.Push(t.VelaData())
	return 1
}

func (t *Task) threadL(L *lua.LState) int {
	n := L.IsInt(1)
	if n > 0 {
		t.option.Pool = n
	}
	L.Push(t.VelaData())
	return 1
}

func (t *Task) intervalL(L *lua.LState) int {
	n := L.IsInt(1)
	if n < 5 {
		t.option.Interval = time.Duration(5) * time.Millisecond
	} else {
		t.option.Interval = time.Duration(n) * time.Millisecond
	}
	L.Push(t.VelaData())
	return 1
}

func (t *Task) NoPassL(L *lua.LState) int {
	t.option.Secret.NoPass = L.IsTrue(1)
	L.Push(t.VelaData())
	return 1
}

func (t *Task) Index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "raw":
		return lua.NewFunction(t.rawL)
	case "interval":
		return lua.NewFunction(t.intervalL)
	case "u":
		return lua.NewFunction(t.usernameL)
	case "U":
		return lua.NewFunction(t.usernameFileL)
	case "p":
		return lua.NewFunction(t.passwdL)
	case "P":
		return lua.NewFunction(t.passwdFileL)
	case "empty":
		return lua.NewFunction(t.NoPassL)
	case "payload":
		return lua.NewFunction(t.payloadL)
	case "Payload":
		return lua.NewFunction(t.PayloadL)
	case "thread":
		return lua.NewFunction(t.threadL)
	case "pipe":
		return lua.NewFunction(t.pipeL)
	case "case":
		return t.option.Switch.Index(L, key)
	case "once":
		return lua.NewFunction(t.onceL)
	case "attack":
		return lua.NewFunction(t.attackL)
	case "mode":
		return lua.NewFunction(t.modeL)
	case "encode":
		return lua.NewFunction(t.encodeL)
	case "intruder":
		return lua.NewFunction(t.intruderL)
	default:
		return lua.LNil
	}

}
