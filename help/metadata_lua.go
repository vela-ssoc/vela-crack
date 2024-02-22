package help

import (
	"fmt"
	"github.com/vela-ssoc/vela-kit/auxlib"
	"github.com/vela-ssoc/vela-kit/kind"
	"github.com/vela-ssoc/vela-kit/lua"
	"github.com/vela-ssoc/vela-kit/strutil"
	risk "github.com/vela-ssoc/vela-risk"
	"strings"
)

func (m *Metadata) String() string                         { return strutil.B2S(m.Bytes()) }
func (m *Metadata) Type() lua.LValueType                   { return lua.LTObject }
func (m *Metadata) AssertFloat64() (float64, bool)         { return 0, false }
func (m *Metadata) AssertString() (string, bool)           { return "", false }
func (m *Metadata) AssertFunction() (*lua.LFunction, bool) { return nil, false }
func (m *Metadata) Peek() lua.LValue                       { return m }

func (m *Metadata) happyL(L *lua.LState) int {
	m.Happy = true
	return 0
}

func (m *Metadata) URL() string {
	return fmt.Sprintf("%s://%s:%d/", m.Scheme, m.Host, m.Port)
}

func (m *Metadata) riskL(L *lua.LState) int {
	level := L.IsString(1)

	ev := risk.Brute(func(re *risk.Event) {
		re.FromCode = L.CodeVM()
		re.RemoteIP = m.Host
		re.RemotePort = int(m.Port)
		re.Payload = fmt.Sprintf("%v", m.Real.Payload)
		re.Set("url", lua.S2L(m.URL()))
		re.Set("response", lua.ToLValue(m.Response))
		re.Set("request", lua.ToLValue(m.Request))
	})

	ev.Leve(level)
	L.Push(ev)
	return 1
}

/*

	switch(metadata) {
    case "response.banner":
	case "response.code":
	case "response.http_code":
	}

	meta.md5("payload" , 1)

*/

func (m *Metadata) encodeExecL(L *lua.LState, method string) *lua.LFunction {
	var fn func(string) string

	switch method {
	case "md5":
		fn = strutil.Md5
	case "base64":
		fn = strutil.Bs64
	case "url":
		fn = strutil.URLEncode
	default:
		L.RaiseError("not found encode %s function", method)
		return nil
	}

	return L.NewFunction(func(co *lua.LState) int {
		name := L.CheckString(1)
		switch name {
		case "payload":
			idx := L.IsInt(2)
			val, ok := m.Select(idx)
			if ok {
				m.Poc.Payload[idx] = fn(val)
			}
		case "user":
			m.Poc.Username = fn(m.Poc.Username)

		case "pass":
			m.Poc.Password = fn(m.Poc.Password)
		}

		L.Push(m)
		return 1
	})

}

func (m *Metadata) NewIndex(L *lua.LState, key string, val lua.LValue) {
	switch key {
	case "username":
		m.Poc.Username = val.String()
	case "password":
		m.Poc.Password = val.String()
	}
}

func (m *Metadata) SetPayloadL(L *lua.LState) int {
	n := L.IsInt(1)
	_, ok := m.Select(n)
	if !ok {
		L.Push(m)
		return 1
	}

	val := L.CheckString(2)
	m.Poc.Payload[n] = val
	L.Push(m)
	return 1
}

/*


 */

func (m *Metadata) Index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "state":
		return lua.S2L(m.Stat.String())
	case "ok":
		return lua.LBool(m.Stat.String() == Succeed.String())

	case "response":
		return lua.ToLValue(m.Response)

	case "request":
		return lua.S2L(m.Request)
	case "error":
		if m.Cause.Len() == 0 {
			return lua.LNil
		}
		return lua.S2L(m.Cause.Wrap().Error())

	case "payload":
		return auxlib.S2Tab(m.Poc.Payload)

	case "set_payload":
		return lua.NewFunction(m.SetPayloadL)

	case "encode_md5":
		return m.encodeExecL(L, "md5")
	case "encode_bs64":
		return m.encodeExecL(L, "bs64")
	case "encode_url":
		return m.encodeExecL(L, "url")
	case "risk":
		return lua.NewFunction(m.riskL)
	case "happy":
		return lua.NewFunction(m.happyL)
	case "port":
		return lua.LInt(m.Port)
	case "scheme":
		return lua.S2L(m.Scheme)
	case "host":
		return lua.S2L(m.Host)
	case "banner":
		return lua.S2L(m.Banner)
	}

	if strings.HasPrefix(key, "r_") {
		if m.Response == nil {
			return lua.LNil
		}

		ex, err := kind.NewExtractor(m.Response, L)
		if err != nil {
			return lua.LNil
		}
		return lua.LString(ex.Peek(key[2:]))
	}

	return lua.LNil
}
