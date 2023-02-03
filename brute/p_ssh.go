package brute

import (
	"github.com/spf13/cast"
	"github.com/vela-ssoc/vela-kit/auxlib"
	"github.com/vela-ssoc/vela-kit/lua"
	"golang.org/x/crypto/ssh"
	"net"
	"time"
)

type sshd struct {
	timeout time.Duration
}

func newBruteSsh(L *lua.LState) service {
	opt := L.CheckTable(1)
	port := cast.ToInt(opt.RawGetString("port").String())

	sv := &sshd{
		timeout: time.Duration(cast.ToInt(opt.RawGetString("timeout").String())),
	}
	return newService(L, sv, port)
}

func (s *sshd) Name() string {
	return "ssh"
}

func (s *sshd) Login(ev *event) {
	if s.timeout == 0 {
		s.timeout = time.Duration(3)
	}

	cfg := &ssh.ClientConfig{
		User: ev.User,
		Auth: []ssh.AuthMethod{
			ssh.Password(ev.Pass),
		},
		Timeout: s.timeout * time.Second,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}
	sv := ev.Server()
	client, err := ssh.Dial("tcp", sv, cfg)
	//fmt.Printf("ssh login user:%v,pass:%v\n", ev.User, ev.Pass)
	if err == nil {
		xEnv.Error("连接成功：", ev.Ip, ev.User, ":", ev.Pass)
		defer client.Close()
		ev.Stat = Succeed
		ev.Banner = auxlib.B2S(client.ServerVersion())
	} else { //密码错误
		//println("密码错误: ",err.Error())
		ev.Stat = Fail
		ev.Banner = err.Error()
	}
}

//func (s *sshd) Index(L *lua.LState, key string) lua.LValue {
//	switch key {
//	case "timeout":
//		//s.timeout = time.Duration(3)
//	}
//	return lua.LNil
//}
