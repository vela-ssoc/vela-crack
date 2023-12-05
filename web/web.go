package web

import (
	"fmt"
	"github.com/vela-ssoc/vela-crack/help"
	"github.com/vela-ssoc/vela-kit/httpx"
	"github.com/vela-ssoc/vela-kit/strutil"
	"net"
	"strings"
)

const tag = '§'

type Client struct {
	raw      string
	section  []string
	position []int
	err      error
	netConn  net.Conn
}

func (cli *Client) concat(mt *help.Metadata) string {

	n := len(cli.position)
	if n == 0 {
		return cli.raw
	}

	section := make([]string, len(cli.section))
	copy(section, cli.section)

	switch mt.Attack {
	case "sniper":
		idx := cli.position[0]
		item, ok := mt.Select(0)
		if ok {
			section[idx] = item
		}
		return strings.Join(section, "")

	case "battering_ram":
		for i := 0; i < n; i++ {
			idx := cli.position[i]
			item, ok := mt.Select(0)
			if ok {
				section[idx] = item
				continue
			}
		}
		return strings.Join(section, "")
	default:
		for i := 0; i < n; i++ {
			item, ok := mt.Select(i)
			if ok {
				idx := cli.position[i]
				section[idx] = item
				continue
			}
		}
		return strings.Join(section, "")
	}
}

func (cli *Client) Connect(peer string) (net.Conn, error) {
	if cli.netConn != nil {
		return cli.netConn, nil
	}

	netConn, err := net.Dial("tcp", peer)
	if err != nil {
		return nil, err
	}

	cli.netConn = netConn

	return netConn, nil
}

func (cli *Client) Send(mt *help.Metadata) {

	mt.Request = cli.concat(mt)
	hr := httpx.NewRawHTTP()

	_, err := hr.Parse(strutil.S2B(mt.Request))
	if err != nil {
		mt.Finish(help.Fail, "new request fail %v", err)
		return
	}

	rr, err := httpx.FromRaw(mt.Request,
		httpx.WithScheme(mt.Scheme),
		httpx.WithPort(mt.Port),
		httpx.WithAddr(mt.Host))

	if err != nil {
		mt.Finish(help.Fail, "new request fail %v", err)
		return
	}

	rsp, err := httpx.Call(rr)
	if err != nil {
		mt.Finish(help.Fail, "%v", err)
		return
	}

	mt.Response = rsp
	mt.Finish(help.Succeed, "ok")
}

func (cli *Client) sub(pos int, end int, mask int) {
	var section string
	if (pos + 1) < end { // empty
		section = cli.raw[pos+1 : end-1]
	}

	cli.section = append(cli.section, section)
	if mask%2 == 0 {
		cli.position = append(cli.position, len(cli.section)-1)
	}
}

func NewWebClient(raw string) *Client {
	r := &Client{raw: raw}

	n := len(raw)
	pos := -1
	mask := 0
	for i := 0; i < n; i++ {
		if raw[i] == tag {
			mask++
			r.sub(pos, i, mask)
			pos = i
		}
	}

	if mask%2 != 0 {
		r.err = fmt.Errorf("no paired matching")
		return r
	}

	if pos != n-1 {
		r.section = append(r.section, r.raw[pos+1:])
	}

	return r
}
