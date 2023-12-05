package web

import (
	"github.com/vela-ssoc/vela-crack/help"
)

type Driver struct {
	client *Client
}

func (d *Driver) Attack(h *help.Metadata) {
	if d.client == nil {
		d.client = NewWebClient(h.Raw)
	}

	d.client.Send(h)
}
