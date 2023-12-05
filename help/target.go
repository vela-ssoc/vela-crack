package help

import "fmt"

type Target struct {
	Scheme string
	Host   string
	Port   uint16
	Raw    string
}

func (t *Target) URL() string {
	return fmt.Sprintf("%s://%s:%d", t.Scheme, t.Host, t.Port)
}
