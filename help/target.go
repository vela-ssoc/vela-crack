package help

import (
	"fmt"
	"strings"
)

type Target struct {
	File   string
	Scheme string
	Host   string
	Port   uint16
	Raw    string
}

func (t *Target) URL() string {
	if len(t.File) != 0 {
		filename := strings.ReplaceAll(t.File, "\\", "/")
		return fmt.Sprintf("%s://[%s]:%d", t.Scheme, filename, t.Port)
	}

	return fmt.Sprintf("%s://%s:%d", t.Scheme, t.Host, t.Port)
}
