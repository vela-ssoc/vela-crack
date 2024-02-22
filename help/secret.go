package help

import "github.com/vela-ssoc/vela-kit/dict"

type Secret struct {
	NoPass   bool
	Username dict.Dictionary
	Password dict.Dictionary
}
