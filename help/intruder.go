package help

import "github.com/vela-ssoc/vela-kit/dict"

type Intruder struct {
	Payload    []dict.Dictionary
	AttackType string
}

func (i *Intruder) Single() bool {
	if i.AttackType == "sniper" || i.AttackType == "battering_bomb" {
		return true
	}
	return false
}
