package crack

import (
	"github.com/vela-ssoc/vela-crack/ftp"
	"github.com/vela-ssoc/vela-crack/mysql"
	"github.com/vela-ssoc/vela-crack/redis"
	"github.com/vela-ssoc/vela-crack/web"
)

func ServiceMapping(scheme string) Service {
	switch scheme {
	case "mysql":
		return &mysql.Driver{}
	case "redis":
		return &redis.Driver{}
	case "ftp":
		return &ftp.Driver{}
	case "http", "https":
		return &web.Driver{}

	default:
		return nil
	}

}
