package config

import "flag"

type Config struct {
	BindAddress     string
	Credentials     string
	CaptiveFallback bool
	CaptiveSubnet   int
	ProxyURL        string
	LogRequests     bool
}

func LoadConfig() Config {
	cfg := Config{}
	flag.StringVar(&cfg.BindAddress, "bind", "127.0.0.1:5000", "proxy listen address")
	flag.StringVar(&cfg.Credentials, "auth", "", "Credentials user:pass for authorization, left blank to disable")
	flag.BoolVar(&cfg.CaptiveFallback, "auth-captive", true, "Captive portal fallback, subnet + user-agent binding")
	flag.IntVar(&cfg.CaptiveSubnet, "captive-subnet", 16, "Subnet value [0-32] for user's subnet binding")
	flag.BoolVar(&cfg.LogRequests, "log-requests", true, "Log requests")
	flag.StringVar(&cfg.ProxyURL, "proxy", "", "sets base proxy to use for all dial-outs. "+
		"Format: <http|https|socks5|socks5h>://[login:password@]host[:port] "+
		"Examples: http://user:password@192.168.1.1:3128, socks5://10.0.0.1:1080")
	flag.Parse()

	return cfg
}
