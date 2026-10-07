package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/dolonet/mtg-multi/mtglib"
)

type Optional struct {
	Enabled TypeBool `json:"enabled"`
}

type ListConfig struct {
	Optional

	DownloadConcurrency TypeConcurrency    `json:"downloadConcurrency"`
	URLs                []TypeBlocklistURI `json:"urls"`
	UpdateEach          TypeDuration       `json:"updateEach"`
}

type Config struct {
	Debug                       TypeBool                 `json:"debug"`
	AllowFallbackOnUnknownDC    TypeBool                 `json:"allowFallbackOnUnknownDc"`
	Secret                      mtglib.Secret            `json:"secret"`
	Secrets                     map[string]mtglib.Secret `json:"secrets"`
	BindTo                      []TypeHostPort           `json:"bindTo"`
	ProxyProtocolListener       TypeBool                 `json:"proxyProtocolListener"`
	PreferIP                    TypePreferIP             `json:"preferIp"`
	AutoUpdate                  TypeBool                 `json:"autoUpdate"`
	DomainFrontingPort          TypePort                 `json:"domainFrontingPort"`
	DomainFrontingIP            TypeIP                   `json:"domainFrontingIp"`
	DomainFrontingProxyProtocol TypeBool                 `json:"domainFrontingProxyProtocol"`
	TolerateTimeSkewness        TypeDuration             `json:"tolerateTimeSkewness"`
	Concurrency                 TypeConcurrency          `json:"concurrency"`
	PublicIPv4                  TypeIP                   `json:"publicIpv4"`
	PublicIPv6                  TypeIP                   `json:"publicIpv6"`
	DomainFronting              struct {
		Host          TypeHost `json:"host"`
		IP            TypeIP   `json:"ip"`
		Port          TypePort `json:"port"`
		ProxyProtocol TypeBool `json:"proxyProtocol"`
	} `json:"domainFronting"`
	Defense struct {
		AntiReplay struct {
			Optional

			MaxSize   TypeBytes     `json:"maxSize"`
			ErrorRate TypeErrorRate `json:"errorRate"`
		} `json:"antiReplay"`
		Blocklist    ListConfig `json:"blocklist"`
		Allowlist    ListConfig `json:"allowlist"`
		Doppelganger struct {
			URLs       []TypeHttpsURL  `json:"urls"`
			Repeats    TypeConcurrency `json:"repeats_per_raid"`
			UpdateEach TypeDuration    `json:"raid_each"`
			DRS        TypeBool        `json:"drs"`
		} `json:"doppelganger"`
	} `json:"defense"`
	Network struct {
		Timeout struct {
			TCP       TypeDuration `json:"tcp"`
			HTTP      TypeDuration `json:"http"`
			Idle      TypeDuration `json:"idle"`
			Handshake TypeDuration `json:"handshake"`
		} `json:"timeout"`
		KeepAlive struct {
			Disabled TypeBool        `json:"disabled"`
			Idle     TypeDuration    `json:"idle"`
			Interval TypeDuration    `json:"interval"`
			Count    TypeConcurrency `json:"count"`
		} `json:"keepAlive"`
		DOHIP           TypeIP         `json:"dohIp"`
		DNS             TypeDNSURI     `json:"dns"`
		Proxies         []TypeProxyURL `json:"proxies"`
		TCPNotSentLowat TypeBytes      `json:"tcpNotSentLowat"`
		// ClientMSS - MSS, которым дробится ServerHello FakeTLS (0 - выкл).
		ClientMSS TypeTCPMSS `json:"clientMss"`
		// ClientMSSBulk - MSS остальной сессии; nil - ключа нет (умолчание),
		// явный 0 - вся сессия на ClientMSS.
		ClientMSSBulk *TypeTCPMSS `json:"clientMssBulk"`
	} `json:"network"`
	APIBindTo TypeHostPort `json:"apiBindTo"`
	Throttle  struct {
		MaxConnections TypeConcurrency `json:"maxConnections"`
		CheckInterval  TypeDuration    `json:"checkInterval"`
	} `json:"throttle"`
	Stats struct {
		StatsD struct {
			Optional

			Address      TypeHostPort        `json:"address"`
			MetricPrefix TypeMetricPrefix    `json:"metricPrefix"`
			TagFormat    TypeStatsdTagFormat `json:"tagFormat"`
		} `json:"statsd"`
		Prometheus struct {
			Optional

			BindTo       TypeHostPort     `json:"bindTo"`
			HTTPPath     TypeHTTPPath     `json:"httpPath"`
			MetricPrefix TypeMetricPrefix `json:"metricPrefix"`
		} `json:"prometheus"`
	} `json:"stats"`
}

func (c *Config) GetConcurrency(defaultValue uint) uint {
	if concurrency := c.Concurrency.Get(0); concurrency != 0 {
		return concurrency
	}
	return c.Concurrency.Get(defaultValue)
}

func (c *Config) GetDNS() *url.URL {
	var dohURL *url.URL

	if dohIP := c.Network.DOHIP.Get(nil); dohIP != nil {
		dohURL, _ = url.Parse("https://" + dohIP.String())
	}

	return c.Network.DNS.Get(dohURL)
}

func (c *Config) GetDomainFrontingPort(defaultValue uint) uint {
	if port := c.DomainFronting.Port.Get(0); port != 0 {
		return port
	}
	return c.DomainFrontingPort.Get(defaultValue)
}

func (c *Config) GetDomainFrontingHost() string {
	return c.DomainFronting.Host.Get("")
}

func (c *Config) GetDomainFrontingProxyProtocol(defaultValue bool) bool {
	return c.DomainFronting.ProxyProtocol.Get(false) || c.DomainFrontingProxyProtocol.Get(defaultValue)
}

func (c *Config) Validate() error {
	if len(c.Secrets) == 0 {
		if !c.Secret.Valid() {
			return fmt.Errorf("invalid secret %s", c.Secret.String())
		}
	} else {
		for name, s := range c.Secrets {
			if !s.Valid() {
				return fmt.Errorf("invalid secret %q: %s", name, s.String())
			}
		}
	}

	if len(c.BindTo) == 0 {
		return fmt.Errorf("incorrect bind-to parameter: no addresses specified")
	}

	seen := make(map[string]struct{}, len(c.BindTo))

	for _, addr := range c.BindTo {
		v := addr.Get("")
		if v == "" {
			return fmt.Errorf("incorrect bind-to parameter: empty address")
		}

		if _, ok := seen[v]; ok {
			return fmt.Errorf("duplicate bind-to address: %s", v)
		}

		seen[v] = struct{}{}
	}

	return c.validateClientMSS()
}

// Границы client-mss и client-mss-bulk. client-mss до 1460 (MSS Ethernet);
// ServerHello дробится в пространстве пользователя, поэтому годится и меньше
// минимума ядра. Но если client-mss-bulk = 0, client-mss ставится прямо на
// сокет, а ядро не принимает TCP_MAXSEG меньше TCP_MIN_MSS (88). bulk не
// меньше классических 536 и не больше предела ядра (MAX_TCP_WINDOW).
const (
	ClientMSSMin       = 48
	ClientMSSMax       = 1460
	ClientMSSKernelMin = 88
	ClientMSSBulkMin   = 536
	ClientMSSBulkMax   = 65495

	// DefaultClientMSSBulk - MSS сессии после ServerHello, если
	// client-mss задан, а client-mss-bulk нет.
	DefaultClientMSSBulk = 1400
)

func (c *Config) validateClientMSS() error {
	mss := c.Network.ClientMSS.Get(0)
	if mss != 0 && (mss < ClientMSSMin || mss > ClientMSSMax) {
		return fmt.Errorf("network.client-mss must be 0 or %d..%d, got %d",
			ClientMSSMin, ClientMSSMax, mss)
	}

	if c.Network.ClientMSSBulk == nil {
		return nil
	}

	bulk := c.Network.ClientMSSBulk.Get(0)
	if bulk != 0 && (bulk < ClientMSSBulkMin || bulk > ClientMSSBulkMax) {
		return fmt.Errorf("network.client-mss-bulk must be 0 or %d..%d, got %d",
			ClientMSSBulkMin, ClientMSSBulkMax, bulk)
	}

	if mss != 0 && bulk == 0 && mss < ClientMSSKernelMin {
		return fmt.Errorf("network.client-mss must be at least %d when network.client-mss-bulk = 0, got %d",
			ClientMSSKernelMin, mss)
	}

	if mss != 0 && bulk != 0 && bulk <= mss {
		return fmt.Errorf("network.client-mss-bulk (%d) must be greater than network.client-mss (%d)",
			bulk, mss)
	}

	return nil
}

// GetClientMSS возвращает MSS для ServerHello и MSS остальной сессии.
// client-mss = 0 - всё выключено (0, 0), client-mss-bulk без client-mss
// ни на что не влияет. bulk = 0 - вся сессия идёт на client-mss, как с
// iptables TCPMSS на SYN клиента.
func (c *Config) GetClientMSS() (handshake, bulk uint) {
	handshake = c.Network.ClientMSS.Get(0)
	if handshake == 0 {
		return 0, 0
	}

	if c.Network.ClientMSSBulk == nil {
		return handshake, DefaultClientMSSBulk
	}

	return handshake, c.Network.ClientMSSBulk.Get(0)
}

// GetSecrets returns all secrets as a map. If the new [secrets] section is used,
// returns that map. Otherwise, wraps the single Secret as {"default": Secret}.
func (c *Config) GetSecrets() map[string]mtglib.Secret {
	if len(c.Secrets) > 0 {
		return c.Secrets
	}

	return map[string]mtglib.Secret{"default": c.Secret}
}

// GetBindAddrs returns all bind addresses as strings.
func (c *Config) GetBindAddrs() []string {
	addrs := make([]string, len(c.BindTo))

	for i, hp := range c.BindTo {
		addrs[i] = hp.Get("")
	}

	return addrs
}

// GetFirstBindPort returns the port of the first bind address.
func (c *Config) GetFirstBindPort() uint {
	if len(c.BindTo) == 0 {
		return 0
	}

	return c.BindTo[0].Port
}

func (c *Config) String() string {
	buf := &bytes.Buffer{}
	encoder := json.NewEncoder(buf)

	encoder.SetEscapeHTML(false)

	if err := encoder.Encode(c); err != nil {
		panic(err)
	}

	return buf.String()
}
