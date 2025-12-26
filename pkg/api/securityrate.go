/*
 * Security Rate (Unified SYN + Connection Rate + UDP Flood) API types for loxicmd
 */
package api

// SecurityRate provides common API wrapper
type SecurityRate struct {
	CommonAPI
}

// SecurityRateInformationGet - wrapper for GET /config/securityrate/all
type SecurityRateInformationGet struct {
	SecurityRateInfo []SecurityRateEntry `json:"securityrateAttr"`
}

// SecurityRateConfig - Configuration payload for POST /config/securityrate
type SecurityRateConfig struct {
	SynEnabled      bool     `json:"synEnabled" yaml:"synEnabled"`
	SynThreshold    uint32   `json:"synThreshold" yaml:"synThreshold"`
	CookieThreshold uint32   `json:"cookieThreshold" yaml:"cookieThreshold"`
	ConnRateEnabled bool     `json:"connRateEnabled" yaml:"connRateEnabled"`
	RatePerSec      uint32   `json:"ratePerSec" yaml:"ratePerSec"`
	ConcurrentLimit uint32   `json:"concurrentLimit" yaml:"concurrentLimit"`
	UdpEnabled      bool     `json:"udpEnabled" yaml:"udpEnabled"`
	UdpPktThreshold uint32   `json:"udpPktThreshold" yaml:"udpPktThreshold"`
	UdpBandwidthMB  uint32   `json:"udpBandwidthMB" yaml:"udpBandwidthMB"`
	WhitelistIps    []string `json:"whitelistIps" yaml:"whitelistIps"`
}

// SecurityRateStats - runtime statistics (may be provided by API)
type SecurityRateStats struct {
	SynBlocked        uint64 `json:"synBlocked,omitempty" yaml:"synBlocked,omitempty"`
	SynPassed         uint64 `json:"synPassed,omitempty" yaml:"synPassed,omitempty"`
	SynCookies        uint64 `json:"synCookies,omitempty" yaml:"synCookies,omitempty"`
	UniqueIps         uint64 `json:"uniqueIps,omitempty" yaml:"uniqueIps,omitempty"`
	ConnBlocked       uint64 `json:"connBlocked,omitempty" yaml:"connBlocked,omitempty"`
	ConnPassed        uint64 `json:"connPassed,omitempty" yaml:"connPassed,omitempty"`
	ConcurrentBlocked uint64 `json:"concurrentBlocked,omitempty" yaml:"concurrentBlocked,omitempty"`
	UdpBlocked        uint64 `json:"udpBlocked,omitempty" yaml:"udpBlocked,omitempty"`
	UdpPassed         uint64 `json:"udpPassed,omitempty" yaml:"udpPassed,omitempty"`
	UdpBytesBlocked   uint64 `json:"udpBytesBlocked,omitempty" yaml:"udpBytesBlocked,omitempty"`
	UdpBytesPassed    uint64 `json:"udpBytesPassed,omitempty" yaml:"udpBytesPassed,omitempty"`
}

// SecurityRateEntry - Combined configuration + stats returned by API
type SecurityRateEntry struct {
	SynEnabled      bool     `json:"synEnabled" yaml:"synEnabled"`
	SynThreshold    uint32   `json:"synThreshold" yaml:"synThreshold"`
	CookieThreshold uint32   `json:"cookieThreshold" yaml:"cookieThreshold"`
	ConnRateEnabled bool     `json:"connRateEnabled" yaml:"connRateEnabled"`
	RatePerSec      uint32   `json:"ratePerSec" yaml:"ratePerSec"`
	ConcurrentLimit uint32   `json:"concurrentLimit" yaml:"concurrentLimit"`
	UdpEnabled      bool     `json:"udpEnabled" yaml:"udpEnabled"`
	UdpPktThreshold uint32   `json:"udpPktThreshold" yaml:"udpPktThreshold"`
	UdpBandwidthMB  uint32   `json:"udpBandwidthMB" yaml:"udpBandwidthMB"`
	WhitelistIps    []string `json:"whitelistIps" yaml:"whitelistIps"`
	// Stats
	SynBlocked        uint64 `json:"synBlocked,omitempty" yaml:"synBlocked,omitempty"`
	SynPassed         uint64 `json:"synPassed,omitempty" yaml:"synPassed,omitempty"`
	SynCookies        uint64 `json:"synCookies,omitempty" yaml:"synCookies,omitempty"`
	UniqueIps         uint64 `json:"uniqueIps,omitempty" yaml:"uniqueIps,omitempty"`
	ConnBlocked       uint64 `json:"connBlocked,omitempty" yaml:"connBlocked,omitempty"`
	ConnPassed        uint64 `json:"connPassed,omitempty" yaml:"connPassed,omitempty"`
	ConcurrentBlocked uint64 `json:"concurrentBlocked,omitempty" yaml:"concurrentBlocked,omitempty"`
	UdpBlocked        uint64 `json:"udpBlocked,omitempty" yaml:"udpBlocked,omitempty"`
	UdpPassed         uint64 `json:"udpPassed,omitempty" yaml:"udpPassed,omitempty"`
	UdpBytesBlocked   uint64 `json:"udpBytesBlocked,omitempty" yaml:"udpBytesBlocked,omitempty"`
	UdpBytesPassed    uint64 `json:"udpBytesPassed,omitempty" yaml:"udpBytesPassed,omitempty"`
}

type ConfigurationSecurityRateFile struct {
	TypeMeta   `yaml:",inline"`
	ObjectMeta `yaml:"metadata,omitempty"`
	Spec       SecurityRateConfig `yaml:"spec"`
}
