package signer

import (
	"errors"
	"fmt"
	"os"
	"strconv"
)

// Config holds the signer service configuration, sourced entirely from the
// environment so no secrets live on disk in the repo.
//
// MLRT env vars:
//
//	SIGNER_BIND_ADDR      listen address (default 127.0.0.1:8088 — private only)
//	SIGNER_TOKEN          bearer token; MUST equal CoinDock's COINDOCK_SIGNER_TOKEN
//	MLRT_ACCOUNT_XPUB     BIP32 account xpub (PUBLIC) for m/44'/<mlrt>'/0'
//	MLRT_BIP44_CHANGE     change level derived before the index (default 0)
//	MLRT_ADDRESS_VERSION  Base58 version byte: 50 mainnet 'M', 111 testnet 'm'
//	MLRT_SELFTEST_INDEX   optional: index whose derived address must equal …
//	MLRT_SELFTEST_ADDRESS optional: … this known address, or the service refuses
//	                      to start (guards against a wrong xpub/path).
//
// ETH env vars (OPTIONAL — ETH derivation is only enabled when ETH_ACCOUNT_XPUB
// is set; otherwise /v1/derive for ETH returns unsupported, exactly as before):
//
//	ETH_ACCOUNT_XPUB      BIP32 account xpub (PUBLIC) for m/44'/60'/0'
//	ETH_BIP44_CHANGE      change level derived before the index (default 0)
//	ETH_SELFTEST_INDEX    optional boot self-test index …
//	ETH_SELFTEST_ADDRESS  … expected EIP-55 0x address for that index.
type Config struct {
	BindAddr string
	Token    string

	MLRTAccountXpub    string
	MLRTChange         uint32
	MLRTAddressVersion byte
	SelfTestIndex      *uint32
	SelfTestAddress    string

	ETHAccountXpub   string
	ETHChange        uint32
	ETHSelfTestIndex *uint32
	ETHSelfTestAddr  string

	BTCAccountXpub   string
	BTCChange        uint32
	BTCHRP           string // "bc" mainnet, "tb" testnet
	BTCSelfTestIndex *uint32
	BTCSelfTestAddr  string
}

// LoadConfig reads and validates configuration from the environment.
func LoadConfig() (*Config, error) {
	cfg := &Config{
		BindAddr:           getenvDefault("SIGNER_BIND_ADDR", "127.0.0.1:8088"),
		Token:              os.Getenv("SIGNER_TOKEN"),
		MLRTAccountXpub:    os.Getenv("MLRT_ACCOUNT_XPUB"),
		MLRTChange:         0,
		MLRTAddressVersion: 50, // 'M' mainnet
		ETHAccountXpub:     os.Getenv("ETH_ACCOUNT_XPUB"),
		ETHChange:          0,
		BTCAccountXpub:     os.Getenv("BTC_ACCOUNT_XPUB"),
		BTCChange:          0,
		BTCHRP:             getenvDefault("BTC_HRP", "bc"),
	}

	if err := parseUint31Env("MLRT_BIP44_CHANGE", &cfg.MLRTChange); err != nil {
		return nil, err
	}
	if v := os.Getenv("MLRT_ADDRESS_VERSION"); v != "" {
		n, err := strconv.ParseUint(v, 10, 8)
		if err != nil {
			return nil, fmt.Errorf("MLRT_ADDRESS_VERSION: %w", err)
		}
		cfg.MLRTAddressVersion = byte(n)
	}
	if idx, err := parseOptIndexEnv("MLRT_SELFTEST_INDEX"); err != nil {
		return nil, err
	} else {
		cfg.SelfTestIndex = idx
	}
	cfg.SelfTestAddress = os.Getenv("MLRT_SELFTEST_ADDRESS")

	if err := parseUint31Env("ETH_BIP44_CHANGE", &cfg.ETHChange); err != nil {
		return nil, err
	}
	if idx, err := parseOptIndexEnv("ETH_SELFTEST_INDEX"); err != nil {
		return nil, err
	} else {
		cfg.ETHSelfTestIndex = idx
	}
	cfg.ETHSelfTestAddr = os.Getenv("ETH_SELFTEST_ADDRESS")

	if err := parseUint31Env("BTC_BIP44_CHANGE", &cfg.BTCChange); err != nil {
		return nil, err
	}
	if idx, err := parseOptIndexEnv("BTC_SELFTEST_INDEX"); err != nil {
		return nil, err
	} else {
		cfg.BTCSelfTestIndex = idx
	}
	cfg.BTCSelfTestAddr = os.Getenv("BTC_SELFTEST_ADDRESS")

	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// ETHEnabled reports whether ETH derivation is configured.
func (c *Config) ETHEnabled() bool {
	return c.ETHAccountXpub != ""
}

// BTCEnabled reports whether BTC derivation is configured.
func (c *Config) BTCEnabled() bool {
	return c.BTCAccountXpub != ""
}

func (c *Config) validate() error {
	if c.Token == "" {
		return errors.New("SIGNER_TOKEN is required")
	}
	if len(c.Token) < 24 {
		return errors.New("SIGNER_TOKEN is too short; use a long random secret (>= 24 chars)")
	}
	if c.MLRTAccountXpub == "" {
		return errors.New("MLRT_ACCOUNT_XPUB is required")
	}
	if (c.SelfTestIndex == nil) != (c.SelfTestAddress == "") {
		return errors.New("MLRT_SELFTEST_INDEX and MLRT_SELFTEST_ADDRESS must be set together")
	}
	if (c.ETHSelfTestIndex == nil) != (c.ETHSelfTestAddr == "") {
		return errors.New("ETH_SELFTEST_INDEX and ETH_SELFTEST_ADDRESS must be set together")
	}
	if c.ETHSelfTestIndex != nil && !c.ETHEnabled() {
		return errors.New("ETH_SELFTEST_* set but ETH_ACCOUNT_XPUB is empty")
	}
	if (c.BTCSelfTestIndex == nil) != (c.BTCSelfTestAddr == "") {
		return errors.New("BTC_SELFTEST_INDEX and BTC_SELFTEST_ADDRESS must be set together")
	}
	if c.BTCSelfTestIndex != nil && !c.BTCEnabled() {
		return errors.New("BTC_SELFTEST_* set but BTC_ACCOUNT_XPUB is empty")
	}
	return nil
}

func getenvDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func parseUint31Env(key string, dst *uint32) error {
	v := os.Getenv(key)
	if v == "" {
		return nil
	}
	n, err := strconv.ParseUint(v, 10, 31)
	if err != nil {
		return fmt.Errorf("%s: %w", key, err)
	}
	*dst = uint32(n)
	return nil
}

func parseOptIndexEnv(key string) (*uint32, error) {
	v := os.Getenv(key)
	if v == "" {
		return nil, nil
	}
	n, err := strconv.ParseUint(v, 10, 31)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", key, err)
	}
	idx := uint32(n)
	return &idx, nil
}
