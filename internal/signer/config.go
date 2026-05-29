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
// Env vars:
//
//	SIGNER_BIND_ADDR      listen address (default 127.0.0.1:8088 — private only)
//	SIGNER_TOKEN          bearer token; MUST equal CoinDock's COINDOCK_SIGNER_TOKEN
//	MLRT_ACCOUNT_XPUB     BIP32 account xpub (PUBLIC) for m/44'/<mlrt>'/0'
//	MLRT_BIP44_CHANGE     change level derived before the index (default 0)
//	MLRT_ADDRESS_VERSION  Base58 version byte: 50 mainnet 'M', 111 testnet 'm'
//	MLRT_SELFTEST_INDEX   optional: index whose derived address must equal …
//	MLRT_SELFTEST_ADDRESS optional: … this known address, or the service refuses
//	                      to start (guards against a wrong xpub/path).
type Config struct {
	BindAddr           string
	Token              string
	MLRTAccountXpub    string
	MLRTChange         uint32
	MLRTAddressVersion byte

	SelfTestIndex   *uint32
	SelfTestAddress string
}

// LoadConfig reads and validates configuration from the environment.
func LoadConfig() (*Config, error) {
	cfg := &Config{
		BindAddr:           getenvDefault("SIGNER_BIND_ADDR", "127.0.0.1:8088"),
		Token:              os.Getenv("SIGNER_TOKEN"),
		MLRTAccountXpub:    os.Getenv("MLRT_ACCOUNT_XPUB"),
		MLRTChange:         0,
		MLRTAddressVersion: 50, // 'M' mainnet
	}

	if v := os.Getenv("MLRT_BIP44_CHANGE"); v != "" {
		n, err := strconv.ParseUint(v, 10, 31)
		if err != nil {
			return nil, fmt.Errorf("MLRT_BIP44_CHANGE: %w", err)
		}
		cfg.MLRTChange = uint32(n)
	}

	if v := os.Getenv("MLRT_ADDRESS_VERSION"); v != "" {
		n, err := strconv.ParseUint(v, 10, 8)
		if err != nil {
			return nil, fmt.Errorf("MLRT_ADDRESS_VERSION: %w", err)
		}
		cfg.MLRTAddressVersion = byte(n)
	}

	if v := os.Getenv("MLRT_SELFTEST_INDEX"); v != "" {
		n, err := strconv.ParseUint(v, 10, 31)
		if err != nil {
			return nil, fmt.Errorf("MLRT_SELFTEST_INDEX: %w", err)
		}
		idx := uint32(n)
		cfg.SelfTestIndex = &idx
	}
	cfg.SelfTestAddress = os.Getenv("MLRT_SELFTEST_ADDRESS")

	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
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
	return nil
}

func getenvDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
