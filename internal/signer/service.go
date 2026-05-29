package signer

import "fmt"

// Service is the configured signer/deriver. In this build it derives watch-only
// MLRT deposit addresses from the account xpub; signing is not implemented.
type Service struct {
	cfg      *Config
	mlrtXpub *ExtendedPubKey
}

// New parses the configured account xpub and, if a self-test is configured,
// verifies that derivation reproduces a known address before returning — so a
// mismatched xpub or derivation path is caught at boot rather than handing out
// wrong (and therefore unspendable) deposit addresses.
func New(cfg *Config) (*Service, error) {
	xpub, err := ParseExtendedPubKey(cfg.MLRTAccountXpub)
	if err != nil {
		return nil, fmt.Errorf("parse MLRT_ACCOUNT_XPUB: %w", err)
	}

	s := &Service{cfg: cfg, mlrtXpub: xpub}

	if cfg.SelfTestIndex != nil {
		got, err := s.DeriveAddress("MLRT", *cfg.SelfTestIndex)
		if err != nil {
			return nil, fmt.Errorf("boot self-test derive: %w", err)
		}
		if got != cfg.SelfTestAddress {
			return nil, fmt.Errorf(
				"boot self-test FAILED: index %d derived %q but expected %q — refusing to start with a mismatched xpub/path",
				*cfg.SelfTestIndex, got, cfg.SelfTestAddress,
			)
		}
	}

	return s, nil
}
