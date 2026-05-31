package signer

import "fmt"

// Service is the configured signer/deriver. It derives watch-only deposit
// addresses from per-chain account xpubs; transaction signing is not
// implemented in this build.
type Service struct {
	cfg      *Config
	mlrtXpub *ExtendedPubKey
	ethXpub  *ExtendedPubKey // nil unless ETH_ACCOUNT_XPUB is configured
}

// New parses the configured account xpub(s) and, for each chain with a
// self-test configured, verifies that derivation reproduces a known address
// before returning — so a mismatched xpub or derivation path is caught at boot
// rather than handing out wrong (and therefore unspendable) deposit addresses.
func New(cfg *Config) (*Service, error) {
	mlrtXpub, err := ParseExtendedPubKey(cfg.MLRTAccountXpub)
	if err != nil {
		return nil, fmt.Errorf("parse MLRT_ACCOUNT_XPUB: %w", err)
	}

	s := &Service{cfg: cfg, mlrtXpub: mlrtXpub}

	if cfg.ETHEnabled() {
		ethXpub, err := ParseExtendedPubKey(cfg.ETHAccountXpub)
		if err != nil {
			return nil, fmt.Errorf("parse ETH_ACCOUNT_XPUB: %w", err)
		}
		s.ethXpub = ethXpub
	}

	if cfg.SelfTestIndex != nil {
		if err := s.runSelfTest("MLRT", *cfg.SelfTestIndex, cfg.SelfTestAddress); err != nil {
			return nil, err
		}
	}
	if cfg.ETHSelfTestIndex != nil {
		if err := s.runSelfTest("ETH", *cfg.ETHSelfTestIndex, cfg.ETHSelfTestAddr); err != nil {
			return nil, err
		}
	}

	return s, nil
}

func (s *Service) runSelfTest(chain string, index uint32, want string) error {
	got, err := s.DeriveAddress(chain, index)
	if err != nil {
		return fmt.Errorf("boot self-test (%s) derive: %w", chain, err)
	}
	if got != want {
		return fmt.Errorf(
			"boot self-test FAILED (%s): index %d derived %q but expected %q — refusing to start with a mismatched xpub/path",
			chain, index, got, want,
		)
	}
	return nil
}
