package signer

import (
	"errors"
	"fmt"
	"strings"

	"github.com/computervirtualservices/malairte/internal/crypto"
)

// ErrUnknownChain is returned for a chain the contract does not define.
var ErrUnknownChain = errors.New("unknown chain")

// ErrUnsupportedChain is returned for a contract chain not implemented in this
// build (ETH/TRON derivation needs keccak/Tron encoding, added in a later phase).
var ErrUnsupportedChain = errors.New("chain not supported in this build")

// DeriveAddress derives a watch-only deposit address for the given chain and
// BIP44 address index, following <change>/<index> beneath the account xpub
// (per coindock api/03-signer-service-api.md, CoinDock passes the user id as
// the address index).
func (s *Service) DeriveAddress(chain string, index uint32) (string, error) {
	switch strings.ToUpper(chain) {
	case "MLRT":
		return s.deriveMLRT(index)
	case "ETH", "TRON":
		return "", fmt.Errorf("%w: %s", ErrUnsupportedChain, strings.ToUpper(chain))
	default:
		return "", fmt.Errorf("%w: %q", ErrUnknownChain, chain)
	}
}

func (s *Service) deriveMLRT(index uint32) (string, error) {
	child, err := s.mlrtXpub.DerivePath(s.cfg.MLRTChange, index)
	if err != nil {
		return "", fmt.Errorf("derive MLRT %d/%d: %w", s.cfg.MLRTChange, index, err)
	}
	addr, err := crypto.PubKeyToAddress(child.PubKey, s.cfg.MLRTAddressVersion)
	if err != nil {
		return "", fmt.Errorf("encode MLRT address: %w", err)
	}
	return addr, nil
}
