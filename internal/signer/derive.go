package signer

import (
	"errors"
	"fmt"
	"strings"

	"github.com/computervirtualservices/malairte/internal/crypto"
)

// ErrUnknownChain is returned for a chain the contract does not define.
var ErrUnknownChain = errors.New("unknown chain")

// ErrUnsupportedChain is returned for a contract chain not enabled in this
// deployment (e.g. ETH when ETH_ACCOUNT_XPUB is unset, or TRON which needs Tron
// address encoding not yet implemented).
var ErrUnsupportedChain = errors.New("chain not supported in this build")

// DeriveAddress derives a watch-only deposit address for the given chain and
// BIP44 address index, following <change>/<index> beneath the account xpub
// (per coindock api/03-signer-service-api.md, CoinDock passes the user id as
// the address index).
func (s *Service) DeriveAddress(chain string, index uint32) (string, error) {
	switch strings.ToUpper(chain) {
	case "MLRT":
		return s.deriveMLRT(index)
	case "ETH":
		return s.deriveETH(index)
	case "BTC":
		return s.deriveBTC(index)
	case "TRON":
		return "", fmt.Errorf("%w: TRON", ErrUnsupportedChain)
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

func (s *Service) deriveETH(index uint32) (string, error) {
	if s.ethXpub == nil {
		return "", fmt.Errorf("%w: ETH (ETH_ACCOUNT_XPUB not configured)", ErrUnsupportedChain)
	}
	child, err := s.ethXpub.DerivePath(s.cfg.ETHChange, index)
	if err != nil {
		return "", fmt.Errorf("derive ETH %d/%d: %w", s.cfg.ETHChange, index, err)
	}
	addr, err := ethAddressFromCompressedPubKey(child.PubKey)
	if err != nil {
		return "", fmt.Errorf("encode ETH address: %w", err)
	}
	return addr, nil
}

func (s *Service) deriveBTC(index uint32) (string, error) {
	if s.btcXpub == nil {
		return "", fmt.Errorf("%w: BTC (BTC_ACCOUNT_XPUB not configured)", ErrUnsupportedChain)
	}
	child, err := s.btcXpub.DerivePath(s.cfg.BTCChange, index)
	if err != nil {
		return "", fmt.Errorf("derive BTC %d/%d: %w", s.cfg.BTCChange, index, err)
	}
	addr, err := btcP2WPKHFromCompressedPubKey(child.PubKey, s.cfg.BTCHRP)
	if err != nil {
		return "", fmt.Errorf("encode BTC address: %w", err)
	}
	return addr, nil
}
