// Command signerd-keygen generates (OFFLINE) the BIP39 mnemonic + BIP44 account
// xpub that the CoinDock signer needs (MLRT_ACCOUNT_XPUB or ETH_ACCOUNT_XPUB).
//
// RUN THIS ON AN OFFLINE MACHINE. For a new wallet it prints a secret recovery
// mnemonic — write it on paper, store it securely, never paste it anywhere
// online. Only the xpub (public) and the self-test values are copied into the
// signer config; the mnemonic/seed never leave your control.
//
// IMPORTANT: derive every chain from the SAME mnemonic. Generate MLRT first
// (default), then re-run with --import "<that mnemonic>" --chain eth to get the
// ETH account xpub for the same wallet:
//
//	signerd-keygen                                   # new wallet, MLRT xpub
//	signerd-keygen --import "word1 ... word24" --chain eth   # ETH xpub, same seed
//
// Paths: MLRT = m/44'/<coin-type>'/<account>' (coin-type 0), ETH = m/44'/60'/0'.
// Deposit addresses are <change>/<index> beneath the account xpub.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/computervirtualservices/malairte/internal/crypto"
	"github.com/computervirtualservices/malairte/internal/hdwallet"
	"github.com/computervirtualservices/malairte/internal/signer"
)

func main() {
	var (
		chain       = flag.String("chain", "mlrt", "chain to derive: mlrt, eth, or btc")
		words       = flag.Int("words", 24, "mnemonic length for a NEW wallet: 12 or 24")
		importMn    = flag.String("import", "", "re-derive from an existing BIP39 mnemonic instead of generating one")
		passphrase  = flag.String("passphrase", "", "optional BIP39 passphrase (25th word) — must be remembered exactly")
		coinType    = flag.Int("coin-type", -1, "BIP44 coin type (default: 0 for mlrt, 60 for eth)")
		account     = flag.Uint("account", 0, "BIP44 account index")
		change      = flag.Uint("change", 0, "change level used for deposit addresses (signerd default 0)")
		selfTestIdx = flag.Uint("self-test-index", 1, "address index to print for the signer boot self-test")
		addrVersion = flag.Uint("address-version", 50, "MLRT Base58 version byte: 50 mainnet 'M', 111 testnet 'm' (ignored for eth)")
	)
	flag.Parse()

	ch := strings.ToLower(*chain)
	if ch != "mlrt" && ch != "eth" && ch != "btc" {
		fmt.Fprintln(os.Stderr, "error: --chain must be mlrt, eth, or btc")
		os.Exit(1)
	}

	// Default coin type per chain unless explicitly overridden.
	ct := *coinType
	if ct < 0 {
		ct = map[string]int{"mlrt": 0, "eth": 60, "btc": 0}[ch]
	}

	// BIP purpose: 84 for BTC native SegWit (BIP84), 44 otherwise (BIP44).
	purpose := uint32(44)
	if ch == "btc" {
		purpose = 84
	}

	mnemonic, generated, err := getMnemonic(*importMn, *words)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	seed := hdwallet.MnemonicToSeed(mnemonic, *passphrase)
	master, err := hdwallet.NewMasterKey(seed)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: derive master:", err)
		os.Exit(1)
	}

	accountKey, err := master.Derive(hdwallet.H(purpose), hdwallet.H(uint32(ct)), hdwallet.H(uint32(*account)))
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: derive account:", err)
		os.Exit(1)
	}

	xpub, err := accountKey.Neuter().String()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: serialize xpub:", err)
		os.Exit(1)
	}

	// Encode the self-test address with the chain's encoder, the same way the
	// running signer will. Cross-check via the private chain AND the public xpub
	// chain (signerd only has the xpub) and abort if they disagree.
	encode := func(pub []byte) (string, error) {
		switch ch {
		case "eth":
			return signer.ETHAddressFromCompressedPubKey(pub)
		case "btc":
			hrp := "bc"
			if *addrVersion == 111 { // reuse the testnet hint flag
				hrp = "tb"
			}
			return signer.BTCAddressFromCompressedPubKey(pub, hrp)
		default:
			return crypto.PubKeyToAddress(pub, byte(*addrVersion))
		}
	}

	privChild, err := accountKey.Derive(uint32(*change), uint32(*selfTestIdx))
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: private derive self-test:", err)
		os.Exit(1)
	}
	addrPriv, err := encode(privChild.Neuter().Key)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: encode address:", err)
		os.Exit(1)
	}

	pubAcct, err := signer.ParseExtendedPubKey(xpub)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: parse xpub:", err)
		os.Exit(1)
	}
	pubChild, err := pubAcct.DerivePath(uint32(*change), uint32(*selfTestIdx))
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: public derive self-test:", err)
		os.Exit(1)
	}
	addrPub, err := encode(pubChild.PubKey)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: encode address (pub):", err)
		os.Exit(1)
	}

	if addrPriv != addrPub {
		fmt.Fprintf(os.Stderr, "FATAL: derivation mismatch (priv=%s pub=%s) — do not use this output\n", addrPriv, addrPub)
		os.Exit(2)
	}

	printResult(ch, purpose, mnemonic, generated, xpub, ct, *account, *change, *selfTestIdx, addrPub, byte(*addrVersion))
}

func getMnemonic(importMn string, words int) (mnemonic string, generated bool, err error) {
	if strings.TrimSpace(importMn) != "" {
		m := strings.Join(strings.Fields(importMn), " ")
		if !hdwallet.ValidateMnemonic(m) {
			return "", false, fmt.Errorf("imported mnemonic failed BIP39 checksum/word validation")
		}
		return m, false, nil
	}
	bits := map[int]int{12: 128, 24: 256}[words]
	if bits == 0 {
		return "", false, fmt.Errorf("--words must be 12 or 24")
	}
	m, err := hdwallet.NewMnemonic(bits)
	if err != nil {
		return "", false, err
	}
	return m, true, nil
}

func printResult(chain string, purpose uint32, mnemonic string, generated bool, xpub string, coinType int, account, change, idx uint, addr string, version byte) {
	bar := strings.Repeat("=", 72)
	prefix := map[string]string{"mlrt": "MLRT", "eth": "ETH", "btc": "BTC"}[chain]

	fmt.Println(bar)
	if generated {
		fmt.Println("  NEW WALLET GENERATED — SECRET RECOVERY MNEMONIC")
		fmt.Println(bar)
		fmt.Println("  Write these words on paper and store them securely OFFLINE.")
		fmt.Println("  Anyone with these words controls all derived funds. They are")
		fmt.Println("  shown ONCE and are NOT saved anywhere.")
		fmt.Println()
		fmt.Println("   ", mnemonic)
		fmt.Println()
		fmt.Println("  Derive the OTHER chains from THIS SAME mnemonic, e.g.:")
		for _, oc := range otherChains(chain) {
			fmt.Printf("    signerd-keygen --import \"<the words>\" --chain %s\n", oc)
		}
	} else {
		fmt.Println("  RE-DERIVED FROM IMPORTED MNEMONIC (mnemonic not reprinted)")
	}
	fmt.Println(bar)
	switch chain {
	case "eth":
		fmt.Println("  Chain          : Ethereum (EIP-55 address)")
	case "btc":
		fmt.Println("  Chain          : Bitcoin (native SegWit P2WPKH, bc1…)")
	default:
		net := "mainnet"
		if version != 50 {
			net = "testnet"
		}
		fmt.Printf("  Chain          : MLRT %s (Base58 version %d)\n", net, version)
	}
	fmt.Printf("  Account path   : m/%d'/%d'/%d'\n", purpose, coinType, account)
	fmt.Printf("  Deposit path   : <%d>/<user_id> beneath the account xpub\n", change)
	fmt.Println(bar)
	fmt.Println("  PUT THIS IN /etc/signerd/env :")
	fmt.Println()
	fmt.Printf("  %s_ACCOUNT_XPUB=%s\n", prefix, xpub)
	if chain == "mlrt" {
		fmt.Printf("  MLRT_ADDRESS_VERSION=%d\n", version)
	}
	fmt.Printf("  %s_SELFTEST_INDEX=%d\n", prefix, idx)
	fmt.Printf("  %s_SELFTEST_ADDRESS=%s\n", prefix, addr)
	fmt.Println()
	fmt.Println(bar)
	fmt.Printf("  Self-test check: index %d derives %s\n", idx, addr)
	fmt.Println("  signerd verifies this at boot and refuses to start on mismatch.")
	fmt.Println(bar)
}

func otherChains(c string) []string {
	var out []string
	for _, x := range []string{"mlrt", "eth", "btc"} {
		if x != c {
			out = append(out, x)
		}
	}
	return out
}
