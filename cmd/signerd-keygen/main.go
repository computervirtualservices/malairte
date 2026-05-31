// Command signerd-keygen generates (OFFLINE) the BIP39 mnemonic + BIP44 account
// xpub that the CoinDock signer needs as MLRT_ACCOUNT_XPUB.
//
// RUN THIS ON AN OFFLINE MACHINE. It prints a secret recovery mnemonic. Write
// the mnemonic on paper, store it securely, and never paste it anywhere online.
// Only the xpub (public) and the self-test values are copied into the signer
// config; the mnemonic/seed never leave your control.
//
// Usage:
//
//	signerd-keygen                       # generate a new 24-word wallet
//	signerd-keygen --words 12            # 12-word instead of 24
//	signerd-keygen --import "word1 ..."  # re-derive xpub from an existing mnemonic
//	signerd-keygen --account 0 --coin-type 0 --self-test-index 1
//
// The derivation path is m/44'/<coin-type>'/<account>'. Deposit addresses are
// then <change>/<index> beneath the account xpub, matching signerd's defaults.
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
		words       = flag.Int("words", 24, "mnemonic length for a NEW wallet: 12 or 24")
		importMn    = flag.String("import", "", "re-derive from an existing BIP39 mnemonic instead of generating one")
		passphrase  = flag.String("passphrase", "", "optional BIP39 passphrase (25th word) — must be remembered exactly")
		coinType    = flag.Uint("coin-type", 0, "BIP44 coin type (MLRT wallet uses 0)")
		account     = flag.Uint("account", 0, "BIP44 account index")
		change      = flag.Uint("change", 0, "change level used for deposit addresses (signerd default 0)")
		selfTestIdx = flag.Uint("self-test-index", 1, "address index to print for the signer boot self-test")
		addrVersion = flag.Uint("address-version", 50, "Base58 version byte: 50 mainnet 'M', 111 testnet 'm'")
	)
	flag.Parse()

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

	// Account path m/44'/<coin-type>'/<account>'.
	accountKey, err := master.Derive(hdwallet.H(44), hdwallet.H(uint32(*coinType)), hdwallet.H(uint32(*account)))
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: derive account:", err)
		os.Exit(1)
	}

	xpub, err := accountKey.Neuter().String()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: serialize xpub:", err)
		os.Exit(1)
	}

	// Cross-check: derive the self-test address two independent ways and require
	// they agree. (1) private chain: account/change/index → pubkey → address.
	// (2) public chain: parse the xpub and CKDpub the same path — the exact code
	// path signerd uses. This proves the xpub is correct AND that signerd (which
	// only has the xpub) derives the identical address.
	privChild, err := accountKey.Derive(uint32(*change), uint32(*selfTestIdx))
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: private derive self-test:", err)
		os.Exit(1)
	}
	addrPriv, err := crypto.PubKeyToAddress(privChild.Neuter().Key, byte(*addrVersion))
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
	addrPub, err := crypto.PubKeyToAddress(pubChild.PubKey, byte(*addrVersion))
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: encode address (pub):", err)
		os.Exit(1)
	}

	if addrPriv != addrPub {
		fmt.Fprintf(os.Stderr, "FATAL: derivation mismatch (priv=%s pub=%s) — do not use this output\n", addrPriv, addrPub)
		os.Exit(2)
	}

	printResult(mnemonic, generated, xpub, *coinType, *account, *change, *selfTestIdx, addrPub, byte(*addrVersion))
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

func printResult(mnemonic string, generated bool, xpub string, coinType, account, change, idx uint, addr string, version byte) {
	bar := strings.Repeat("=", 72)
	net := "mainnet"
	if version != 50 {
		net = "testnet"
	}

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
	} else {
		fmt.Println("  RE-DERIVED FROM IMPORTED MNEMONIC (mnemonic not reprinted)")
	}
	fmt.Println(bar)
	fmt.Printf("  Network        : %s (address version %d)\n", net, version)
	fmt.Printf("  Account path   : m/44'/%d'/%d'\n", coinType, account)
	fmt.Printf("  Deposit path   : <%d>/<user_id> beneath the account xpub\n", change)
	fmt.Println(bar)
	fmt.Println("  PUT THIS IN /etc/signerd/env :")
	fmt.Println()
	fmt.Printf("  MLRT_ACCOUNT_XPUB=%s\n", xpub)
	fmt.Printf("  MLRT_ADDRESS_VERSION=%d\n", version)
	fmt.Printf("  MLRT_SELFTEST_INDEX=%d\n", idx)
	fmt.Printf("  MLRT_SELFTEST_ADDRESS=%s\n", addr)
	fmt.Println()
	fmt.Println(bar)
	fmt.Printf("  Self-test check: index %d derives %s\n", idx, addr)
	fmt.Println("  signerd verifies this at boot and refuses to start on mismatch.")
	fmt.Println(bar)
}
