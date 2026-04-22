// Command malairte-cli is a command-line interface for interacting with a running malairte-node node.
// It communicates via the JSON-RPC interface.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/computervirtualservices/malairte/internal/crypto"
)

const defaultRPCURL = "http://127.0.0.1:9332"

// rpcAuth holds optional HTTP Basic Auth credentials. When both fields are
// non-empty the CLI attaches an Authorization header to every RPC call.
// Populated from --rpc-user / --rpc-pass flags OR the MALAIRTE_RPC_USER /
// MALAIRTE_RPC_PASS env vars, so operators can avoid putting the password
// in shell history.
type rpcAuth struct {
	user string
	pass string
}

var currentAuth rpcAuth

func main() {
	rpcURL := flag.String("rpc", defaultRPCURL, "RPC server URL")
	rpcUser := flag.String("rpc-user", os.Getenv("MALAIRTE_RPC_USER"),
		"RPC Basic Auth user (or set MALAIRTE_RPC_USER)")
	rpcPass := flag.String("rpc-pass", os.Getenv("MALAIRTE_RPC_PASS"),
		"RPC Basic Auth password (or set MALAIRTE_RPC_PASS)")
	flag.Usage = usage
	flag.Parse()

	currentAuth = rpcAuth{user: *rpcUser, pass: *rpcPass}

	args := flag.Args()
	if len(args) == 0 {
		usage()
		os.Exit(1)
	}

	cmd := args[0]
	cmdArgs := args[1:]

	var err error
	switch cmd {
	case "genkey":
		err = cmdGenKey()
	case "getinfo":
		err = cmdRPC(*rpcURL, "getblockchaininfo", nil)
	case "getblockcount":
		err = cmdGetBlockCount(*rpcURL)
	case "getblockhash":
		if len(cmdArgs) < 1 {
			fmt.Fprintln(os.Stderr, "usage: malairte-cli getblockhash <height>")
			os.Exit(1)
		}
		height, e := strconv.ParseUint(cmdArgs[0], 10, 64)
		if e != nil {
			fmt.Fprintf(os.Stderr, "invalid height: %v\n", e)
			os.Exit(1)
		}
		err = cmdRPC(*rpcURL, "getblockhash", []interface{}{height})
	case "getblock":
		if len(cmdArgs) < 1 {
			fmt.Fprintln(os.Stderr, "usage: malairte-cli getblock <hash>")
			os.Exit(1)
		}
		err = cmdRPC(*rpcURL, "getblock", []interface{}{cmdArgs[0], 2})
	case "getrawtransaction":
		if len(cmdArgs) < 1 {
			fmt.Fprintln(os.Stderr, "usage: malairte-cli getrawtransaction <txid> [verbose]")
			os.Exit(1)
		}
		verbose := false
		if len(cmdArgs) >= 2 && cmdArgs[1] != "0" {
			verbose = true
		}
		err = cmdRPC(*rpcURL, "getrawtransaction", []interface{}{cmdArgs[0], verbose})
	case "sendrawtx":
		if len(cmdArgs) < 1 {
			fmt.Fprintln(os.Stderr, "usage: malairte-cli sendrawtx <hex>")
			os.Exit(1)
		}
		err = cmdRPC(*rpcURL, "sendrawtransaction", []interface{}{cmdArgs[0]})
	case "getmempoolinfo":
		err = cmdRPC(*rpcURL, "getmempoolinfo", nil)
	case "getpeerinfo":
		err = cmdRPC(*rpcURL, "getpeerinfo", nil)
	case "getmininginfo":
		err = cmdRPC(*rpcURL, "getmininginfo", nil)
	case "stop":
		err = cmdRPC(*rpcURL, "stop", nil)
	case "getaddresstransactions":
		if len(cmdArgs) < 1 {
			fmt.Fprintln(os.Stderr, "usage: malairte-cli getaddresstransactions <address> [limit]")
			os.Exit(1)
		}
		txParams := []interface{}{cmdArgs[0]}
		if len(cmdArgs) >= 2 {
			if n, e := strconv.ParseInt(cmdArgs[1], 10, 64); e == nil {
				txParams = append(txParams, n)
			}
		}
		err = cmdRPC(*rpcURL, "getaddresstransactions", txParams)
	case "getaddressbalance":
		if len(cmdArgs) < 1 {
			fmt.Fprintln(os.Stderr, "usage: malairte-cli getaddressbalance <address>")
			os.Exit(1)
		}
		err = cmdRPC(*rpcURL, "getaddressbalance", []interface{}{cmdArgs[0]})
	case "getaddressutxos":
		if len(cmdArgs) < 1 {
			fmt.Fprintln(os.Stderr, "usage: malairte-cli getaddressutxos <address>")
			os.Exit(1)
		}
		err = cmdRPC(*rpcURL, "getaddressutxos", []interface{}{cmdArgs[0]})
	case "validateaddress":
		if len(cmdArgs) < 1 {
			fmt.Fprintln(os.Stderr, "usage: malairte-cli validateaddress <address>")
			os.Exit(1)
		}
		err = cmdRPC(*rpcURL, "validateaddress", []interface{}{cmdArgs[0]})
	case "getblocktemplate":
		err = cmdRPC(*rpcURL, "getblocktemplate", []interface{}{map[string]interface{}{}})
	case "status":
		err = cmdStatus(*rpcURL)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		usage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// usage prints the command usage information.
func usage() {
	fmt.Fprintf(os.Stderr, `malairte-cli — Malairt node CLI

Usage:
  malairte-cli [--rpc <url>] <command> [args]

Commands:
  genkey                          Generate a new secp256k1 keypair and print addresses
  getinfo                         Get blockchain summary info
  getblockcount                   Get current block height
  getblockhash <height>           Get block hash at height
  getblock <hash>                 Get block details by hash
  getrawtransaction <txid> [1]    Get transaction by txid (pass 1 for verbose JSON)
  sendrawtx <hex>                 Submit a raw transaction hex
  getaddresstransactions <addr> [n]  Get confirmed transactions for an address (default 50)
  getaddressbalance <addr>           Get confirmed spendable balance for an address
  getaddressutxos <addr>             List individual unspent outputs for an address
  getmempoolinfo                  Get mempool statistics
  getpeerinfo                     Get connected peer info
  getmininginfo                   Get mining statistics
  getblocktemplate                Get a block template for mining
  validateaddress <addr>          Validate an address
  status                          Live sync/mining dashboard — prints one line
                                  every ~2 seconds until Ctrl-C. Shows
                                  progress while the node is downloading the
                                  chain, then switches to hashrate + tip
                                  once mining starts.
  stop                            Stop the node

Options:
  --rpc <url>    RPC server URL (default: http://127.0.0.1:9332)

`)
}

// cmdGenKey generates a new secp256k1 keypair and prints the results.
func cmdGenKey() error {
	privKey, pubKey, err := crypto.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("generate key pair: %w", err)
	}

	// Derive addresses for both mainnet and testnet
	mainnetAddr, err := crypto.PubKeyToAddress(pubKey, 50) // version byte 50 → "M"
	if err != nil {
		return fmt.Errorf("derive mainnet address: %w", err)
	}
	testnetAddr, err := crypto.PubKeyToAddress(pubKey, 111) // version byte 111 → "m"
	if err != nil {
		return fmt.Errorf("derive testnet address: %w", err)
	}

	fmt.Println("=== New Malairt Key ===")
	fmt.Printf("Private Key (hex):    %s\n", hex.EncodeToString(privKey))
	fmt.Printf("Public Key  (hex):    %s\n", hex.EncodeToString(pubKey))
	fmt.Printf("Address (mainnet):    %s\n", mainnetAddr)
	fmt.Printf("Address (testnet):    %s\n", testnetAddr)
	fmt.Println()
	fmt.Println("SECURITY WARNING: Keep your private key secret!")
	fmt.Println("Anyone with the private key can spend your funds.")
	return nil
}

// cmdGetBlockCount calls getblockchaininfo and prints the block height.
func cmdGetBlockCount(rpcURL string) error {
	resp, err := callRPC(rpcURL, "getblockchaininfo", nil)
	if err != nil {
		return err
	}
	result, ok := resp["result"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("unexpected result type")
	}
	fmt.Println(result["blocks"])
	return nil
}

// cmdRPC calls a JSON-RPC method and pretty-prints the result.
func cmdRPC(rpcURL, method string, params []interface{}) error {
	resp, err := callRPC(rpcURL, method, params)
	if err != nil {
		return err
	}

	// Check for RPC error
	if errObj, ok := resp["error"]; ok && errObj != nil {
		errMap, ok := errObj.(map[string]interface{})
		if ok {
			return fmt.Errorf("RPC error %v: %v", errMap["code"], errMap["message"])
		}
		return fmt.Errorf("RPC error: %v", errObj)
	}

	// Pretty-print the result
	result := resp["result"]
	if result == nil {
		fmt.Println("null")
		return nil
	}

	out, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal result: %w", err)
	}
	fmt.Println(string(out))
	return nil
}

// rpcResponse is the JSON-RPC response envelope.
type rpcResponse struct {
	ID     interface{} `json:"id"`
	Result interface{} `json:"result"`
	Error  interface{} `json:"error"`
}

// callRPC makes a JSON-RPC 1.0 POST request and returns the response map.
// Attaches HTTP Basic Auth when the global currentAuth is populated. Gives
// an actionable 401 message (rather than a JSON decode error) when the
// server demands auth the user didn't supply.
func callRPC(rpcURL, method string, params []interface{}) (map[string]interface{}, error) {
	if params == nil {
		params = []interface{}{}
	}
	reqBody := map[string]interface{}{
		"id":      1,
		"method":  method,
		"params":  params,
		"jsonrpc": "1.0",
	}
	data, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, rpcURL, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if currentAuth.user != "" && currentAuth.pass != "" {
		req.SetBasicAuth(currentAuth.user, currentAuth.pass)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP POST to %s: %w", rpcURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf(
			"RPC server requires authentication (HTTP 401). " +
				"Pass --rpc-user and --rpc-pass, or set MALAIRTE_RPC_USER / MALAIRTE_RPC_PASS env vars.")
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response (status %d): %w", resp.StatusCode, err)
	}
	return result, nil
}

// cmdStatus prints a single live-updating line that shows the node's sync
// progress during initial block download and, once synced, flips to a
// mining summary. Intended for end users running the node as a background
// service — they can open a terminal, run "malairte-cli status", and see
// what the daemon is doing without trawling the log file. Exits on Ctrl-C.
func cmdStatus(rpcURL string) error {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	t := time.NewTicker(2 * time.Second)
	defer t.Stop()

	// First render immediately so users don't wait 2 seconds for anything
	// to appear.
	printStatusOnce(rpcURL)
	for {
		select {
		case <-sigCh:
			fmt.Println()
			return nil
		case <-t.C:
			printStatusOnce(rpcURL)
		}
	}
}

func printStatusOnce(rpcURL string) {
	mining, mErr := callRPC(rpcURL, "getmininginfo", nil)
	peers, pErr := callRPC(rpcURL, "getpeerinfo", nil)
	if mErr != nil || pErr != nil {
		fmt.Printf("\r[offline] node not responding at %s — is the service running?                \r", rpcURL)
		return
	}

	minfo, _ := mining["result"].(map[string]interface{})
	pinfo, _ := peers["result"].([]interface{})

	height := int64(0)
	if v, ok := minfo["blocks"].(float64); ok {
		height = int64(v)
	}
	hps := int64(0)
	if v, ok := minfo["hashespersec"].(float64); ok {
		hps = int64(v)
	}
	generate := false
	if v, ok := minfo["generate"].(bool); ok {
		generate = v
	}

	bestPeer := int64(0)
	for _, raw := range pinfo {
		p, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		if v, ok := p["startheight"].(float64); ok && int64(v) > bestPeer {
			bestPeer = int64(v)
		}
	}

	// "Syncing" heuristic: we have at least one peer advertising a height
	// above ours, so blocks are still flowing in. Once the local tip catches
	// up the progress bar disappears and the miner summary takes over.
	if bestPeer > height {
		pct := 0
		if bestPeer > 0 {
			pct = int(height * 100 / bestPeer)
		}
		fmt.Printf("\r[syncing] block %s / %s  (%d%%)  %s  peers=%d        \r",
			humanInt(height), humanInt(bestPeer), pct, progressBar(pct, 20), len(pinfo))
		return
	}

	if generate {
		fmt.Printf("\r[mining]  height=%s  hashrate=%s  peers=%d                         \r",
			humanInt(height), humanHashrate(hps), len(pinfo))
		return
	}

	fmt.Printf("\r[relay]   height=%s  peers=%d  (mining disabled)                        \r",
		humanInt(height), len(pinfo))
}

func progressBar(pct, width int) string {
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	fill := pct * width / 100
	bar := make([]byte, 0, width+2)
	bar = append(bar, '[')
	for i := 0; i < width; i++ {
		if i < fill {
			bar = append(bar, '#')
		} else {
			bar = append(bar, '.')
		}
	}
	bar = append(bar, ']')
	return string(bar)
}

func humanInt(n int64) string {
	// thousands separators without bringing in a locale package.
	sign := ""
	if n < 0 {
		sign = "-"
		n = -n
	}
	s := strconv.FormatInt(n, 10)
	if len(s) <= 3 {
		return sign + s
	}
	out := make([]byte, 0, len(s)+len(s)/3)
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	return sign + string(out)
}

func humanHashrate(hps int64) string {
	switch {
	case hps >= 1_000_000_000_000:
		return fmt.Sprintf("%.2f TH/s", float64(hps)/1e12)
	case hps >= 1_000_000_000:
		return fmt.Sprintf("%.2f GH/s", float64(hps)/1e9)
	case hps >= 1_000_000:
		return fmt.Sprintf("%.2f MH/s", float64(hps)/1e6)
	case hps >= 1_000:
		return fmt.Sprintf("%.2f kH/s", float64(hps)/1e3)
	default:
		return fmt.Sprintf("%d H/s", hps)
	}
}
