// Command malairtcli is a command-line interface for interacting with a running malairted node.
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
	"strconv"

	"github.com/malairt/malairt/internal/crypto"
)

const defaultRPCURL = "http://127.0.0.1:9332"

func main() {
	rpcURL := flag.String("rpc", defaultRPCURL, "RPC server URL")
	flag.Usage = usage
	flag.Parse()

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
			fmt.Fprintln(os.Stderr, "usage: malairtcli getblockhash <height>")
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
			fmt.Fprintln(os.Stderr, "usage: malairtcli getblock <hash>")
			os.Exit(1)
		}
		err = cmdRPC(*rpcURL, "getblock", []interface{}{cmdArgs[0], 2})
	case "getrawtransaction":
		if len(cmdArgs) < 1 {
			fmt.Fprintln(os.Stderr, "usage: malairtcli getrawtransaction <txid> [verbose]")
			os.Exit(1)
		}
		verbose := false
		if len(cmdArgs) >= 2 && cmdArgs[1] != "0" {
			verbose = true
		}
		err = cmdRPC(*rpcURL, "getrawtransaction", []interface{}{cmdArgs[0], verbose})
	case "sendrawtx":
		if len(cmdArgs) < 1 {
			fmt.Fprintln(os.Stderr, "usage: malairtcli sendrawtx <hex>")
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
			fmt.Fprintln(os.Stderr, "usage: malairtcli getaddresstransactions <address> [limit]")
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
			fmt.Fprintln(os.Stderr, "usage: malairtcli getaddressbalance <address>")
			os.Exit(1)
		}
		err = cmdRPC(*rpcURL, "getaddressbalance", []interface{}{cmdArgs[0]})
	case "getaddressutxos":
		if len(cmdArgs) < 1 {
			fmt.Fprintln(os.Stderr, "usage: malairtcli getaddressutxos <address>")
			os.Exit(1)
		}
		err = cmdRPC(*rpcURL, "getaddressutxos", []interface{}{cmdArgs[0]})
	case "validateaddress":
		if len(cmdArgs) < 1 {
			fmt.Fprintln(os.Stderr, "usage: malairtcli validateaddress <address>")
			os.Exit(1)
		}
		err = cmdRPC(*rpcURL, "validateaddress", []interface{}{cmdArgs[0]})
	case "getblocktemplate":
		err = cmdRPC(*rpcURL, "getblocktemplate", []interface{}{map[string]interface{}{}})
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
	fmt.Fprintf(os.Stderr, `malairtcli — Malairt node CLI

Usage:
  malairtcli [--rpc <url>] <command> [args]

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

	resp, err := http.Post(rpcURL, "application/json", bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("HTTP POST to %s: %w", rpcURL, err)
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return result, nil
}
