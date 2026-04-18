// Package rpc provides a Bitcoin-compatible JSON-RPC 1.0 HTTP server.
package rpc

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"

	"github.com/computervirtualservices/malairte/internal/chain"
	"github.com/computervirtualservices/malairte/internal/mempool"
	"github.com/computervirtualservices/malairte/internal/mining"
	"github.com/computervirtualservices/malairte/internal/network"
)

// rpcRequest represents an incoming JSON-RPC 1.0 request.
type rpcRequest struct {
	ID     interface{}   `json:"id"`
	Method string        `json:"method"`
	Params []interface{} `json:"params"`
}

// rpcResponse represents an outgoing JSON-RPC 1.0 response.
type rpcResponse struct {
	ID     interface{} `json:"id"`
	Result interface{} `json:"result"`
	Error  *rpcError   `json:"error"`
}

// rpcError represents a JSON-RPC error object.
type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Standard JSON-RPC error codes.
const (
	errCodeParse          = -32700
	errCodeInvalidRequest = -32600
	errCodeMethodNotFound = -32601
	errCodeInvalidParams  = -32602
	errCodeInternal       = -32603
)

// Server is a Bitcoin-compatible JSON-RPC 1.0 HTTP server.
type Server struct {
	bc      *chain.Blockchain
	pool    *mempool.TxPool
	miner   *mining.CpuMiner
	peerSrv *network.PeerServer
	params  *chain.ChainParams
	httpSrv *http.Server
	stopCh  chan struct{}
}

// NewServer creates the RPC server with all required dependencies.
func NewServer(bc *chain.Blockchain, pool *mempool.TxPool, miner *mining.CpuMiner, peerSrv *network.PeerServer, params *chain.ChainParams) *Server {
	return &Server{
		bc:      bc,
		pool:    pool,
		miner:   miner,
		peerSrv: peerSrv,
		params:  params,
		stopCh:  make(chan struct{}, 1),
	}
}

// SetMiner sets the CPU miner (allows setting it after the server is created).
func (s *Server) SetMiner(miner *mining.CpuMiner) {
	s.miner = miner
}

// Start starts the HTTP server on the given address (e.g. "127.0.0.1:9332").
// Only binds to localhost for security.
func (s *Server) Start(addr string) error {
	// Validate that addr is localhost-only
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid RPC address %q: %w", addr, err)
	}
	if host != "127.0.0.1" && host != "::1" && host != "localhost" {
		log.Printf("[rpc] WARNING: binding RPC to non-localhost address %s", host)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRequest)

	s.httpSrv = &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	log.Printf("[rpc] JSON-RPC server listening on %s", addr)
	go func() {
		if err := s.httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[rpc] server error: %v", err)
		}
	}()
	return nil
}

// ServeHTTP implements http.Handler, allowing the server to be embedded in
// a custom mux or used directly with net/http/httptest in tests.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handleRequest(w, r)
}

// Stop gracefully shuts down the RPC HTTP server.
func (s *Server) Stop() {
	if s.httpSrv != nil {
		s.httpSrv.Close()
	}
}

// handleRequest reads and dispatches a single JSON-RPC request.
func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 4*1024*1024))
	if err != nil {
		writeError(w, nil, errCodeParse, "failed to read request body")
		return
	}
	defer r.Body.Close()

	var req rpcRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, nil, errCodeParse, "failed to parse JSON")
		return
	}

	result, rpcErr := s.dispatch(req.Method, req.Params)

	resp := rpcResponse{ID: req.ID}
	if rpcErr != nil {
		resp.Error = rpcErr
	} else {
		resp.Result = result
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

// dispatch routes a method name to its handler function.
func (s *Server) dispatch(method string, params []interface{}) (interface{}, *rpcError) {
	switch method {
	case "getblockchaininfo":
		return s.getBlockchainInfo(params)
	case "getblockhash":
		return s.getBlockHash(params)
	case "getblockheader":
		return s.getBlockHeader(params)
	case "getblock":
		return s.getBlock(params)
	case "getrawtransaction":
		return s.getRawTransaction(params)
	case "sendrawtransaction":
		return s.sendRawTransaction(params)
	case "getmempoolinfo":
		return s.getMempoolInfo(params)
	case "getrawmempool":
		return s.getRawMempool(params)
	case "getblocktemplate":
		return s.getBlockTemplate(params)
	case "submitblock":
		return s.submitBlock(params)
	case "getpeerinfo":
		return s.getPeerInfo(params)
	case "getnetworkinfo":
		return s.getNetworkInfo(params)
	case "getmininginfo":
		return s.getMiningInfo(params)
	case "getnetworkhashps":
		return s.getNetworkHashps(params)
	case "validateaddress":
		return s.validateAddress(params)
	case "getaddresstransactions":
		return s.getAddressTransactions(params)
	case "getaddressbalance":
		return s.getAddressBalance(params)
	case "getaddressutxos":
		return s.getAddressUTXOs(params)
	case "stop":
		return s.stop(params)
	default:
		return nil, &rpcError{Code: errCodeMethodNotFound, Message: fmt.Sprintf("method not found: %s", method)}
	}
}

// writeError writes a JSON-RPC error response.
func writeError(w http.ResponseWriter, id interface{}, code int, message string) {
	resp := rpcResponse{
		ID:    id,
		Error: &rpcError{Code: code, Message: message},
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

// newRPCError creates a *rpcError with the given code and message.
func newRPCError(code int, message string) *rpcError {
	return &rpcError{Code: code, Message: message}
}
