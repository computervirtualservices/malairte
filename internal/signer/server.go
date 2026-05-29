package signer

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// maxBodyBytes caps request bodies; derive/sign payloads are tiny.
const maxBodyBytes = 4 << 10 // 4 KiB

// Handler returns the HTTP routes implementing api/03-signer-service-api.md.
//
//	POST /v1/derive  (bearer auth)  -> {address}
//	POST /v1/sign    (bearer auth)  -> 501 (not implemented in this build)
//	GET  /v1/health                 -> 200 (readiness; unauthenticated)
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", s.handleHealth)
	mux.HandleFunc("/v1/derive", s.requireAuth(s.handleDerive))
	mux.HandleFunc("/v1/sign", s.requireAuth(s.handleSign))
	return mux
}

type deriveRequest struct {
	Chain string `json:"chain"`
	Index *int64 `json:"index"`
}

type deriveResponse struct {
	Address string `json:"address"`
}

type errorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

func (s *Service) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Service) handleDerive(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}

	var req deriveRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	if strings.TrimSpace(req.Chain) == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "chain is required")
		return
	}
	if req.Index == nil {
		writeError(w, http.StatusBadRequest, "bad_request", "index is required")
		return
	}
	if *req.Index < 0 || *req.Index >= int64(hardenedOffset) {
		writeError(w, http.StatusBadRequest, "bad_request", "index must be a non-negative integer below 2^31")
		return
	}

	addr, err := s.DeriveAddress(req.Chain, uint32(*req.Index))
	if err != nil {
		switch {
		case errors.Is(err, ErrUnknownChain):
			writeError(w, http.StatusBadRequest, "unknown_chain", err.Error())
		case errors.Is(err, ErrUnsupportedChain):
			writeError(w, http.StatusNotImplemented, "unsupported_chain", err.Error())
		case errors.Is(err, ErrInvalidChild):
			// Astronomically unlikely; tell the caller to try the next index.
			writeError(w, http.StatusConflict, "invalid_index", err.Error())
		default:
			writeError(w, http.StatusInternalServerError, "derive_failed", err.Error())
		}
		return
	}

	writeJSON(w, http.StatusOK, deriveResponse{Address: addr})
}

func (s *Service) handleSign(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotImplemented, "not_implemented",
		"signing is disabled in this build (Phase 1 derive-only); /v1/sign is gated behind COINDOCK_MALAIRTE_SIGNING_ENABLED and launch sign-off")
}

// requireAuth enforces a constant-time bearer-token check.
func (s *Service) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	want := []byte("Bearer " + s.cfg.Token)
	return func(w http.ResponseWriter, r *http.Request) {
		got := []byte(r.Header.Get("Authorization"))
		if subtle.ConstantTimeEq(int32(len(got)), int32(len(want))) != 1 ||
			subtle.ConstantTimeCompare(got, want) != 1 {
			writeError(w, http.StatusUnauthorized, "unauthorized", "missing or invalid bearer token")
			return
		}
		next(w, r)
	}
}

// decodeJSON reads and strictly decodes the request body, writing a 400 on
// failure. Returns false if the caller should stop.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body: "+err.Error())
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, errorResponse{Error: code, Message: msg})
}
