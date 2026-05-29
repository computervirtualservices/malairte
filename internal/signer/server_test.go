package signer

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/computervirtualservices/malairte/internal/crypto"
)

const testToken = "test-token-0123456789abcdef" // >= 24 chars

// newTestService builds a service from a valid (BIP32 test-vector) xpub used as
// a stand-in account xpub. Address correctness of CKDpub itself is proven in
// bip32_test.go; here we exercise the HTTP contract.
func newTestService(t *testing.T) *Service {
	t.Helper()
	cfg := &Config{
		Token:              testToken,
		MLRTAccountXpub:    xpubM0H,
		MLRTChange:         0,
		MLRTAddressVersion: 50, // 'M'
	}
	svc, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return svc
}

func doRequest(t *testing.T, h http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestDeriveHappyPath(t *testing.T) {
	h := newTestService(t).Handler()

	rec := doRequest(t, h, http.MethodPost, "/v1/derive", testToken, `{"chain":"MLRT","index":42}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var resp deriveResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.HasPrefix(resp.Address, "M") {
		t.Errorf("expected mainnet 'M' address, got %q", resp.Address)
	}
	version, payload, err := crypto.Base58CheckDecode(resp.Address)
	if err != nil {
		t.Fatalf("address failed Base58Check decode: %v", err)
	}
	if version != 50 {
		t.Errorf("address version = %d, want 50", version)
	}
	if len(payload) != 20 {
		t.Errorf("address payload = %d bytes, want 20 (hash160)", len(payload))
	}

	// Deterministic: same index -> same address.
	rec2 := doRequest(t, h, http.MethodPost, "/v1/derive", testToken, `{"chain":"MLRT","index":42}`)
	var resp2 deriveResponse
	_ = json.Unmarshal(rec2.Body.Bytes(), &resp2)
	if resp.Address != resp2.Address {
		t.Errorf("derivation not deterministic: %q != %q", resp.Address, resp2.Address)
	}
}

func TestDeriveRequiresAuth(t *testing.T) {
	h := newTestService(t).Handler()

	if rec := doRequest(t, h, http.MethodPost, "/v1/derive", "", `{"chain":"MLRT","index":1}`); rec.Code != http.StatusUnauthorized {
		t.Errorf("no token: status = %d, want 401", rec.Code)
	}
	if rec := doRequest(t, h, http.MethodPost, "/v1/derive", "wrong-token-xxxxxxxxxxxxxxxx", `{"chain":"MLRT","index":1}`); rec.Code != http.StatusUnauthorized {
		t.Errorf("bad token: status = %d, want 401", rec.Code)
	}
}

func TestDeriveValidation(t *testing.T) {
	h := newTestService(t).Handler()

	cases := []struct {
		name string
		body string
		want int
	}{
		{"missing index", `{"chain":"MLRT"}`, http.StatusBadRequest},
		{"empty chain", `{"chain":"","index":1}`, http.StatusBadRequest},
		{"hardened index", `{"chain":"MLRT","index":2147483648}`, http.StatusBadRequest},
		{"negative index", `{"chain":"MLRT","index":-1}`, http.StatusBadRequest},
		{"unknown chain", `{"chain":"DOGE","index":1}`, http.StatusBadRequest},
		{"unsupported eth", `{"chain":"ETH","index":1}`, http.StatusNotImplemented},
		{"unsupported tron", `{"chain":"TRON","index":1}`, http.StatusNotImplemented},
		{"unknown field", `{"chain":"MLRT","index":1,"foo":true}`, http.StatusBadRequest},
		{"garbage", `not json`, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := doRequest(t, h, http.MethodPost, "/v1/derive", testToken, tc.body)
			if rec.Code != tc.want {
				t.Errorf("status = %d, want %d (body %s)", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

func TestSignNotImplemented(t *testing.T) {
	h := newTestService(t).Handler()
	rec := doRequest(t, h, http.MethodPost, "/v1/sign", testToken, `{"chain":"MLRT"}`)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", rec.Code)
	}
}

func TestSignRequiresAuth(t *testing.T) {
	h := newTestService(t).Handler()
	if rec := doRequest(t, h, http.MethodPost, "/v1/sign", "", `{}`); rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestHealthUnauthenticated(t *testing.T) {
	h := newTestService(t).Handler()
	rec := doRequest(t, h, http.MethodGet, "/v1/health", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"status":"ok"`) {
		t.Errorf("unexpected health body: %s", rec.Body.String())
	}
}

func TestBootSelfTest(t *testing.T) {
	// Derive a known address, then confirm the self-test accepts it and rejects
	// a wrong one.
	base := newTestService(t)
	addr, err := base.DeriveAddress("MLRT", 7)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}

	idx := uint32(7)
	okCfg := &Config{Token: testToken, MLRTAccountXpub: xpubM0H, MLRTAddressVersion: 50, SelfTestIndex: &idx, SelfTestAddress: addr}
	if _, err := New(okCfg); err != nil {
		t.Errorf("self-test should pass for correct address: %v", err)
	}

	badCfg := &Config{Token: testToken, MLRTAccountXpub: xpubM0H, MLRTAddressVersion: 50, SelfTestIndex: &idx, SelfTestAddress: "Mwrongaddress11111111111111111111"}
	if _, err := New(badCfg); err == nil {
		t.Error("self-test should fail for wrong address, got nil error")
	}
}
