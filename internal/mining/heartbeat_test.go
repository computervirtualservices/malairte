package mining

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testPubKey = "02a1b2c3d4e5f607182930414253647586979a8b9c0d1e2f301122334455667788"

func TestHeartbeatSender_DisabledWhenUnconfigured(t *testing.T) {
	t.Parallel()

	h := NewHeartbeatSender("", "", "addr", "rig-1", nil)
	if h.Enabled() {
		t.Fatalf("expected disabled when URL+pubkey empty")
	}

	// Start must be a no-op; Stop must not panic.
	h.Start()
	h.Stop()
}

func TestHeartbeatSender_PostsPayloadWithPubKey(t *testing.T) {
	t.Parallel()

	var (
		mu       sync.Mutex
		got      []map[string]any
		hitCount atomic.Int32
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitCount.Add(1)

		body, _ := io.ReadAll(r.Body)
		var payload map[string]any
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Errorf("decode body: %v", err)
		}
		mu.Lock()
		got = append(got, payload)
		mu.Unlock()

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{}}`))
	}))
	defer srv.Close()

	h := NewHeartbeatSender(srv.URL, testPubKey, "Maddr123", "rig-1", func() int64 { return 9001 })
	h.Interval = 40 * time.Millisecond
	h.Start()
	time.Sleep(120 * time.Millisecond)
	h.Stop()

	if hitCount.Load() < 2 {
		t.Fatalf("expected at least 2 pings, got %d", hitCount.Load())
	}

	mu.Lock()
	defer mu.Unlock()
	if len(got) == 0 {
		t.Fatal("no payloads received")
	}
	first := got[0]
	if first["address"] != "Maddr123" {
		t.Errorf("address = %v, want Maddr123", first["address"])
	}
	if first["pubkey"] != testPubKey {
		t.Errorf("pubkey = %v, want %s", first["pubkey"], testPubKey)
	}
	if first["worker_id"] != "rig-1" {
		t.Errorf("worker_id = %v, want rig-1", first["worker_id"])
	}
	if int64(first["hashrate"].(float64)) != 9001 {
		t.Errorf("hashrate = %v, want 9001", first["hashrate"])
	}
}
