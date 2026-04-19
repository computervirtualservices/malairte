package mining

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"sync"
	"time"
)

// HeartbeatSender posts the miner's status (address, worker id, current
// hashrate) to the explorer every Interval. The explorer uses the presence
// of recent heartbeats to show a rig as "Active" on the miner dashboard —
// the lagging "block mined in last N minutes" signal was too noisy on small
// networks. If URL or Token is empty the sender is disabled and Start is a
// no-op so main.go can unconditionally construct one.
type HeartbeatSender struct {
	URL      string
	Token    string
	Address  string
	WorkerID string
	Interval time.Duration
	Timeout  time.Duration

	// rateFn returns the current hashes-per-second; allows plugging in any
	// source (CPU miner, mock in tests) without coupling to *CpuMiner.
	rateFn func() int64

	client   *http.Client
	cancelFn context.CancelFunc
	wg       sync.WaitGroup
}

// NewHeartbeatSender builds a sender that reads the current hashrate from
// rateFn on every tick. Pass a nil rateFn to report 0 (useful for a
// bare-node heartbeat).
func NewHeartbeatSender(url, token, address, workerID string, rateFn func() int64) *HeartbeatSender {
	if rateFn == nil {
		rateFn = func() int64 { return 0 }
	}
	return &HeartbeatSender{
		URL:      url,
		Token:    token,
		Address:  address,
		WorkerID: workerID,
		Interval: 60 * time.Second,
		Timeout:  10 * time.Second,
		rateFn:   rateFn,
		client:   &http.Client{Timeout: 10 * time.Second},
	}
}

// Enabled reports whether the sender has enough configuration to ping. When
// false Start is a no-op.
func (h *HeartbeatSender) Enabled() bool {
	return h.URL != "" && h.Token != "" && h.Address != ""
}

// Start launches the background goroutine. Calling Start twice is a no-op.
func (h *HeartbeatSender) Start() {
	if !h.Enabled() {
		return
	}
	if h.cancelFn != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	h.cancelFn = cancel
	h.wg.Add(1)
	go h.loop(ctx)
	log.Printf("Heartbeat sender started: %s (worker=%q, interval=%s)", h.URL, h.WorkerID, h.Interval)
}

// Stop waits for the goroutine to exit.
func (h *HeartbeatSender) Stop() {
	if h.cancelFn == nil {
		return
	}
	h.cancelFn()
	h.wg.Wait()
	h.cancelFn = nil
}

func (h *HeartbeatSender) loop(ctx context.Context) {
	defer h.wg.Done()

	// Ping immediately so "Active" shows up without a 60s delay.
	h.send(ctx)

	t := time.NewTicker(h.Interval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			h.send(ctx)
		}
	}
}

func (h *HeartbeatSender) send(ctx context.Context) {
	payload := map[string]any{
		"address":   h.Address,
		"worker_id": h.WorkerID,
		"hashrate":  h.rateFn(),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		log.Printf("heartbeat: marshal: %v", err)
		return
	}

	reqCtx, cancel := context.WithTimeout(ctx, h.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, h.URL, bytes.NewReader(body))
	if err != nil {
		log.Printf("heartbeat: build request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+h.Token)

	resp, err := h.client.Do(req)
	if err != nil {
		log.Printf("heartbeat: POST %s: %v", h.URL, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		log.Printf("heartbeat: %d %s — %s", resp.StatusCode, resp.Status, bytes.TrimSpace(snippet))
		return
	}

	// Drain body so the connection can be reused.
	_, _ = io.Copy(io.Discard, resp.Body)
}
