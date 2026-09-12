package output

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/n4uu/wraith/internal/event"
)

const webhookQueueSize = 256

// Webhook POSTs alerts to an HTTP endpoint.
//
// Delivery is asynchronous and lossy by design: a slow or unreachable endpoint
// must never stall the ring buffer reader, so a full queue drops the alert and
// bumps a counter instead of applying backpressure to the kernel.
type Webhook struct {
	url    string
	client *http.Client
	queue  chan event.Event
	done   chan struct{}

	dropped  atomic.Uint64
	failed   atomic.Uint64
	closeOne sync.Once
}

type webhookPayload struct {
	// text and content cover Slack- and Discord-shaped receivers; a generic
	// receiver can just read the event object.
	Text    string      `json:"text"`
	Content string      `json:"content"`
	Event   event.Event `json:"event"`
}

// NewWebhook starts the delivery worker for url.
func NewWebhook(url string, timeout time.Duration) *Webhook {
	w := &Webhook{
		url:    url,
		client: &http.Client{Timeout: timeout},
		queue:  make(chan event.Event, webhookQueueSize),
		done:   make(chan struct{}),
	}
	go w.run()
	return w
}

func (w *Webhook) Emit(ev event.Event) error {
	select {
	case w.queue <- ev:
	default:
		w.dropped.Add(1)
	}
	return nil
}

func (w *Webhook) run() {
	defer close(w.done)
	for ev := range w.queue {
		if err := w.post(ev); err != nil {
			w.failed.Add(1)
		}
	}
}

func (w *Webhook) post(ev event.Event) error {
	summary := fmt.Sprintf("[%s] %s (%s) — %s",
		strings.ToUpper(ev.Rule.Severity.String()), ev.Rule.ID, ev.Rule.Technique, ev.Message())

	body, err := json.Marshal(webhookPayload{Text: summary, Content: summary, Event: ev})
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), w.client.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %s", resp.Status)
	}
	return nil
}

// Dropped counts alerts discarded because the queue was full.
func (w *Webhook) Dropped() uint64 { return w.dropped.Load() }

// Failed counts alerts the endpoint rejected or that timed out.
func (w *Webhook) Failed() uint64 { return w.failed.Load() }

// Close drains the queue and waits for the worker to finish.
func (w *Webhook) Close() error {
	w.closeOne.Do(func() {
		close(w.queue)
		<-w.done
	})
	return nil
}
