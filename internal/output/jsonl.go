package output

import (
	"encoding/json"
	"io"
	"sync"

	"github.com/n4uu/wraith/internal/event"
)

// JSONL writes one JSON object per line.
type JSONL struct {
	mu      sync.Mutex
	enc     *json.Encoder
	closer  io.Closer
	flusher interface{ Sync() error }
}

// NewJSONL encodes to w. If w owns a file descriptor, pass it as closer so the
// sink releases it on shutdown.
func NewJSONL(w io.Writer, closer io.Closer) *JSONL {
	j := &JSONL{enc: json.NewEncoder(w), closer: closer}
	if f, ok := w.(interface{ Sync() error }); ok {
		j.flusher = f
	}
	return j
}

func (j *JSONL) Emit(ev event.Event) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.enc.Encode(ev)
}

func (j *JSONL) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()

	if j.flusher != nil {
		_ = j.flusher.Sync()
	}
	if j.closer != nil {
		return j.closer.Close()
	}
	return nil
}
