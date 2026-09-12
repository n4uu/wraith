// Package output turns events into something a human or a log pipeline reads.
package output

import (
	"errors"

	"github.com/n4uu/wraith/internal/event"
)

// Sink consumes detections.
type Sink interface {
	Emit(event.Event) error
	Close() error
}

// Multi fans an event out to every sink, collecting rather than short-circuiting
// on error: a broken webhook must not silence the console.
type Multi []Sink

func (m Multi) Emit(ev event.Event) error {
	var errs []error
	for _, s := range m {
		if err := s.Emit(ev); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (m Multi) Close() error {
	var errs []error
	for _, s := range m {
		if err := s.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
