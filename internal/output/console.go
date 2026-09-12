package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/n4uu/wraith/internal/event"
)

const (
	ansiReset  = "\033[0m"
	ansiDim    = "\033[2m"
	ansiRed    = "\033[31m"
	ansiBoldRd = "\033[1;31m"
	ansiYellow = "\033[33m"
	ansiBlue   = "\033[34m"
	ansiGray   = "\033[90m"
)

var severityColor = map[event.Severity]string{
	event.SevCritical: ansiBoldRd,
	event.SevHigh:     ansiRed,
	event.SevMedium:   ansiYellow,
	event.SevLow:      ansiBlue,
	event.SevInfo:     ansiGray,
}

// Console renders events for a terminal.
type Console struct {
	w     io.Writer
	color bool
}

// NewConsole writes to w, emitting ANSI colour only when color is true.
func NewConsole(w io.Writer, color bool) *Console {
	return &Console{w: w, color: color}
}

func (c *Console) Emit(ev event.Event) error {
	// Pad before painting: ANSI escapes would otherwise count toward the width.
	severity := fmt.Sprintf("%-8s", strings.ToUpper(ev.Rule.Severity.String()))

	line := fmt.Sprintf("%s %s %-15s %-10s %s",
		ev.Time.Format("15:04:05.000"),
		c.paint(severity, severityColor[ev.Rule.Severity]),
		ev.Rule.ID,
		ev.Rule.Technique,
		ev.Message(),
	)

	if _, err := fmt.Fprintln(c.w, line); err != nil {
		return err
	}

	if context := c.context(ev); context != "" {
		if _, err := fmt.Fprintln(c.w, c.paint("    └─ "+context, ansiDim)); err != nil {
			return err
		}
	}
	return nil
}

// context is the indented second line: the provenance an analyst needs before
// deciding whether the alert is worth chasing.
func (c *Console) context(ev event.Event) string {
	var parts []string

	parts = append(parts, fmt.Sprintf("uid=%d", ev.UID))
	if ev.Proc.Exe != "" {
		exe := ev.Proc.Exe
		if ev.Proc.Deleted {
			exe += " (deleted)"
		}
		parts = append(parts, "exe="+exe)
	}
	if ev.Parent.Comm != "" {
		parts = append(parts, fmt.Sprintf("parent=%s[%d]", ev.Parent.Comm, ev.PPID))
	}
	if ev.Target.Exe != "" {
		parts = append(parts, "target_exe="+ev.Target.Exe)
	}
	if ev.Proc.Container != "" {
		parts = append(parts, "container="+ev.Proc.Container)
	}
	if ev.Proc.Cmdline != "" {
		parts = append(parts, "cmdline="+ev.Proc.Cmdline)
	}

	if len(parts) <= 1 {
		return ""
	}
	return strings.Join(parts, "  ")
}

func (c *Console) paint(s, color string) string {
	if !c.color || color == "" {
		return s
	}
	return color + s + ansiReset
}

func (c *Console) Close() error { return nil }
