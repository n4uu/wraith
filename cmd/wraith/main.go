// Command wraith watches the kernel for fileless and in-memory attack
// techniques and reports them as structured alerts.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"golang.org/x/sys/unix"

	"github.com/n4uu/wraith/internal/event"
	"github.com/n4uu/wraith/internal/output"
	"github.com/n4uu/wraith/internal/sensor"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "dev"

type options struct {
	jsonOut        bool
	outPath        string
	webhookURL     string
	webhookTimeout time.Duration
	minSeverity    string
	excludeComms   string
	dedupWindow    time.Duration
	emitInfo       bool
	noColor        bool
	listRules      bool
	showVersion    bool
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "wraith: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	opts := parseFlags()

	switch {
	case opts.showVersion:
		fmt.Printf("wraith %s\n", version)
		return nil
	case opts.listRules:
		printRules(os.Stdout)
		return nil
	}

	minSeverity, err := event.ParseSeverity(opts.minSeverity)
	if err != nil {
		return err
	}

	sinks, webhook, err := buildSinks(opts)
	if err != nil {
		return err
	}
	defer sinks.Close()

	s, err := sensor.Load(sensor.Config{EmitInfo: opts.emitInfo})
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			return fmt.Errorf("%w\nwraith needs CAP_BPF and CAP_PERFMON (run it as root)", err)
		}
		return err
	}
	defer s.Close()

	for _, warning := range s.Warnings {
		fmt.Fprintf(os.Stderr, "warning: %s\n", warning)
	}

	filter := output.NewFilter(minSeverity, splitComms(opts.excludeComms), opts.dedupWindow)

	fmt.Fprintf(os.Stderr, "wraith %s: watching for in-memory execution and process injection (min severity: %s)\n",
		version, minSeverity)
	fmt.Fprintf(os.Stderr, "press ctrl-c to stop\n\n")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	runErr := s.Run(ctx, func(ev event.Event) {
		if !filter.Allow(ev) {
			return
		}
		if err := sinks.Emit(ev); err != nil {
			fmt.Fprintf(os.Stderr, "emit: %v\n", err)
		}
	})

	printSummary(s, filter, webhook)

	return runErr
}

func parseFlags() options {
	var opts options

	flag.BoolVar(&opts.jsonOut, "json", false, "write JSON lines to stdout instead of the human-readable console")
	flag.StringVar(&opts.outPath, "out", "", "append JSON lines to this file as well")
	flag.StringVar(&opts.webhookURL, "webhook", "", "POST every alert to this URL (Slack/Discord compatible)")
	flag.DurationVar(&opts.webhookTimeout, "webhook-timeout", 5*time.Second, "per-request webhook timeout")
	flag.StringVar(&opts.minSeverity, "min-severity", "low", "minimum severity to report: info, low, medium, high, critical")
	flag.StringVar(&opts.excludeComms, "exclude-comm", "", "comma-separated process names to ignore")
	flag.DurationVar(&opts.dedupWindow, "dedup", 5*time.Second, "collapse identical alerts within this window (0 disables)")
	flag.BoolVar(&opts.emitInfo, "info", false, "also report informational signals such as bare memfd_create calls (pair with -min-severity info, since they're filtered out below that by default)")
	flag.BoolVar(&opts.noColor, "no-color", false, "disable ANSI colour")
	flag.BoolVar(&opts.listRules, "list-rules", false, "print the detection catalog and exit")
	flag.BoolVar(&opts.showVersion, "version", false, "print version and exit")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "wraith: eBPF sensor for fileless execution and process injection on Linux\n\n")
		fmt.Fprintf(os.Stderr, "usage: sudo wraith [flags]\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	return opts
}

func buildSinks(opts options) (output.Multi, *output.Webhook, error) {
	var sinks output.Multi

	if opts.jsonOut {
		sinks = append(sinks, output.NewJSONL(os.Stdout, nil))
	} else {
		sinks = append(sinks, output.NewConsole(os.Stdout, !opts.noColor && isTerminal(os.Stdout)))
	}

	if opts.outPath != "" {
		f, err := os.OpenFile(opts.outPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, nil, fmt.Errorf("open %s: %w", opts.outPath, err)
		}
		sinks = append(sinks, output.NewJSONL(f, f))
	}

	var webhook *output.Webhook
	if opts.webhookURL != "" {
		webhook = output.NewWebhook(opts.webhookURL, opts.webhookTimeout)
		sinks = append(sinks, webhook)
	}

	return sinks, webhook, nil
}

func printRules(w *os.File) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "RULE\tSEVERITY\tTECHNIQUE\tTITLE")
	for _, r := range event.Rules() {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", r.ID, r.Severity, r.Technique, r.Title)
	}
	tw.Flush()

	fmt.Fprintln(w)
	for _, r := range event.Rules() {
		fmt.Fprintf(w, "%s (%s: %s)\n  %s\n\n", r.ID, r.Technique, r.TechniqueName, r.Rationale)
	}
}

func printSummary(s *sensor.Sensor, filter *output.Filter, webhook *output.Webhook) {
	stats, err := s.Stats()
	if err != nil {
		return
	}

	fmt.Fprintf(os.Stderr, "\n%d signal(s) raised by the kernel, %d deduplicated", stats.Emitted, filter.Suppressed())
	if stats.Dropped > 0 {
		fmt.Fprintf(os.Stderr, ", %d lost to a full ring buffer", stats.Dropped)
	}
	if webhook != nil {
		if dropped := webhook.Dropped(); dropped > 0 {
			fmt.Fprintf(os.Stderr, ", %d webhook alerts dropped", dropped)
		}
		if failed := webhook.Failed(); failed > 0 {
			fmt.Fprintf(os.Stderr, ", %d webhook deliveries failed", failed)
		}
	}
	fmt.Fprintln(os.Stderr)
}

func splitComms(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func isTerminal(f *os.File) bool {
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	return err == nil
}
