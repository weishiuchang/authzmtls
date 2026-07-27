// Package logging provides authzmtls's leveled logger: log/slog-based,
// with exactly five levels (TRACE, DEBUG, INFO, WARN, ERROR), each with a
// specific, enumerated purpose (see README.md's "Logging" section).
package logging

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
)

// authzmtls defines exactly five log levels, each with one specific job -
// never a general-purpose bucket - per README.md's "Logging" section.
const (
	// LevelTrace is below slog's built-in DEBUG. Off by default; logs the
	// complete AuthZReq/AuthZRes verbatim and unsanitized (including env
	// vars), so it must be logged as a structured field (slog.Any), never a
	// concatenated string, to stay safe from log injection.
	LevelTrace slog.Level = -8

	// LevelDebug is slog's built-in DEBUG. Off by default; logs allow
	// decisions (which would otherwise drown out INFO given how much
	// traffic never touches a rule), plus the configured allowlist at
	// startup and after every successful reload.
	LevelDebug = slog.LevelDebug

	// LevelInfo is slog's built-in INFO and authzmtls's default level. Logs
	// deny decisions, startup, reload-start, and shutdown - nothing else.
	LevelInfo = slog.LevelInfo

	// LevelWarn is slog's built-in WARN. On by default. Exactly three
	// cases: a live (non-cached) datasource resolution failure, an
	// unrecognized config field being ignored, or a request failing
	// identity sanitization - the last is a deliberate alertable
	// possible-attack signal, not routine noise.
	LevelWarn = slog.LevelWarn

	// LevelError is slog's built-in ERROR. On by default; used exclusively
	// for conditions that crash the process (bad config, bad reload).
	// Every ERROR call site must be followed by process exit, with the
	// logger flushed first so the reason is never lost.
	LevelError = slog.LevelError
)

// levelNames is the canonical level-name table, shared by ParseLevel (config
// input -> slog.Level) and the JSON handler's level rendering (slog.Level ->
// output string) so the two directions can never drift apart.
var levelNames = map[string]slog.Level{
	"TRACE": LevelTrace,
	"DEBUG": LevelDebug,
	"INFO":  LevelInfo,
	"WARN":  LevelWarn,
	"ERROR": LevelError,
}

// ParseLevel parses a case-insensitive level name into its slog.Level; the
// single source of truth for what counts as a valid level name.
func ParseLevel(name string) (slog.Level, error) {
	lvl, ok := levelNames[strings.ToUpper(strings.TrimSpace(name))]
	if !ok {
		return 0, fmt.Errorf("logging: invalid level %q (want one of TRACE, DEBUG, INFO, WARN, ERROR)", name)
	}
	return lvl, nil
}

// ValidLevelName reports whether name is one of the five recognized level
// names; internal/config's validation calls this to reject bad config
// without duplicating the level table.
func ValidLevelName(name string) bool {
	_, err := ParseLevel(name)
	return err == nil
}

// levelName renders l using authzmtls's five-name vocabulary, since slog
// would otherwise print custom TRACE as "DEBUG-4". Levels that don't land
// exactly on one of the five constants are bucketed to the nearest level
// at or below.
func levelName(l slog.Level) string {
	switch {
	case l < LevelDebug:
		return "TRACE"
	case l < LevelInfo:
		return "DEBUG"
	case l < LevelWarn:
		return "INFO"
	case l < LevelError:
		return "WARN"
	default:
		return "ERROR"
	}
}

// New builds the process-wide logger, threshold-filtered at level. Output
// is always JSON, never slog's text handler - load-bearing, since TRACE
// embeds raw request content as a structured field specifically to stay
// safe from log injection.
//
// New does not exit the process on an invalid level name (that's
// internal/config's job at startup); it falls back to LevelInfo instead.
func New(level string) *slog.Logger {
	lvl, err := ParseLevel(level)
	if err != nil {
		lvl = LevelInfo
	}

	handler := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level:       lvl,
		ReplaceAttr: replaceLevelAttr,
	})
	return slog.New(handler)
}

// replaceLevelAttr rewrites the JSON handler's "level" attribute from
// slog.Level's default rendering (which doesn't know about TRACE) to
// authzmtls's five-name vocabulary.
func replaceLevelAttr(_ []string, a slog.Attr) slog.Attr {
	if a.Key != slog.LevelKey {
		return a
	}
	lvl, ok := a.Value.Any().(slog.Level)
	if !ok {
		return a
	}
	a.Value = slog.StringValue(levelName(lvl))
	return a
}

// Trace is a package-level convenience for the one level slog doesn't
// provide a method for, saving callers from repeating the level constant.
func Trace(ctx context.Context, logger *slog.Logger, msg string, args ...any) {
	logger.Log(ctx, LevelTrace, msg, args...)
}
