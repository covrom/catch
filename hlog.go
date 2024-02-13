package catch

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
)

const criticalElapsed = 5 * time.Second

// StructuredLogger is a simple, but powerful implementation of a custom structured
// logger backed on log/slog. I encourage users to copy it, adapt it and make it their
// own. Also take a look at https://github.com/go-chi/httplog for a dedicated pkg based
// on this work, designed for context-based http routers.
// Example:
// logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
// slog.SetDefault(logger) 
// hlog := NewStructuredLogger(slog.Default().Handler(), true)
func NewStructuredLogger(handler slog.Handler, onlyErrs bool) func(next http.Handler) http.Handler {
	return middleware.RequestLogger(
		&StructuredLogger{
			Logger:     handler,
			OnlyErrors: onlyErrs,
		},
	)
}

type StructuredLogger struct {
	Logger     slog.Handler
	OnlyErrors bool
}

func (l *StructuredLogger) NewLogEntry(r *http.Request) middleware.LogEntry {
	var logFields []slog.Attr
	// logFields = append(logFields, slog.String("ts", time.Now().UTC().Format(time.RFC1123)))

	if reqID := middleware.GetReqID(r.Context()); reqID != "" {
		logFields = append(logFields, slog.String("req_id", reqID))
	}

	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}

	handler := l.Logger.WithAttrs(append(logFields,
		slog.String("http_scheme", scheme),
		slog.String("http_proto", r.Proto),
		slog.String("http_method", r.Method),
		slog.String("remote_addr", r.RemoteAddr),
		slog.String("user_agent", r.UserAgent()),
		slog.String("uri", fmt.Sprintf("%s://%s%s", scheme, r.Host, r.RequestURI))))

	entry := StructuredLoggerEntry{
		Ctx:        r.Context(),
		OnlyErrors: l.OnlyErrors,
		Logger:     slog.New(handler),
	}

	// entry.Logger.LogAttrs(entry.Ctx, slog.LevelInfo, "request started")

	return &entry
}

type StructuredLoggerEntry struct {
	Ctx        context.Context
	OnlyErrors bool
	Logger     *slog.Logger
}

func (l *StructuredLoggerEntry) Write(status, bytes int, header http.Header, elapsed time.Duration, extra interface{}) {
	lvl := slog.LevelInfo
	if l.OnlyErrors {
		if status < 400 && elapsed < criticalElapsed {
			return
		}
	}
	if status >= 400 {
		lvl = slog.LevelError
	} else if elapsed > criticalElapsed {
		lvl = slog.LevelWarn
	}
	l.Logger.LogAttrs(l.Ctx, lvl, "request complete",
		slog.Int("resp_status", status),
		slog.Int("resp_byte_length", bytes),
		slog.Float64("resp_elapsed_ms", float64(elapsed.Nanoseconds())/1000000.0),
	)
}

func (l *StructuredLoggerEntry) Panic(v interface{}, stack []byte) {
	l.Logger.LogAttrs(l.Ctx, slog.LevelError, "",
		slog.String("stack", string(stack)),
		slog.String("panic", fmt.Sprintf("%+v", v)),
	)
}

// Helper methods used by the application to get the request-scoped
// logger entry and set additional fields between handlers.
//
// This is a useful pattern to use to set state on the entry as it
// passes through the handler chain, which at any point can be logged
// with a call to .Print(), .Info(), etc.

func GetLogEntry(r *http.Request) *slog.Logger {
	entry := middleware.GetLogEntry(r).(*StructuredLoggerEntry)
	return entry.Logger
}

func LogEntrySetField(r *http.Request, key string, value interface{}) {
	if entry, ok := r.Context().Value(middleware.LogEntryCtxKey).(*StructuredLoggerEntry); ok {
		entry.Logger = entry.Logger.With(key, value)
	}
}

func LogEntrySetAttrs(r *http.Request, attrs ...any) {
	if entry, ok := r.Context().Value(middleware.LogEntryCtxKey).(*StructuredLoggerEntry); ok {
		entry.Logger = entry.Logger.With(attrs...)
	}
}

func LogEntrySetFields(r *http.Request, fields map[string]interface{}) {
	if entry, ok := r.Context().Value(middleware.LogEntryCtxKey).(*StructuredLoggerEntry); ok {
		for k, v := range fields {
			entry.Logger = entry.Logger.With(k, v)
		}
	}
}

func LogAllStatuses(r *http.Request) {
	if entry, ok := r.Context().Value(middleware.LogEntryCtxKey).(*StructuredLoggerEntry); ok {
		entry.OnlyErrors = false
	}
}

func LogHeaders(r *http.Request) {
	if len(r.Header) > 0 {
		headerField := make([]any, 0, 2*len(r.Header))
		for k, v := range r.Header {
			k = strings.ToLower(k)
			switch {
			case len(v) == 0:
				continue
			case len(v) == 1:
				headerField = append(headerField, k, v[0])
			default:
				headerField = append(headerField, k, fmt.Sprintf("[%s]", strings.Join(v, "], [")))
			}
		}

		LogEntrySetAttrs(r, slog.Group("header", headerField...))
	}
}

func GetRequestIdLogger(r *http.Request) *slog.Logger {
	if reqID := middleware.GetReqID(r.Context()); reqID != "" {
		return slog.With(slog.String("req_id", reqID))
	}
	return slog.Default()
}
