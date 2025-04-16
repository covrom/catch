package catch

import (
	"fmt"
	"log/slog"
	"net/http"
	"runtime"
	"strings"

	"github.com/go-chi/render"
)

// ErrResponse represents an error response structure
type ErrResponse struct {
	Err            error `json:"-"` // Low-level runtime error
	HTTPStatusCode int   `json:"-"` // HTTP response status code

	StatusText string `json:"status"`          // User-level status message
	AppCode    int64  `json:"code,omitempty"`  // Application-specific error code
	ErrorText  string `json:"error,omitempty"` // Application-level error message
}

// Render implements the render.Renderer interface
func (e *ErrResponse) Render(w http.ResponseWriter, r *http.Request) error {
	render.Status(r, e.HTTPStatusCode)
	return nil
}

// Error implements the error interface
func (e *ErrResponse) Error() string {
	return fmt.Sprintf("%d %s %s", e.AppCode, e.StatusText, e.ErrorText)
}

// Recoverer is a middleware that recovers from panics
func Recoverer(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rvr := recover(); rvr != nil && rvr != http.ErrAbortHandler {
				v := Identify()

				slog.Error("panic", "recovered", rvr, "caller", v)

				render.Render(w, r, &ErrResponse{
					ErrorText:      "panic",
					StatusText:     "panic",
					HTTPStatusCode: http.StatusInternalServerError,
				})
			}
		}()
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

// Identify returns the package name, file name and line number where panic occurred
func Identify() string {
	var name, file string
	var line int
	var pc [16]uintptr

	n := runtime.Callers(3, pc[:])
	for _, pc := range pc[:n] {
		fn := runtime.FuncForPC(pc)
		if fn == nil {
			continue
		}
		file, line = fn.FileLine(pc)
		name = fn.Name()
		if !strings.HasPrefix(name, "runtime.") {
			break
		}
	}

	return fmt.Sprintf("name: %v, file: %v:%v", name, file, line)
}

// Protection adds security headers to responses
func Protection(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=15768000; includeSubDomains")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}
