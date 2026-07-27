// Package dockerapi implements the Docker Engine API authorization plugin
// protocol: the AuthZReq/AuthZRes wire types and the HTTP handlers for
// /Plugin.Activate, /AuthZPlugin.AuthZReq, and /AuthZPlugin.AuthZRes, per
// https://docs.docker.com/engine/extend/plugins_authorization/.
package dockerapi

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"go.opentelemetry.io/otel/metric"

	"github.com/weishiuchang/authzmtls/internal/logging"
	"github.com/weishiuchang/authzmtls/internal/telemetry"
)

// Decider is the injected policy interface: dockerapi's HTTP handlers decode
// the wire protocol and delegate the actual allow/deny decision here, so
// the rule engine can be wired in later without this package changing. A
// non-nil error is a plugin-side failure (surfaced via AuthZRes.Err, treated
// as a deny by dockerd), distinct from a policy-driven deny.
type Decider interface {
	Decide(ctx context.Context, req *AuthZReq) (allow bool, msg string, err error)
}

// DeciderFunc adapts a plain function to the Decider interface, mirroring
// http.HandlerFunc.
type DeciderFunc func(ctx context.Context, req *AuthZReq) (allow bool, msg string, err error)

// Decide implements Decider.
func (f DeciderFunc) Decide(ctx context.Context, req *AuthZReq) (bool, string, error) {
	return f(ctx, req)
}

// latencyHistogramName is the OTel instrument name for end-to-end
// /AuthZPlugin.AuthZReq handling time, recorded for every request regardless
// of outcome.
const latencyHistogramName = "authzmtls.latency"

// Handler implements the Docker Engine API authorization plugin protocol
// (/Plugin.Activate, /AuthZPlugin.AuthZReq, /AuthZPlugin.AuthZRes),
// decoding the wire types in types.go and delegating decisions to an
// injected Decider.
type Handler struct {
	decider Decider
	logger  *slog.Logger
	latency metric.Float64Histogram
}

// NewHandler constructs a Handler. logger must be non-nil; TRACE-level
// request/response logging relies on it being the process-wide slog.Logger
// so its level threshold is respected.
func NewHandler(decider Decider, logger *slog.Logger) *Handler {
	hist, _ := telemetry.Meter().Float64Histogram(
		latencyHistogramName,
		metric.WithUnit("ms"),
		metric.WithDescription("End-to-end /AuthZPlugin.AuthZReq handling latency, every request regardless of outcome."),
	)
	// Float64Histogram always returns a usable (possibly no-op) instrument
	// even on error, so hist is safe to store unconditionally.
	return &Handler{decider: decider, logger: logger, latency: hist}
}

// Mux returns an http.Handler with all three protocol endpoints registered.
func (h *Handler) Mux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/Plugin.Activate", h.handleActivate)
	mux.HandleFunc("/AuthZPlugin.AuthZReq", h.handleAuthZReq)
	mux.HandleFunc("/AuthZPlugin.AuthZRes", h.handleAuthZRes)
	return mux
}

// handleActivate implements the Docker plugin discovery handshake: every
// Docker plugin must answer /Plugin.Activate with the interfaces it
// implements.
func (h *Handler) handleActivate(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, PluginActivateRes{Implements: []string{"authz"}})
}

// handleAuthZReq implements /AuthZPlugin.AuthZReq, called before dockerd
// executes the original request. The full handler body is timed and
// recorded to authzmtls.latency regardless of outcome.
func (h *Handler) handleAuthZReq(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer func() {
		elapsedMS := float64(time.Since(start)) / float64(time.Millisecond)
		h.latency.Record(r.Context(), elapsedMS)
	}()

	req, ok := h.decodeRequest(w, r)
	if !ok {
		return
	}

	allow, msg, err := h.decider.Decide(r.Context(), req)
	res := AuthZRes{Allow: allow, Msg: msg}
	if err != nil {
		res.Err = err.Error()
	}

	h.writeAuthZRes(w, r, res)
}

// handleAuthZRes implements /AuthZPlugin.AuthZRes, called after dockerd
// executes the original request, carrying the daemon's response alongside
// the original request fields. Delegates to the same Decider as
// /AuthZPlugin.AuthZReq; this package only wires the protocol.
func (h *Handler) handleAuthZRes(w http.ResponseWriter, r *http.Request) {
	req, ok := h.decodeRequest(w, r)
	if !ok {
		return
	}

	allow, msg, err := h.decider.Decide(r.Context(), req)
	res := AuthZRes{Allow: allow, Msg: msg}
	if err != nil {
		res.Err = err.Error()
	}

	h.writeAuthZRes(w, r, res)
}

// decodeRequest decodes the AuthZReq JSON body and, on success, logs it at
// TRACE. Logging via slog.Any (a structured field) rather than a
// concatenated string keeps this safe from log injection despite carrying
// raw, attacker-influenced request content verbatim.
//
// On decode failure it writes a 400 response itself and returns ok=false;
// callers should return immediately in that case.
func (h *Handler) decodeRequest(w http.ResponseWriter, r *http.Request) (*AuthZReq, bool) {
	var req AuthZReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, AuthZRes{Allow: false, Err: "malformed AuthZReq: " + err.Error()})
		return nil, false
	}

	logging.Trace(r.Context(), h.logger, "docker authz request", slog.Any("request", &req))

	return &req, true
}

// writeAuthZRes logs res at TRACE immediately before writing it as the HTTP
// response body, centralizing the logging both AuthZReq and AuthZRes
// handlers share.
func (h *Handler) writeAuthZRes(w http.ResponseWriter, r *http.Request, res AuthZRes) {
	logging.Trace(r.Context(), h.logger, "docker authz response", slog.Any("response", &res))
	writeJSON(w, http.StatusOK, res)
}

// writeJSON writes v as a JSON response body with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
