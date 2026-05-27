package udshandoff

import (
	"log/slog"
	"net/netip"
	"time"

	"github.com/zhouchenh/era-ocserv/internal/proxyproto"
)

// Event names the spec §8.3 lifecycle event taxonomy.
type Event string

const (
	EventHandoffStart   Event = "handoff_start"
	EventHandoffInvalid Event = "handoff_invalid"
	EventFlowClosed     Event = "flow_closed"
	EventFlowError      Event = "flow_error"
)

// LogFields is the structured-log payload the spec §8.3 requires on every
// flow lifecycle event. The field names match the spec's list (trace_id,
// protocol, client_src, original_dst, device_id, user_id, event,
// bytes_in, bytes_out, duration_ms).
//
// Callers populate the relevant subset; unknown fields are zero-valued and
// omitted by EmitTo.
type LogFields struct {
	TraceID     string
	Protocol    ProtocolName
	ClientSrc   netip.AddrPort
	OriginalDst netip.AddrPort
	DeviceID    string
	UserID      string
	Event       Event
	BytesIn     int64
	BytesOut    int64
	Duration    time.Duration

	// Extra slog attributes — used to carry rejection-cause detail
	// (e.g. on EventHandoffInvalid: kind=duplicate_tlv, type=0xE3). The
	// listener attaches these so the operator can debug a single failure
	// without grepping multiple lines.
	Extra []slog.Attr
}

// EmitTo writes the fields to logger at the given level. Omitted fields are
// skipped so a "flow_closed" line doesn't carry an empty device_id (which
// would confuse log grep / tooling).
func (f LogFields) EmitTo(logger *slog.Logger, level slog.Level, msg string) {
	if logger == nil {
		return
	}
	attrs := make([]slog.Attr, 0, 12+len(f.Extra))
	if f.Event != "" {
		attrs = append(attrs, slog.String("event", string(f.Event)))
	}
	if f.TraceID != "" {
		attrs = append(attrs, slog.String("trace_id", f.TraceID))
	}
	if f.Protocol != "" {
		attrs = append(attrs, slog.String("protocol", string(f.Protocol)))
	}
	if f.ClientSrc.IsValid() {
		attrs = append(attrs, slog.String("client_src", f.ClientSrc.String()))
	}
	if f.OriginalDst.IsValid() {
		attrs = append(attrs, slog.String("original_dst", f.OriginalDst.String()))
	}
	if f.DeviceID != "" {
		attrs = append(attrs, slog.String("device_id", f.DeviceID))
	}
	if f.UserID != "" {
		attrs = append(attrs, slog.String("user_id", f.UserID))
	}
	if f.BytesIn != 0 || f.Event == EventFlowClosed || f.Event == EventFlowError {
		attrs = append(attrs, slog.Int64("bytes_in", f.BytesIn))
	}
	if f.BytesOut != 0 || f.Event == EventFlowClosed || f.Event == EventFlowError {
		attrs = append(attrs, slog.Int64("bytes_out", f.BytesOut))
	}
	if f.Duration > 0 || f.Event == EventFlowClosed || f.Event == EventFlowError {
		attrs = append(attrs, slog.Int64("duration_ms", f.Duration.Milliseconds()))
	}
	attrs = append(attrs, f.Extra...)
	logger.LogAttrs(nil, level, msg, attrs...)
}

// FromTLVs populates the subset of LogFields that can be read directly from
// parsed TLVs (TraceID, DeviceID, UserID) — convenience for the listener.
func (f *LogFields) FromTLVs(tlvs []proxyproto.TLV) {
	for _, t := range tlvs {
		switch t.Type {
		case proxyproto.EraTLVTraceID:
			f.TraceID = string(t.Value)
		case proxyproto.EraTLVDeviceID:
			f.DeviceID = string(t.Value)
		case proxyproto.EraTLVUserID:
			f.UserID = string(t.Value)
		}
	}
}
