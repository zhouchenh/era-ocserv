package udsserve

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/zhouchenh/era-ocserv/internal/auth"
	"github.com/zhouchenh/era-ocserv/internal/certctx"
)

// wrapHandler is the per-stream HTTP middleware the UDS bridge inserts
// in front of the cstp.Server handler chain.
//
// What it does:
//
//   - Reads the parsed *HandoffInfo from the request context (set by
//     http.Server.ConnContext).
//   - Extracts the device UUID from the TLV-carried Subject DN via
//     auth.DeviceIDFromSubjectDN.
//   - Stores the device id on the request context using certctx, so
//     the downstream certBoundVerifier (defined in cmd/era-ocserv)
//     cross-checks it against the password-verify response — exactly
//     the same flow as legacy loopback mode, just with a different
//     extraction source.
//   - Logs a per-request trace line carrying the facade-supplied
//     trace_id + device_id + user_id (spec §8.3 lifecycle event).
//
// On any failure (HandoffInfo absent, Subject DN malformed, CN not
// idgen-shaped) the middleware short-circuits the request with HTTP
// 400/401 and the downstream handler is not invoked.
func wrapHandler(next http.Handler, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info, ok := FromContext(r.Context())
		if !ok || info == nil {
			http.Error(w, "missing UDS handoff info", http.StatusInternalServerError)
			return
		}
		deviceID, err := auth.DeviceIDFromSubjectDN(info.SubjectDN)
		if err != nil {
			logger.Warn("uds handoff subject DN invalid",
				slog.String("trace_id", info.TraceID),
				slog.String("subject_dn", info.SubjectDN),
				slog.String("err", err.Error()),
			)
			if errors.Is(err, auth.ErrInvalidSubjectDN) {
				http.Error(w, "invalid subject DN", http.StatusBadRequest)
				return
			}
			http.Error(w, "device id not present in subject DN", http.StatusUnauthorized)
			return
		}
		// Note: `ERA_TLV_DEVICE_ID` carries an era-portal device-UUID
		// (RFC 4122 form per UDS spec §4.2), while the cert CN we just
		// extracted is era-ocserv's idgen-shaped device id (dev_<26
		// base32>; see internal/auth/deviceid.go). The two identify
		// the same device but live in different namespaces; cross-
		// checking them is the facade's job (token → device →
		// cert+UUID mapping) and is captured in HandoffInfo.DeviceID
		// for diagnostics only.
		ctx := certctx.WithDeviceID(r.Context(), deviceID)
		logger.Debug("uds handoff serving request",
			slog.String("trace_id", info.TraceID),
			slog.String("device_id", deviceID),
			slog.String("user_id", info.UserID),
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
		)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
