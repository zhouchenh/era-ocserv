package udshandoff

import (
	"fmt"

	"github.com/zhouchenh/era-ocserv/internal/proxyproto"
)

// ProtocolName is the spec §7 protocol identifier. The string values match
// the spec's "Protocol" column verbatim where practical; mixed-case Aliases
// are normalised by Lookup.
type ProtocolName string

// Canonical protocol names matching the spec §7 matrix rows. These are the
// labels emitted in counter / log dimensions.
const (
	ProtoVLESSRealityVisionSeed ProtocolName = "vless-reality-vision-seed"
	ProtoAnyTLS                 ProtocolName = "anytls"
	ProtoVLESSWSSync            ProtocolName = "vless-ws-sync"
	ProtoVLESSWSTransfer        ProtocolName = "vless-ws-transfer"
	ProtoVLESSWSLive            ProtocolName = "vless-ws-live"
	ProtoTTConnect              ProtocolName = "tt-connect"
	ProtoAnyConnectCSTP         ProtocolName = "anyconnect-cstp"
	ProtoAnyConnectDTLS         ProtocolName = "anyconnect-dtls"
	ProtoShadowTLS              ProtocolName = "shadow-tls"
	ProtoHysteria2              ProtocolName = "hy2"
	ProtoJuicity                ProtocolName = "juicity"
	ProtoTTH3                   ProtocolName = "tt-h3"
	ProtoBrowserH3              ProtocolName = "browser-h3"
	ProtoDriveWeb               ProtocolName = "drive-web"
)

// Spec declares the per-protocol TLV requirements as in spec §7.
//
// Mandatory: every flow MUST carry these. Missing → reject.
// Optional:  emission allowed but not required. Caller decides what to do.
// Forbidden: emission disallowed. Present → reject.
//
// `EraTLVSpecVersion` (0xEF) and `EraTLVTraceID` (0xEE) are mandatory for
// every protocol — they are stamped in the per-protocol Spec instances below,
// so the validator handles them uniformly.
type Spec struct {
	// Name is the protocol's canonical name (used in logs + counters).
	Name ProtocolName
	// L4 is "tcp" or "udp" — pinned because the wire shape differs (§3 vs §5).
	L4 string
	// Mandatory TLVs (must appear).
	Mandatory []proxyproto.TLVType
	// Optional TLVs (may or may not appear; no validator rejection).
	Optional []proxyproto.TLVType
	// Forbidden TLVs (must NOT appear).
	Forbidden []proxyproto.TLVType
}

// universalMandatory lists TLVs every protocol MUST carry per §7.
var universalMandatory = []proxyproto.TLVType{
	proxyproto.EraTLVSpecVersion,
	proxyproto.EraTLVTraceID,
}

// universalOptional lists TLVs that are universally optional per §7
// ("standard PROXY-v2 TLVs PP2_TYPE_ALPN / PP2_TYPE_AUTHORITY / PP2_TYPE_SSL
// are universally optional except where called out").
var universalOptional = []proxyproto.TLVType{
	proxyproto.PP2TypeALPN,
	proxyproto.PP2TypeAuthority,
	proxyproto.PP2TypeSSL,
}

// matrix is the spec §7 table encoded as code. Each entry's Mandatory /
// Optional / Forbidden slices are the row's M/O/F columns, with the two
// universal-mandatory TLVs (0xEF SpecVersion, 0xEE TraceID) prepended.
//
// Two TLVs are not in the §7 column header but matter to the validator:
//   - EraTLVRouteTag (0xE0) is the pre-existing ADR-F3 TLV. The §7 table
//     doesn't list it; treat it as universally optional (the spec text
//     describes it as "emitted opportunistically").
//   - The standard PP2 TLVs (PP2TypeALPN/Authority/SSL) are universally
//     optional per the §7 note above.
//
// `ProtocolMatrix.Lookup` returns a Spec the caller can pass to
// `Spec.Validate(parsed)`.
var matrix = map[ProtocolName]Spec{
	ProtoVLESSRealityVisionSeed: {
		Name: ProtoVLESSRealityVisionSeed, L4: "tcp",
		// SNI=O ALPNd=O TOKEN=F DEVICE=M USER=M VLESS-target=M VLESS-UUID=M
		// VLESS-flow=M QUIC-CID=F QUIC-stream=F DTLS-PSK=F SOURCE-V6=M mTLS-DN=F
		Mandatory: tlvs(
			proxyproto.EraTLVDeviceID, proxyproto.EraTLVUserID,
			proxyproto.EraTLVVLESSTarget, proxyproto.EraTLVVLESSUUID,
			proxyproto.EraTLVVLESSFlow, proxyproto.EraTLVSourceHintV6,
		),
		Optional: tlvs(proxyproto.EraTLVOrigSNI, proxyproto.EraTLVALPNDetail),
		Forbidden: tlvs(
			proxyproto.EraTLVToken, proxyproto.EraTLVQUICConnID,
			proxyproto.EraTLVQUICStreamID, proxyproto.EraTLVDTLSPSK,
			proxyproto.EraTLVMTLSSubjectDN,
		),
	},
	ProtoAnyTLS: {
		Name: ProtoAnyTLS, L4: "tcp",
		Mandatory: tlvs(
			proxyproto.EraTLVToken, proxyproto.EraTLVDeviceID,
			proxyproto.EraTLVUserID, proxyproto.EraTLVSourceHintV6,
		),
		Optional: tlvs(proxyproto.EraTLVOrigSNI, proxyproto.EraTLVALPNDetail),
		Forbidden: tlvs(
			proxyproto.EraTLVVLESSTarget, proxyproto.EraTLVVLESSUUID,
			proxyproto.EraTLVVLESSFlow, proxyproto.EraTLVQUICConnID,
			proxyproto.EraTLVQUICStreamID, proxyproto.EraTLVDTLSPSK,
			proxyproto.EraTLVMTLSSubjectDN,
		),
	},
	ProtoVLESSWSSync: vlessWSSpec(ProtoVLESSWSSync),
	ProtoVLESSWSTransfer: vlessWSSpec(ProtoVLESSWSTransfer),
	ProtoVLESSWSLive: vlessWSSpec(ProtoVLESSWSLive),
	ProtoTTConnect: {
		Name: ProtoTTConnect, L4: "tcp",
		Mandatory: tlvs(
			proxyproto.EraTLVToken, proxyproto.EraTLVDeviceID,
			proxyproto.EraTLVUserID, proxyproto.EraTLVALPNDetail,
			proxyproto.EraTLVSourceHintV6,
		),
		Optional: tlvs(proxyproto.EraTLVOrigSNI),
		Forbidden: tlvs(
			proxyproto.EraTLVVLESSTarget, proxyproto.EraTLVVLESSUUID,
			proxyproto.EraTLVVLESSFlow, proxyproto.EraTLVQUICConnID,
			proxyproto.EraTLVQUICStreamID, proxyproto.EraTLVDTLSPSK,
			proxyproto.EraTLVMTLSSubjectDN,
		),
	},
	ProtoAnyConnectCSTP: {
		Name: ProtoAnyConnectCSTP, L4: "tcp",
		Mandatory: tlvs(
			proxyproto.EraTLVToken, proxyproto.EraTLVDeviceID,
			proxyproto.EraTLVUserID, proxyproto.EraTLVSourceHintV6,
			proxyproto.EraTLVMTLSSubjectDN,
		),
		Optional: tlvs(proxyproto.EraTLVOrigSNI, proxyproto.EraTLVALPNDetail),
		Forbidden: tlvs(
			proxyproto.EraTLVVLESSTarget, proxyproto.EraTLVVLESSUUID,
			proxyproto.EraTLVVLESSFlow, proxyproto.EraTLVQUICConnID,
			proxyproto.EraTLVQUICStreamID, proxyproto.EraTLVDTLSPSK,
		),
	},
	ProtoAnyConnectDTLS: {
		Name: ProtoAnyConnectDTLS, L4: "udp",
		// SNI=F ALPNd=F TOKEN=M DEVICE=M USER=M VLESS-target=F VLESS-UUID=F
		// VLESS-flow=F QUIC-CID=F QUIC-stream=F DTLS-PSK=M SOURCE-V6=M mTLS-DN=M
		Mandatory: tlvs(
			proxyproto.EraTLVToken, proxyproto.EraTLVDeviceID,
			proxyproto.EraTLVUserID, proxyproto.EraTLVDTLSPSK,
			proxyproto.EraTLVSourceHintV6, proxyproto.EraTLVMTLSSubjectDN,
		),
		Optional: nil,
		Forbidden: tlvs(
			proxyproto.EraTLVOrigSNI, proxyproto.EraTLVALPNDetail,
			proxyproto.EraTLVVLESSTarget, proxyproto.EraTLVVLESSUUID,
			proxyproto.EraTLVVLESSFlow, proxyproto.EraTLVQUICConnID,
			proxyproto.EraTLVQUICStreamID,
		),
	},
	ProtoShadowTLS: {
		Name: ProtoShadowTLS, L4: "tcp",
		Mandatory: tlvs(
			proxyproto.EraTLVToken, proxyproto.EraTLVDeviceID,
			proxyproto.EraTLVUserID, proxyproto.EraTLVSourceHintV6,
		),
		Optional: tlvs(proxyproto.EraTLVOrigSNI, proxyproto.EraTLVALPNDetail),
		Forbidden: tlvs(
			proxyproto.EraTLVVLESSTarget, proxyproto.EraTLVVLESSUUID,
			proxyproto.EraTLVVLESSFlow, proxyproto.EraTLVQUICConnID,
			proxyproto.EraTLVQUICStreamID, proxyproto.EraTLVDTLSPSK,
			proxyproto.EraTLVMTLSSubjectDN,
		),
	},
	ProtoHysteria2: quicEgressSpec(ProtoHysteria2),
	ProtoJuicity:   quicEgressSpec(ProtoJuicity),
	ProtoTTH3:      quicEgressSpec(ProtoTTH3),
	ProtoBrowserH3: {
		Name: ProtoBrowserH3, L4: "udp",
		// SNI=O ALPNd=M TOKEN=F DEVICE=F USER=F VLESS-target=F VLESS-UUID=F
		// VLESS-flow=F QUIC-CID=M QUIC-stream=O DTLS-PSK=F SOURCE-V6=F mTLS-DN=F
		Mandatory: tlvs(proxyproto.EraTLVALPNDetail, proxyproto.EraTLVQUICConnID),
		Optional:  tlvs(proxyproto.EraTLVOrigSNI, proxyproto.EraTLVQUICStreamID),
		Forbidden: tlvs(
			proxyproto.EraTLVToken, proxyproto.EraTLVDeviceID,
			proxyproto.EraTLVUserID, proxyproto.EraTLVVLESSTarget,
			proxyproto.EraTLVVLESSUUID, proxyproto.EraTLVVLESSFlow,
			proxyproto.EraTLVDTLSPSK, proxyproto.EraTLVSourceHintV6,
			proxyproto.EraTLVMTLSSubjectDN,
		),
	},
	ProtoDriveWeb: {
		Name: ProtoDriveWeb, L4: "tcp",
		// Everything except universals = F. No backend-egress, no per-device
		// keying — drive-web is a reverse-proxy hop to era-portal.
		Mandatory: nil,
		Optional:  tlvs(proxyproto.EraTLVOrigSNI, proxyproto.EraTLVALPNDetail),
		Forbidden: tlvs(
			proxyproto.EraTLVToken, proxyproto.EraTLVDeviceID,
			proxyproto.EraTLVUserID, proxyproto.EraTLVVLESSTarget,
			proxyproto.EraTLVVLESSUUID, proxyproto.EraTLVVLESSFlow,
			proxyproto.EraTLVQUICConnID, proxyproto.EraTLVQUICStreamID,
			proxyproto.EraTLVDTLSPSK, proxyproto.EraTLVSourceHintV6,
			proxyproto.EraTLVMTLSSubjectDN,
		),
	},
}

// tlvs is a typed sugar helper for the matrix literal.
func tlvs(types ...proxyproto.TLVType) []proxyproto.TLVType { return types }

// vlessWSSpec returns the shared shape used by all three vless_ws path modes
// (sync / transfer / live). Per §7, the three rows are identical.
func vlessWSSpec(name ProtocolName) Spec {
	return Spec{
		Name: name, L4: "tcp",
		Mandatory: tlvs(
			proxyproto.EraTLVToken, proxyproto.EraTLVDeviceID,
			proxyproto.EraTLVUserID, proxyproto.EraTLVALPNDetail,
			proxyproto.EraTLVSourceHintV6,
		),
		Optional: tlvs(proxyproto.EraTLVOrigSNI),
		Forbidden: tlvs(
			proxyproto.EraTLVVLESSTarget, proxyproto.EraTLVVLESSUUID,
			proxyproto.EraTLVVLESSFlow, proxyproto.EraTLVQUICConnID,
			proxyproto.EraTLVQUICStreamID, proxyproto.EraTLVDTLSPSK,
			proxyproto.EraTLVMTLSSubjectDN,
		),
	}
}

// quicEgressSpec is the shape shared by hy2 / juicity / tt-h3. Per §7 they
// are identical (Browser h3 is different — no token, no source hint).
func quicEgressSpec(name ProtocolName) Spec {
	return Spec{
		Name: name, L4: "udp",
		Mandatory: tlvs(
			proxyproto.EraTLVToken, proxyproto.EraTLVDeviceID,
			proxyproto.EraTLVUserID, proxyproto.EraTLVALPNDetail,
			proxyproto.EraTLVQUICConnID, proxyproto.EraTLVSourceHintV6,
		),
		Optional: tlvs(proxyproto.EraTLVOrigSNI, proxyproto.EraTLVQUICStreamID),
		Forbidden: tlvs(
			proxyproto.EraTLVVLESSTarget, proxyproto.EraTLVVLESSUUID,
			proxyproto.EraTLVVLESSFlow, proxyproto.EraTLVDTLSPSK,
			proxyproto.EraTLVMTLSSubjectDN,
		),
	}
}

// LookupProtocol returns the spec for a protocol name. Returns nil if the
// name is not in the matrix.
//
// The matrix is read-only after init; callers can hold the *Spec pointer
// safely across goroutines.
func LookupProtocol(name ProtocolName) *Spec {
	if s, ok := matrix[name]; ok {
		// Return a pointer to the map's value. Since matrix is never mutated
		// after init this is safe; tests cover the immutability assertion.
		spec := s
		return &spec
	}
	return nil
}

// AllProtocols returns the canonical protocol names in alphabetical order.
// Mostly useful for tests + metric-dimension enumeration.
func AllProtocols() []ProtocolName {
	out := make([]ProtocolName, 0, len(matrix))
	for k := range matrix {
		out = append(out, k)
	}
	sortProtocolNames(out)
	return out
}

// Validate checks parsed TLVs against the protocol's spec. The result names
// the kind of failure for the caller (so the listener can pick the right
// counter / log line).
//
// Universal mandatory TLVs (0xEF SpecVersion, 0xEE TraceID) are checked first.
// Per-protocol mandatory / forbidden checks follow. Unknown ERA TLVs are not
// rejected here — they are caller-handled per spec §4.4 (skip+log).
//
// The validator does NOT itself increment counters; the caller does, because
// the unknown-ERA-TLV counter is dimensioned by {type, protocol} and the
// caller has the protocol context.
type ValidateResult struct {
	// OK indicates the TLVs pass both mandatory and forbidden checks.
	OK bool
	// MissingMandatory lists TLV types that were declared M but absent.
	MissingMandatory []proxyproto.TLVType
	// PresentForbidden lists TLV types that were declared F but present.
	PresentForbidden []proxyproto.TLVType
	// ValueErrors lists TLVs whose value failed per-type validation per §4.3.
	ValueErrors []ValueError
	// UnknownERA lists ERA-range TLV types that are not recognised by the
	// matrix (neither M, O, F for this protocol AND not a defined ERA TLV).
	// Per spec §4.4: skip with DEBUG + counter.
	UnknownERA []proxyproto.TLVType
}

// ValueError is one per-TLV value-validation failure.
type ValueError struct {
	Type proxyproto.TLVType
	Err  error
}

// Validate checks the parsed TLVs against this Spec.
func (s *Spec) Validate(parsed []proxyproto.TLV) ValidateResult {
	res := ValidateResult{OK: true}

	// Build a set of types present in parsed.
	present := make(map[proxyproto.TLVType]proxyproto.TLV, len(parsed))
	for _, t := range parsed {
		present[t.Type] = t
	}

	// Universal mandatories.
	for _, t := range universalMandatory {
		if _, ok := present[t]; !ok {
			res.OK = false
			res.MissingMandatory = append(res.MissingMandatory, t)
		}
	}
	// Per-protocol mandatories.
	for _, t := range s.Mandatory {
		if _, ok := present[t]; !ok {
			res.OK = false
			res.MissingMandatory = append(res.MissingMandatory, t)
		}
	}
	// Per-protocol forbidden.
	for _, t := range s.Forbidden {
		if _, ok := present[t]; ok {
			res.OK = false
			res.PresentForbidden = append(res.PresentForbidden, t)
		}
	}
	// Per-TLV value validation. We run this on every parsed TLV so a
	// malformed value gets caught even if it's an optional TLV.
	for _, t := range parsed {
		if err := proxyproto.ValidateTLV(t); err != nil {
			res.OK = false
			res.ValueErrors = append(res.ValueErrors, ValueError{Type: t.Type, Err: err})
		}
	}
	// Spec version sanity: the byte MUST equal SpecVersionStage1 (0x01).
	if v, ok := present[proxyproto.EraTLVSpecVersion]; ok {
		if len(v.Value) != 1 || v.Value[0] != proxyproto.SpecVersionStage1 {
			res.OK = false
			res.ValueErrors = append(res.ValueErrors, ValueError{
				Type: proxyproto.EraTLVSpecVersion,
				Err:  fmt.Errorf("spec_version=%v (want 0x%02x)", v.Value, proxyproto.SpecVersionStage1),
			})
		}
	}
	// Classify unknown ERA-range TLVs (not in M/O/F and not a defined ERA TLV
	// type the spec recognises). Per §4.4 these are skip+log — they do NOT
	// flip OK to false; the caller logs them and continues.
	allowed := make(map[proxyproto.TLVType]struct{}, len(universalMandatory)+len(universalOptional)+len(s.Mandatory)+len(s.Optional)+len(s.Forbidden))
	for _, t := range universalMandatory {
		allowed[t] = struct{}{}
	}
	for _, t := range universalOptional {
		allowed[t] = struct{}{}
	}
	allowed[proxyproto.EraTLVRouteTag] = struct{}{} // universally allowed per ADR-F3
	for _, t := range s.Mandatory {
		allowed[t] = struct{}{}
	}
	for _, t := range s.Optional {
		allowed[t] = struct{}{}
	}
	for _, t := range s.Forbidden {
		// Forbidden types are accounted for in the M/F path; including in
		// allowed keeps them out of the unknown-ERA path.
		allowed[t] = struct{}{}
	}
	for _, t := range parsed {
		if _, ok := allowed[t.Type]; ok {
			continue
		}
		if t.Type.IsERACustom() {
			res.UnknownERA = append(res.UnknownERA, t.Type)
			continue
		}
		// Standard PROXY-v2 TLV that we don't explicitly use. Skip silently
		// (no counter, no log) per §4.4. Not adding to UnknownERA — the
		// listener won't log this case.
	}
	return res
}
