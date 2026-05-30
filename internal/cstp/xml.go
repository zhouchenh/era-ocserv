package cstp

import (
	"encoding/xml"
	"errors"
	"io"
)

// XML wire shapes for the CSTP phase 2 auth exchange.
//
// All four messages share the <config-auth> root with different "type"
// attributes. We define a single AuthEnvelope type and discriminate by
// Type. The marshalled output matches what shipping AnyConnect /
// OpenConnect clients accept; the parsed input is permissive about
// optional elements per the spec.

// AnyConnect / OpenConnect family of "type" values on <config-auth>.
const (
	authTypeInit        = "init"
	authTypeAuthRequest = "auth-request"
	authTypeAuthReply   = "auth-reply"
	authTypeComplete    = "complete"
)

// authEnvelope is the wire-shape of <config-auth>. It is used for both
// inbound (init / auth-reply) and outbound (auth-request / complete)
// messages. Unused fields for a given direction are emitted as
// omitempty.
type authEnvelope struct {
	XMLName xml.Name `xml:"config-auth"`
	Client  string   `xml:"client,attr"`
	Type    string   `xml:"type,attr"`
	AggVer  string   `xml:"aggregate-auth-version,attr,omitempty"`

	Version  *authVersion  `xml:"version,omitempty"`
	DeviceID *authDeviceID `xml:"device-id,omitempty"`
	Opaque   *authOpaque   `xml:"opaque,omitempty"`
	Auth     *authBlock    `xml:"auth,omitempty"`

	// Phase 2c-only fields. SessionToken / SessionID are both used so
	// clients that consult either survive.
	SessionToken string `xml:"session-token,omitempty"`
	SessionID    string `xml:"session-id,omitempty"`
}

type authVersion struct {
	Who   string `xml:"who,attr,omitempty"`
	Value string `xml:",chardata"`
}

type authDeviceID struct {
	DeviceType      string `xml:"device-type,attr,omitempty"`
	PlatformVersion string `xml:"platform-version,attr,omitempty"`
	UniqueID        string `xml:"unique-id,attr,omitempty"`
	Value           string `xml:",chardata"`
}

type authOpaque struct {
	IsFor     string `xml:"is-for,attr,omitempty"`
	SessionID string `xml:"session-id"`
}

type authBlock struct {
	ID       string    `xml:"id,attr,omitempty"`
	Title    string    `xml:"title,omitempty"`
	Message  string    `xml:"message,omitempty"`
	Form     *authForm `xml:"form,omitempty"`
	Username string    `xml:"username,omitempty"`
	Password string    `xml:"password,omitempty"`
}

type authForm struct {
	Action string         `xml:"action,attr"`
	Method string         `xml:"method,attr"`
	Inputs []authFormItem `xml:"input"`
}

type authFormItem struct {
	Label string `xml:"label,attr,omitempty"`
	Name  string `xml:"name,attr"`
	Type  string `xml:"type,attr,omitempty"`
}

// parsedAuth is the digested shape callers actually care about. The
// raw XML structs above carry boilerplate; this is what server.go
// pattern-matches against.
type parsedAuth struct {
	Type       string
	OpaqueID   string
	Username   string
	Password   string
	DeviceUUID string
}

// errInvalidXML is returned for input the XML decoder rejects or that
// is missing the <config-auth> root.
var errInvalidXML = errors.New("cstp: invalid auth envelope xml")

// parseAuthRequest reads and validates a <config-auth> envelope from
// an HTTP request body. The reader is consumed in full so callers do
// not need to drain it.
func parseAuthRequest(r io.Reader) (parsedAuth, error) {
	var env authEnvelope
	dec := xml.NewDecoder(r)
	if err := dec.Decode(&env); err != nil {
		return parsedAuth{}, errInvalidXML
	}
	if env.XMLName.Local != "config-auth" {
		return parsedAuth{}, errInvalidXML
	}
	pa := parsedAuth{Type: env.Type}
	if env.Opaque != nil {
		pa.OpaqueID = env.Opaque.SessionID
	}
	if env.Auth != nil {
		pa.Username = env.Auth.Username
		pa.Password = env.Auth.Password
	}
	if env.DeviceID != nil {
		pa.DeviceUUID = env.DeviceID.UniqueID
	}
	return pa, nil
}

// buildAuthForm renders an auth-request prompting for a single field, with the
// given opaque session id round-tripped to the client.
//
// era-ocserv uses stock ocserv's 2-step SIMPLE auth path: a username-only form,
// then a password-only form, each a single <input>. This is deliberate — a
// single combined username+password form pushes the iOS Cisco Secure Client
// onto its aggregate-auth path (it then requires an X-Aggregate-Auth response
// header just to pass the form, and afterwards refuses to send the CSTP CONNECT
// even on a byte-for-byte stock-shaped complete). The single-input forms drive
// the simple path that stock ocserv uses and that connects iOS end-to-end.
func buildAuthForm(opaqueID, message string, inputs []authFormItem) ([]byte, error) {
	env := authEnvelope{
		Client: "vpn",
		Type:   authTypeAuthRequest,
		Version: &authVersion{
			Who:   "sg",
			Value: "0.1(1)",
		},
		Opaque: &authOpaque{IsFor: "sg", SessionID: opaqueID},
		Auth: &authBlock{
			ID:      "main",
			Message: message,
			Form: &authForm{
				Action: "/auth",
				Method: "post",
				Inputs: inputs,
			},
		},
	}
	return marshalAuth(&env)
}

// buildUsernameRequest renders the step-1 auth-request (username-only form).
func buildUsernameRequest(opaqueID, message string) ([]byte, error) {
	return buildAuthForm(opaqueID, message, []authFormItem{
		{Label: "Username:", Name: "username", Type: "text"},
	})
}

// buildPasswordRequest renders the step-2 auth-request (password-only form).
func buildPasswordRequest(opaqueID, message string) ([]byte, error) {
	return buildAuthForm(opaqueID, message, []authFormItem{
		{Label: "Password:", Name: "password", Type: "password"},
	})
}

// buildAuthComplete renders the phase 2c server response: the minimal
// type="complete" success envelope that stock ocserv emits and that Cisco
// Secure Client accepts before issuing the CSTP CONNECT.
//
// It is deliberately just <version> + <auth id="success"><title> — NO <config>
// and NO <vpn-profile-manifest>. A side-by-side capture against the iOS Cisco
// Secure Client showed stock ocserv (with no client profile configured) sends
// exactly this 189-byte body and connects instantly, whereas advertising a
// profile manifest sent the iOS Network Extension into a pre-tunnel profile
// fetch it never completed (it went silent after the complete and never issued
// the CONNECT). The post-auth instruction the client actually needs is the
// `webvpnc` directive cookie (see profile.go), not an XML <config>.
//
// The session credential is delivered ONLY via the Set-Cookie: webvpn header
// (set by the caller), NEVER in an XML element. Carrying it in a
// <session-token> element (an OpenConnect-only extension) plus extra
// <session-id>/<message> siblings makes Cisco Secure Client reject the
// complete and silently refuse to send the CONNECT — while OpenConnect, which
// harvests the token from <session-token> and is lenient about the rest,
// interoperated regardless.
func buildAuthComplete() ([]byte, error) {
	env := authEnvelope{
		Client:  "vpn",
		Type:    authTypeComplete,
		Version: &authVersion{Who: "sg", Value: "0.1(1)"},
		Auth: &authBlock{
			ID:    "success",
			Title: "SSL VPN Service",
		},
	}
	return marshalAuth(&env)
}

func marshalAuth(env *authEnvelope) ([]byte, error) {
	// Stock ocserv prefixes every config-auth message with the XML declaration:
	// worker-auth.c's oc_success_msg_head (the type="complete") and OC_LOGIN_START
	// (the auth-request) both begin with
	// `<?xml version="1.0" encoding="UTF-8"?>\n`, and the iOS Cisco Secure Client
	// drives that wire form to a connected tunnel — so we match it. We emit a
	// compact (un-indented) body: inter-element whitespace is insignificant XML,
	// and OpenConnect interoperates with either.
	buf, err := xml.Marshal(env)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(xml.Header)+len(buf))
	out = append(out, []byte(xml.Header)...)
	out = append(out, buf...)
	return out, nil
}
