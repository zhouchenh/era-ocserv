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
	SessionToken string      `xml:"session-token,omitempty"`
	SessionID    string      `xml:"session-id,omitempty"`
	Config       *authConfig `xml:"config,omitempty"`
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

type authConfig struct {
	Client  string             `xml:"client,attr,omitempty"`
	Type    string             `xml:"type,attr,omitempty"`
	VPNBase *authVPNBaseConfig `xml:"vpn-base-config,omitempty"`
}

type authVPNBaseConfig struct {
	ServerCertHash string `xml:"server-cert-hash,omitempty"`
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

// buildAuthRequest renders the phase 2a server response: an
// auth-request prompting for username + password with the given opaque
// session id round-tripped to the client.
func buildAuthRequest(opaqueID, prompt string) ([]byte, error) {
	env := authEnvelope{
		Client: "vpn",
		Type:   authTypeAuthRequest,
		AggVer: "2",
		Opaque: &authOpaque{IsFor: "sg", SessionID: opaqueID},
		Auth: &authBlock{
			ID:      "main",
			Message: prompt,
			Form: &authForm{
				Action: "/auth",
				Method: "post",
				Inputs: []authFormItem{
					{Label: "Username:", Name: "username", Type: "text"},
					{Label: "Password:", Name: "password", Type: "password"},
				},
			},
		},
	}
	return marshalAuth(&env)
}

// buildAuthComplete renders the phase 2c server response: an
// auth-complete carrying the session token the client will echo on the
// CONNECT request, plus an informational success message.
func buildAuthComplete(sessionToken, opaqueID, certHashBase64 string) ([]byte, error) {
	env := authEnvelope{
		Client:       "vpn",
		Type:         authTypeComplete,
		AggVer:       "2",
		SessionToken: sessionToken,
		SessionID:    opaqueID,
		Auth: &authBlock{
			ID:      "success",
			Message: "Logged in",
		},
	}
	if certHashBase64 != "" {
		env.Config = &authConfig{
			Client: "vpn",
			Type:   "private",
			VPNBase: &authVPNBaseConfig{
				ServerCertHash: certHashBase64,
			},
		}
	}
	return marshalAuth(&env)
}

// buildAuthError renders an auth-request with an error message,
// returned when phase 2b credentials fail verification. The client
// re-prompts the user.
func buildAuthError(opaqueID, message string) ([]byte, error) {
	env := authEnvelope{
		Client: "vpn",
		Type:   authTypeAuthRequest,
		AggVer: "2",
		Opaque: &authOpaque{IsFor: "sg", SessionID: opaqueID},
		Auth: &authBlock{
			ID:      "main",
			Message: message,
			Form: &authForm{
				Action: "/auth",
				Method: "post",
				Inputs: []authFormItem{
					{Label: "Username:", Name: "username", Type: "text"},
					{Label: "Password:", Name: "password", Type: "password"},
				},
			},
		},
	}
	return marshalAuth(&env)
}

func marshalAuth(env *authEnvelope) ([]byte, error) {
	buf, err := xml.MarshalIndent(env, "", "  ")
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(buf)+len(xml.Header))
	out = append(out, []byte(xml.Header)...)
	out = append(out, buf...)
	return out, nil
}
