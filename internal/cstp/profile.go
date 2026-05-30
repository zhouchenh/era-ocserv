package cstp

import (
	"strings"
)

// anyConnectProfileXML is a minimal-but-valid AnyConnectProfile (modeled on
// ocserv's doc/profile.xml), served by handleProfile on GET /profiles/*. The
// type="complete" envelope deliberately advertises NO <vpn-profile-manifest>
// (see buildAuthComplete / profile.go), so the iOS Cisco Secure Client does not
// fetch it on the proven flow; serving a valid profile here is defensive, since
// the facade routes /profiles/* to era-ocserv and some clients may probe it.
const anyConnectProfileXML = `<?xml version="1.0" encoding="UTF-8"?>
<AnyConnectProfile xmlns="http://schemas.xmlsoap.org/encoding/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://schemas.xmlsoap.org/encoding/ AnyConnectProfile.xsd">
  <ClientInitialization>
    <UseStartBeforeLogon UserControllable="false">false</UseStartBeforeLogon>
    <AutomaticCertSelection UserControllable="false">false</AutomaticCertSelection>
    <ShowPreConnectMessage>false</ShowPreConnectMessage>
    <CertificateStore>All</CertificateStore>
    <CertificateStoreOverride>false</CertificateStoreOverride>
    <ProxySettings>Native</ProxySettings>
    <AutoConnectOnStart UserControllable="false">false</AutoConnectOnStart>
    <MinimizeOnConnect UserControllable="true">true</MinimizeOnConnect>
    <LocalLanAccess UserControllable="true">false</LocalLanAccess>
    <AutoReconnect UserControllable="false">true<AutoReconnectBehavior UserControllable="false">ReconnectAfterResume</AutoReconnectBehavior></AutoReconnect>
    <AutoUpdate UserControllable="false">false</AutoUpdate>
    <RSASecurIDIntegration UserControllable="false">Automatic</RSASecurIDIntegration>
    <WindowsLogonEnforcement>SingleLocalLogon</WindowsLogonEnforcement>
    <CertEnrollmentPin>pinAllowed</CertEnrollmentPin>
    <CertificateMatch>
      <KeyUsage>
        <MatchKey>Digital_Signature</MatchKey>
      </KeyUsage>
    </CertificateMatch>
  </ClientInitialization>
  <ServerList>
    <HostEntry>
      <HostName>ERA</HostName>
      <HostAddress>eracloud.app</HostAddress>
    </HostEntry>
  </ServerList>
</AnyConnectProfile>`

// serverCertSHA1 is the uppercase-hex SHA-1 of the eracloud.app public TLS leaf
// certificate (the facade terminates TLS, so era-ocserv cannot read it). It
// populates the webvpnc directive's sh: field — AnyConnect's gateway-cert pin —
// as the built-in DEFAULT when no override is configured.
// NOTE: on the covert :443 path the facade terminates TLS with its own live
// eracloud.app leaf, which this constant may not match; the -server-cert-sha1
// flag (cstp.Config.ServerCertSHA1) overrides it per deployment. A future change
// should instead have the facade pass its leaf-cert hash to era-ocserv via a
// handoff TLV (the ERA TLV range 0xE0-0xEF is fully allocated, so that is a
// separate documented follow-up).
const serverCertSHA1 = "525FB9D7A730F41527C4F85394454E716B389997"

// buildWebVPNC builds the value of the `webvpnc` directive cookie stock ocserv
// sets on the type="complete" response (worker-auth.c). Cisco Secure Client
// reads it AFTER auth to learn what to do before the tunnel CONNECT:
//
//	bu: base URL · p:t protocol=tunnel · iu: install URL · sh: gateway cert hash
//
// certSHA1 is the uppercase-hex SHA-1 of the public TLS leaf cert (the sh: pin).
// This is EXACTLY stock ocserv's directive when no client profile is configured
// — and a side-by-side capture against the iOS Cisco Secure Client proved that
// shape connects instantly. The optional `lu:` (translation-table URL) and
// `fu:`/`fh:` (profile URL + hash) fields are deliberately OMITTED: adding them
// (as an earlier revision did) sends the iOS Network Extension into a pre-tunnel
// fetch phase — GET the URL-encoded `lu:` query-string and the `fu:` profile —
// that it never completes, so it goes silent after the complete and never sends
// the CONNECT. Stock ships none of them and works; we match stock. The value is
// sent verbatim (its &/:/% are literal — do NOT use http.SetCookie, which would
// percent-escape them).
func buildWebVPNC(certSHA1 string) string {
	return "bu:/&p:t&iu:1/&sh:" + certSHA1
}

// AnyConnect post-auth "housekeeping" response bodies the client GETs between
// auth and the tunnel CONNECT (the webvpnc lu:/iu: targets + the VPN downloader
// update-check URLs), mirroring stock ocserv's canned bodies
// (worker-http-handlers.c). Serving these instead of 404 lets the iOS client's
// pre-tunnel reconciliation complete so it proceeds to the CONNECT.
const (
	anyConnectVPNManifestXML = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<vpn rev=\"1.0\">\n</vpn>\n"
	anyConnectUpdateTxt      = "0,0,0000\n"
	anyConnectVPNDownloader  = "#!/bin/sh\n\nexit 0"
	anyConnectEmptyHTML      = "<html></html>\n"
)

// isAnyConnectHousekeepingPath reports whether p is one of the AnyConnect
// post-auth control/downloader URLs era-ocserv must serve (rather than 404) so
// the Cisco Secure Client reconciliation phase completes.
func isAnyConnectHousekeepingPath(p string) bool {
	return strings.HasPrefix(p, "/+CSCOT+/") ||
		strings.HasPrefix(p, "/1/") ||
		p == "/VPNManifest.xml" ||
		p == "/logout"
}
