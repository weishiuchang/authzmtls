package dockerapi

// AuthZReq is the JSON body dockerd POSTs to /AuthZPlugin.AuthZReq and (with
// the AuthZRes-only fields below also populated) /AuthZPlugin.AuthZRes.
// Field names and JSON casing match Docker's wire protocol exactly:
// https://docs.docker.com/engine/extend/plugins_authorization/#authzreq
type AuthZReq struct {
	// User is populated by dockerd from the client's TLS certificate
	// Subject CN; this is the raw value $IDENTITY expands from.
	User string `json:"User"`

	// UserAuthNMethod is the authentication method used (e.g. "TLS").
	UserAuthNMethod string `json:"UserAuthNMethod"`

	// RequestMethod is the HTTP method of the original request (e.g. "POST").
	RequestMethod string `json:"RequestMethod"`

	// RequestURI is the URI of the original request, including query string.
	RequestURI string `json:"RequestURI"`

	// RequestBody is present on the request-authorization call, absent on
	// the response-authorization call.
	RequestBody []byte `json:"RequestBody,omitempty"`

	// RequestHeaders holds the original request's HTTP headers.
	RequestHeaders map[string]string `json:"RequestHeaders,omitempty"`

	// ResponseStatusCode is only populated on the /AuthZPlugin.AuthZRes call.
	ResponseStatusCode int `json:"ResponseStatusCode,omitempty"`

	// ResponseBody is only populated on the /AuthZPlugin.AuthZRes call.
	ResponseBody []byte `json:"ResponseBody,omitempty"`

	// ResponseHeaders is only populated on the /AuthZPlugin.AuthZRes call.
	ResponseHeaders map[string]string `json:"ResponseHeaders,omitempty"`
}

// AuthZRes is the JSON body returned from both /AuthZPlugin.AuthZReq and
// /AuthZPlugin.AuthZRes. Field names and JSON casing match Docker's wire
// protocol exactly:
// https://docs.docker.com/engine/extend/plugins_authorization/#authzres
type AuthZRes struct {
	Allow bool `json:"Allow"`

	// Msg is returned to the user on a deny; should not disclose sensitive
	// information.
	Msg string `json:"Msg,omitempty"`

	// Err, if non-empty, is returned to the user and treated as a deny by
	// dockerd.
	Err string `json:"Err,omitempty"`
}

// PluginActivateRes is the /Plugin.Activate handshake response body:
// always exactly {"Implements": ["authz"]} for this project - dockerd's
// authorization subsystem checks for the driver name "authz" specifically,
// not "authorization".
type PluginActivateRes struct {
	Implements []string `json:"Implements"`
}
