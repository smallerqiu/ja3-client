package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"unicode/utf8"

	patchedhttp "github.com/smallerqiu/ja3-client/http"
	ja3 "github.com/smallerqiu/ja3-client/ja3"
)

// Error codes carried in every response envelope, so bindings can raise a typed
// error instead of guessing from an empty body.
const (
	ErrOK            = 0
	ErrNilArgument   = 1
	ErrBadJSON       = 2
	ErrSessionInit   = 3
	ErrInvalidHandle = 4
	ErrRequest       = 5
	ErrReadBody      = 6
	ErrMarshal       = 7
)

// ffiRequest is the FFI-facing request/config contract.
//
// It deliberately does not reuse ja3.Ja3Request: that struct has no json tags, so
// "with_http3", "force_http1", "source_ip", "client_data" and
// "not_follow_redirects" would be silently ignored (encoding/json only matches
// case-insensitively, never across underscores), and its Body is []byte, which
// encoding/json decodes from base64 only - wrong for the text payloads callers
// write in Python, Node or C#.
//
// One struct serves both ja3_session_new (client-level options) and
// ja3_request / ja3_session_request (per-call options). Fields that do not apply
// to one of the two are simply unused there.
type ffiRequest struct {
	Method      string `json:"method"`
	URL         string `json:"url"`
	Body        string `json:"body"`
	BodyBase64  string `json:"body_base64"`
	Proxy       string `json:"proxy"`
	SourceIP    string `json:"source_ip"`
	Impersonate string `json:"impersonate"`
	Ja3         string `json:"ja3"`
	Akamai      string `json:"akamai"`

	// Headers accepts {"name": "value"} or {"name": ["v1", "v2"]}.
	Headers map[string]any `json:"headers"`

	Timeout              int  `json:"timeout"`
	ForceHTTP1           bool `json:"force_http1"`
	RandomExtensionOrder bool `json:"random_extension_order"`
	NotFollowRedirects   bool `json:"not_follow_redirects"`
	WithDebug            bool `json:"with_debug"`

	// WithHTTP3 is a pointer so "absent" (keep the profile default) stays
	// distinguishable from an explicit false.
	WithHTTP3 *bool `json:"with_http3"`

	ClientData *ffiClientData `json:"client_data"`

	warnings []string
}

// ffiClientData wraps ja3.ClientData so its keys go through the same
// snake_case/Go-name normalization as the top level.
type ffiClientData struct {
	Data    ja3.ClientData
	Unknown []string
}

func (c *ffiClientData) UnmarshalJSON(raw []byte) error {
	unknown, err := normalizeInto(raw, &c.Data)
	c.Unknown = unknown

	return err
}

// ffiResponse is the single return shape of every exported function.
type ffiResponse struct {
	ErrorCode  int                 `json:"error_code"`
	Error      string              `json:"error,omitempty"`
	Warnings   []string            `json:"warnings,omitempty"`
	StatusCode int                 `json:"status_code,omitempty"`
	Protocol   string              `json:"protocol,omitempty"`
	Headers    map[string][]string `json:"headers,omitempty"`
	SetCookies []string            `json:"set_cookies,omitempty"`
	Body       string              `json:"body,omitempty"`
	BodyBase64 string              `json:"body_base64,omitempty"`
	BodyBinary bool                `json:"body_binary,omitempty"`
	BodySize   int                 `json:"body_size"`
	Session    uint64              `json:"session,omitempty"`
	Version    string              `json:"version,omitempty"`
	Abi        int                 `json:"abi,omitempty"`
	BuildTime  string              `json:"build_time,omitempty"`
	OK         bool                `json:"ok"`
}

func okEnvelope() *ffiResponse { return &ffiResponse{ErrorCode: ErrOK, OK: true} }

func errEnvelope(code int, msg string) *ffiResponse {
	return &ffiResponse{ErrorCode: code, Error: msg, OK: false}
}

// addWarnings queues notes on the request; parseRequest attaches them to the
// envelope that carries the result.
func (r *ffiRequest) addWarnings(warnings ...string) {
	r.warnings = append(r.warnings, warnings...)
}

// addWarnings records notes without duplicating ones already present. They land in
// the exported field immediately, so a caller inspecting the envelope in Go sees the
// same list the JSON does.
func (r *ffiResponse) addWarnings(warnings ...string) {
	seen := make(map[string]bool, len(r.Warnings)+len(warnings))

	for _, w := range r.Warnings {
		seen[w] = true
	}

	for _, w := range warnings {
		if w == "" || seen[w] {
			continue
		}

		seen[w] = true
		r.Warnings = append(r.Warnings, w)
	}
}

// encode turns the envelope into the JSON text the caller receives.
func (r *ffiResponse) encode() string {
	if len(r.Warnings) > 0 {
		sort.Strings(r.Warnings)
	}

	out, err := json.Marshal(r)
	if err != nil {
		return `{"error_code":7,"error":"response marshal failed","ok":false}`
	}

	return string(out)
}

// canonical collapses a name so with_http3, WithHTTP3 and "With-Http3" all resolve
// to the same field. Case-insensitive matching alone is not enough once a Go name
// has consecutive capitals (HTTP3, IP) or underscores.
func canonical(name string) string {
	var b strings.Builder

	for _, r := range strings.ToLower(name) {
		if r == '_' || r == '-' || r == ' ' {
			continue
		}

		b.WriteRune(r)
	}

	return b.String()
}

// canonicalIndex maps every accepted spelling of a struct's fields back to the
// json tag the decoder expects.
func canonicalIndex(target any) map[string]string {
	index := map[string]string{}

	t := reflect.TypeOf(target)
	if t == nil {
		return index
	}

	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}

	if t.Kind() != reflect.Struct {
		return index
	}

	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)

		if f.PkgPath != "" { // unexported fields are not settable from JSON
			continue
		}

		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}

		name := strings.Split(tag, ",")[0]
		if name == "" || name == "," {
			name = f.Name
		}

		index[canonical(name)] = name
		index[canonical(f.Name)] = name
	}

	return index
}

// normalizeInto decodes a JSON object into target after rewriting the caller's key
// spellings onto the struct's tags. Unknown keys are returned instead of dropped -
// a typo'd option behind a C ABI is otherwise invisible forever.
func normalizeInto(raw []byte, target any) ([]string, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}

	if fields == nil {
		return nil, nil // "null" decodes to the zero value
	}

	index := canonicalIndex(target)
	rewritten := make(map[string]json.RawMessage, len(fields))
	unknown := []string{}

	for key, value := range fields {
		name, ok := index[canonical(key)]
		if !ok {
			unknown = append(unknown, key)
			continue
		}

		rewritten[name] = value
	}

	buf, err := json.Marshal(rewritten)
	if err != nil {
		return unknown, err
	}

	return unknown, json.Unmarshal(buf, target)
}

// headerOp is one header instruction from the caller: set a name to a list of
// values, or remove the name entirely.
type headerOp struct {
	name   string
	values []string
	remove bool
}

// parseHeaderOps accepts "value", ["v1","v2"], [] and null per key.
//
// A null or an empty list means "remove this header", which is how a caller drops
// the impersonated user-agent or the identity accept-encoding the FFI installs by
// default. Names are canonicalised through http.Header so an override always hits
// the same map key the base uses.
func parseHeaderOps(in map[string]any) ([]headerOp, []string) {
	if in == nil {
		return nil, nil
	}

	names := make([]string, 0, len(in))
	for name := range in {
		names = append(names, name)
	}

	sort.Strings(names)

	ops := make([]headerOp, 0, len(in))
	warnings := []string{}

	for _, name := range names {
		if strings.TrimSpace(name) == "" {
			warnings = append(warnings, "header with empty name ignored")
			continue
		}

		switch v := in[name].(type) {
		case nil:
			ops = append(ops, headerOp{name: name, remove: true})
		case string:
			ops = append(ops, headerOp{name: name, values: []string{v}})
		case []any:
			if len(v) == 0 {
				ops = append(ops, headerOp{name: name, remove: true})
				continue
			}

			values := make([]string, 0, len(v))

			for _, item := range v {
				s, ok := item.(string)
				if !ok {
					warnings = append(warnings, fmt.Sprintf("header %q: non-string list entry %v ignored", name, item))
					continue
				}

				values = append(values, s)
			}

			if len(values) == 0 {
				warnings = append(warnings, fmt.Sprintf("header %q: no usable list values, header removed", name))
				ops = append(ops, headerOp{name: name, remove: true})
				continue
			}

			ops = append(ops, headerOp{name: name, values: values})
		default:
			// Numbers and booleans are common in JSON produced by other languages.
			ops = append(ops, headerOp{name: name, values: []string{fmt.Sprint(v)}})
		}
	}

	return ops, warnings
}

// applyHeaderOps layers ops onto base. base is copied, never mutated.
func applyHeaderOps(base patchedhttp.Header, ops []headerOp) patchedhttp.Header {
	out := base.Clone()
	if out == nil {
		out = patchedhttp.Header{}
	}

	for _, op := range ops {
		out.Del(op.name)

		if op.remove {
			continue
		}

		for _, value := range op.values {
			out.Add(op.name, value)
		}
	}

	return out
}

func (r *ffiRequest) bodyBytes() ([]byte, error) {
	if r.BodyBase64 != "" {
		body, err := base64.StdEncoding.DecodeString(r.BodyBase64)
		if err != nil {
			return nil, fmt.Errorf("body_base64 is not valid base64: %w", err)
		}

		return body, nil
	}

	if r.Body != "" {
		return []byte(r.Body), nil
	}

	return nil, nil
}

// parseRequest validates a JSON blob coming over the ABI.
func parseRequest(raw string) (*ffiRequest, *ffiResponse) {
	req := &ffiRequest{}

	unknown, err := normalizeInto([]byte(raw), req)
	if err != nil {
		return nil, errEnvelope(ErrBadJSON, err.Error())
	}

	for _, key := range unknown {
		req.warnings = append(req.warnings, fmt.Sprintf("unknown option %q ignored", key))
	}

	if req.ClientData != nil {
		for _, key := range req.ClientData.Unknown {
			req.warnings = append(req.warnings, fmt.Sprintf("unknown client_data option %q ignored", key))
		}
	}

	sort.Strings(req.warnings)

	return req, nil
}

// toJa3Request maps the FFI contract onto the library's request struct, the shape
// client.CreateSession consumes.
func (r *ffiRequest) toJa3Request() (*ja3.Ja3Request, error) {
	body, err := r.bodyBytes()
	if err != nil {
		return nil, err
	}

	headers, headerWarnings := parseHeaderOps(r.Headers)
	r.addWarnings(headerWarnings...)

	var clientData *ja3.ClientData
	if r.ClientData != nil {
		clientData = &r.ClientData.Data
	}

	return &ja3.Ja3Request{
		Method:               r.method(),
		URL:                  r.URL,
		Headers:              applyHeaderOps(nil, headers),
		Body:                 body,
		Proxy:                r.Proxy,
		SourceIP:             r.SourceIP,
		Impersonate:          r.Impersonate,
		Ja3:                  r.Ja3,
		Akamai:               r.Akamai,
		ForceHTTP1:           r.ForceHTTP1,
		WithHTTP3:            r.WithHTTP3,
		RandomExtensionOrder: r.RandomExtensionOrder,
		Timeout:              r.Timeout,
		NotFollowRedirects:   r.NotFollowRedirects,
		WithDebug:            r.WithDebug,
		ClientData:           clientData,
	}, nil
}

func (r *ffiRequest) method() string {
	if r.Method == "" {
		return http.MethodGet
	}

	return r.Method
}

// buildOutRequest builds the wire request for an already-resolved header map.
//
// It uses the library's patched net/http, not the standard one: client.HttpClient.Do
// only accepts that Request type, and the patched package is what carries the
// header-ordering support.
func buildOutRequest(r *ffiRequest, headers map[string][]string) (*patchedhttp.Request, error) {
	body, err := r.bodyBytes()
	if err != nil {
		return nil, &callError{code: ErrBadJSON, msg: err.Error()}
	}

	req, err := patchedhttp.NewRequest(r.method(), r.URL, bytes.NewReader(body))
	if err != nil {
		return nil, &callError{code: ErrRequest, msg: err.Error()}
	}

	if len(headers) > 0 {
		req.Header = patchedhttp.Header(headers)
	}

	return req, nil
}

// addWarnings on an envelope from a parsed request, so parse-time notes survive even
// when the request never got as far as building a client.
func withWarnings(env *ffiResponse, req *ffiRequest) *ffiResponse {
	if env == nil || req == nil {
		return env
	}

	env.addWarnings(req.warnings...)

	return env
}

// callError carries an error code across the ABI alongside the message.
type callError struct {
	code int
	msg  string
}

func (e *callError) Error() string { return e.msg }

// envelopeFor turns a Go error into the response envelope the caller sees.
func envelopeFor(err error) *ffiResponse {
	var ce *callError
	if errors.As(err, &ce) {
		return errEnvelope(ce.code, ce.msg)
	}

	return errEnvelope(ErrRequest, err.Error())
}

// fillResponse copies an HTTP response into the envelope. The body comes back as a
// UTF-8 string when it survives that and as base64 when it does not: a C string
// cannot carry NUL bytes, and callers must not silently lose bytes.
func fillResponse(env *ffiResponse, resp *patchedhttp.Response, body []byte) {
	env.StatusCode = resp.StatusCode
	env.Protocol = resp.Proto
	env.Headers = resp.Header
	env.BodySize = len(body)

	if body == nil {
		body = []byte{}
	}

	if utf8.Valid(body) {
		env.Body = string(body)
	} else {
		env.BodyBase64 = base64.StdEncoding.EncodeToString(body)
		env.BodyBinary = true
	}

	if cookies := resp.Header.Values("Set-Cookie"); len(cookies) > 0 {
		env.SetCookies = cookies
	}
}
