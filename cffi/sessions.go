package main

import (
	"fmt"
	"io"
	"sync"

	client "github.com/smallerqiu/ja3-client"
	patchedhttp "github.com/smallerqiu/ja3-client/http"
	ja3 "github.com/smallerqiu/ja3-client/ja3"
)

// session is one long-lived HttpClient plus the header base it was created with.
//
// The header base is recorded because the underlying client only applies its
// default headers - including the impersonated user-agent - when a request carries
// no headers at all (client.Do: `if len(req.Header) == 0 { use defaults }`).
// Without this, every per-request header object would silently drop the
// user-agent, so ja3_session_request merges request headers over a clone of it.
type session struct {
	id      uint64
	handle  client.HttpClient
	headers patchedhttp.Header
}

var (
	sessionsMu sync.Mutex
	sessions   = map[uint64]*session{}
	nextID     uint64
)

// resolveUserAgent repeats the user-agent selection CreateSession does, using only
// exported builders, so the FFI can record the header base. The returned profile is
// thrown away; CreateSession still builds the real client.
func resolveUserAgent(r *ffiRequest) string {
	var profile ja3.ClientProfile
	var err error

	switch {
	case r.Ja3 != "":
		profile, err = ja3.BuildClientHelloSpecFromJa3Key(r.Ja3, r.Akamai, r.WithHTTP3)
	case r.ClientData != nil:
		profile, err = ja3.BuildClientHelloSpecWithCP(r.ClientData.Data)
	default:
		impersonate := r.Impersonate
		if impersonate == "" {
			impersonate = ja3.DefaultImpersonate
		}

		profile, err = ja3.BuildClientHelloSpec(impersonate, r.WithHTTP3)
	}

	if err != nil {
		return ""
	}

	return profile.GetUserAgent()
}

// baseHeaders builds the header map to hand to CreateSession, so user-agent and
// accept-encoding are resolved exactly once and shared by every later request.
//
// accept-encoding is pinned to identity unless the caller chose it: the transport
// does not transparently decompress, so a gzipped body would cross the ABI as
// base64 the caller cannot read.
func baseHeaders(r *ffiRequest) patchedhttp.Header {
	ops, warnings := parseHeaderOps(r.Headers)
	r.addWarnings(warnings...)

	base := patchedhttp.Header{}

	if ua := resolveUserAgent(r); ua != "" {
		base.Set("user-agent", ua)
	}

	base = applyHeaderOps(base, ops)

	if base.Get("accept-encoding") == "" {
		base.Set("accept-encoding", "identity")
	}

	return base
}

// buildSession creates the client for r. The caller owns the returned session and
// must close it when it is not registered in the handle table.
func buildSession(r *ffiRequest) (*session, error) {
	req, err := r.toJa3Request()
	if err != nil {
		return nil, err
	}

	base := baseHeaders(r)
	req.Headers = base

	handle, err := client.CreateSession(req)
	if err != nil {
		return nil, err
	}

	return &session{handle: handle, headers: base}, nil
}

// registerSession assigns a handle id and keeps the session alive for the caller.
func registerSession(s *session) uint64 {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()

	nextID++
	s.id = nextID
	sessions[nextID] = s

	return nextID
}

// lookupSession returns a registered session, or nil for an unknown/zero id.
func lookupSession(id uint64) *session {
	if id == 0 {
		return nil
	}

	sessionsMu.Lock()
	defer sessionsMu.Unlock()

	return sessions[id]
}

// closeSession removes and drains a handle, reporting whether it existed.
func closeSession(id uint64) bool {
	sessionsMu.Lock()
	s := sessions[id]
	delete(sessions, id)
	sessionsMu.Unlock()

	if s == nil {
		return false
	}

	s.handle.CloseIdleConnections()

	return true
}

// mergeHeaders layers the per-request headers onto a clone of the session's header
// base. null / [] removes a base header, which is how a caller drops the
// impersonated user-agent or the default accept-encoding.
func (s *session) mergeHeaders(request map[string]any) (patchedhttp.Header, []string) {
	ops, warnings := parseHeaderOps(request)

	for _, op := range ops {
		if op.remove && s.headers.Get(op.name) != "" {
			warnings = append(warnings, fmt.Sprintf("header %q: session default removed", op.name))
		}
	}

	return applyHeaderOps(s.headers, ops), warnings
}

// doOneShot mirrors client.DoRequest: build a client, use it once, drop it. It goes
// through the same session code path so both spellings behave identically.
func doOneShot(r *ffiRequest) (*ffiResponse, error) {
	s, err := buildSession(r)
	if err != nil {
		return nil, err
	}
	defer s.handle.CloseIdleConnections()

	return s.perform(r)
}

// perform executes one request and returns the response body, closing the body when
// it can.
func (s *session) perform(r *ffiRequest) (*ffiResponse, error) {
	env := okEnvelope()

	headers, warnings := s.mergeHeaders(r.Headers)
	env.addWarnings(warnings...)

	req, err := buildOutRequest(r, headers)
	if err != nil {
		return nil, err
	}

	resp, err := s.handle.Do(req)
	if err != nil {
		return nil, &callError{code: ErrRequest, msg: err.Error()}
	}
	if resp == nil || resp.Body == nil {
		return nil, &callError{code: ErrReadBody, msg: "transport returned no response body"}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &callError{code: ErrReadBody, msg: err.Error()}
	}

	fillResponse(env, resp, body)

	return env, nil
}
