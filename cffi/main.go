package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// Version and BuildTime are injected by the release build:
// -ldflags "-X main.Version=1.2.4 -X main.BuildTime=2026-10-15T02:00:00Z".
var (
	Version   = "dev"
	BuildTime = "unknown"
)

// ABIVersion bumps whenever the JSON contract below changes shape. Bindings check
// it once at load time so an old .so next to a new binding fails loudly instead of
// returning empty bodies.
const ABIVersion = 2

const (
	ErrPanic = 8
)

// cString copies a Go string into memory the caller must free with ja3_free.
// Every exported function returns exactly that, including the error paths: the ABI
// has no separate error channel.
func cString(s string) *C.char { return C.CString(s) }

func cJSON(env *ffiResponse) *C.char { return cString(env.encode()) }

// safeCall runs an export body and converts a panic into an envelope. A Go panic
// that reaches C aborts the whole host process, which for a library loaded by Node,
// Python or .NET is the worst possible failure mode.
func safeCall(fn func() *ffiResponse) (env *ffiResponse) {
	defer func() {
		if recovered := recover(); recovered != nil {
			env = errEnvelope(ErrPanic, panicText(recovered))
		}
	}()

	return fn()
}

func panicText(recovered any) string {
	if err, ok := recovered.(error); ok {
		return err.Error()
	}

	return fmt.Sprint(recovered)
}

//export ja3_version
func ja3_version() *C.char {
	env := okEnvelope()
	env.Version = Version
	env.Abi = ABIVersion
	env.BuildTime = BuildTime

	return cJSON(env)
}

// ja3_request performs a one-shot request: a client is built from the payload, used
// once, and its idle connections are dropped. Use ja3_session_new when you want
// connection and cookie reuse across calls.
//
//export ja3_request
func ja3_request(payload *C.char) *C.char {
	raw := C.GoString(payload)

	return cJSON(safeCall(func() *ffiResponse {
		req, bad := parseRequest(raw)
		if bad != nil {
			return bad
		}

		if req.URL == "" {
			return withWarnings(errEnvelope(ErrNilArgument, "url is required"), req)
		}

		env, err := doOneShot(req)
		if err != nil {
			return withWarnings(envelopeFor(err), req)
		}

		return withWarnings(env, req)
	}))
}

// ja3_session_new builds a persistent client and returns its handle in
// {"session": <id>}. The handle stays valid until ja3_session_close, and every
// request through it reuses the connection pool and the cookie jar.
//
//export ja3_session_new
func ja3_session_new(payload *C.char) *C.char {
	raw := C.GoString(payload)

	return cJSON(safeCall(func() *ffiResponse {
		req, bad := parseRequest(raw)
		if bad != nil {
			return bad
		}

		s, err := buildSession(req)
		if err != nil {
			return withWarnings(errEnvelope(ErrSessionInit, err.Error()), req)
		}

		env := okEnvelope()
		env.Session = registerSession(s)

		return withWarnings(env, req)
	}))
}

// ja3_session_request runs one request on an existing handle.
//
//export ja3_session_request
func ja3_session_request(id C.ulonglong, payload *C.char) *C.char {
	raw := C.GoString(payload)

	return cJSON(safeCall(func() *ffiResponse {
		s := lookupSession(uint64(id))
		if s == nil {
			return errEnvelope(ErrInvalidHandle, "unknown session handle; call ja3_session_new first or close it with ja3_session_close")
		}

		req, bad := parseRequest(raw)
		if bad != nil {
			return bad
		}

		if req.URL == "" {
			return withWarnings(errEnvelope(ErrNilArgument, "url is required"), req)
		}

		env, err := s.perform(req)
		if err != nil {
			return withWarnings(envelopeFor(err), req)
		}

		env.Session = s.id

		return withWarnings(env, req)
	}))
}

// ja3_session_close drops a handle and its idle connections. Closing twice reports
// ErrInvalidHandle, which is not fatal.
//
//export ja3_session_close
func ja3_session_close(id C.ulonglong) *C.char {
	return cJSON(safeCall(func() *ffiResponse {
		if !closeSession(uint64(id)) {
			return errEnvelope(ErrInvalidHandle, "session handle is not open")
		}

		return okEnvelope()
	}))
}

// ja3_free releases a string returned by any other export. Not calling it leaks one
// allocation per response; calling it on anything else is undefined behaviour.
//
//export ja3_free
func ja3_free(ptr *C.char) {
	if ptr != nil {
		C.free(unsafe.Pointer(ptr))
	}
}

// request and Free are the v1 spellings kept for existing Python/Node code. They
// forward to the new ABI, so their payloads are the new snake_case envelope rather
// than ja3.Response - see cffi/README.md.
//
//export request
func request(payload *C.char) *C.char { return ja3_request(payload) }

//export Free
func Free(ptr *C.char) { ja3_free(ptr) }

func main() {}
