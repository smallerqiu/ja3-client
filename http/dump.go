package http

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"net/url"
	"strings"
	"time"
)

// dumpConn is a net.Conn which writes to Writer and reads from Reader
type dumpConn struct {
	io.Writer
	io.Reader
}

func (c *dumpConn) Close() error                       { return nil }
func (c *dumpConn) LocalAddr() net.Addr                { return nil }
func (c *dumpConn) RemoteAddr() net.Addr               { return nil }
func (c *dumpConn) SetDeadline(t time.Time) error      { return nil }
func (c *dumpConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *dumpConn) SetWriteDeadline(t time.Time) error { return nil }

type neverEnding byte

func (b neverEnding) Read(p []byte) (n int, err error) {
	for i := range p {
		p[i] = byte(b)
	}
	return len(p), nil
}

// drainBody reads all of b to memory and then returns two equivalent
// ReadClosers yielding the same bytes.
//
// It returns an error if the initial slurp of all bytes fails. It does not attempt
// to make the returned ReadClosers have identical error-matching behavior.
func drainBody(b io.ReadCloser) (r1, r2 io.ReadCloser, err error) {
	if b == nil || b == NoBody {
		// No copying needed. Preserve the magic sentinel meaning of NoBody.
		return NoBody, NoBody, nil
	}
	var buf bytes.Buffer
	if _, err = buf.ReadFrom(b); err != nil {
		return nil, b, err
	}
	if err = b.Close(); err != nil {
		return nil, b, err
	}
	return io.NopCloser(&buf), io.NopCloser(bytes.NewReader(buf.Bytes())), nil
}

// outGoingLength is a copy of the unexported
// (*http.Request).outgoingLength method.
func outgoingLength(req *Request) int64 {
	if req.Body == nil || req.Body == NoBody {
		return 0
	}
	if req.ContentLength != 0 {
		return req.ContentLength
	}
	return -1
}

// errNoBody is a sentinel error value used by failureToReadBody so we
// can detect that the lack of body was intentional.
var errNoBody = errors.New("sentinel error value")

// failureToReadBody is a io.ReadCloser that just returns errNoBody on
// Read. It's swapped in when we don't actually want to consume
// the body, but need a non-nil one, and want to distinguish the
// error from reading the dummy body.
type failureToReadBody struct{}

func (failureToReadBody) Read([]byte) (int, error) { return 0, errNoBody }
func (failureToReadBody) Close() error             { return nil }

// DumpRequestOut is like DumpRequest but for outgoing client requests. It
// includes any headers that the standard http.Transport adds, such as
// User-Agent.
func DumpRequestOut(req *Request, body bool) ([]byte, error) {
	save := req.Body
	dummyBody := false
	if !body {
		contentLength := outgoingLength(req)
		if contentLength != 0 {
			req.Body = io.NopCloser(io.LimitReader(neverEnding('x'), contentLength))
			dummyBody = true
		}
	} else {
		var err error
		save, req.Body, err = drainBody(req.Body)
		if err != nil {
			return nil, err
		}
	}

	// Since we're using the actual Transport code to write the request,
	// switch to http so the Transport doesn't try to do an SSL
	// negotiation with our dumpConn and its bytes.Buffer & pipe.
	// The wire format for https and http are the same, anyway.
	reqSend := req
	if req.URL.Scheme == "https" {
		reqSend = new(Request)
		*reqSend = *req
		reqSend.URL = new(url.URL)
		*reqSend.URL = *req.URL
		reqSend.URL.Scheme = "http"
	}

	// Use the actual Transport code to record what we would send
	// on the wire, but not using TCP.  Use a Transport with a
	// custom dialer that returns a fake net.Conn that waits
	// for the full input (and recording it), and then responds
	// with a dummy response.
	var buf bytes.Buffer // records the output
	pr, pw := io.Pipe()
	defer pr.Close()
	defer pw.Close()
	dr := &delegateReader{c: make(chan io.Reader)}

	t := &Transport{
		Dial: func(net, addr string) (net.Conn, error) {
			return &dumpConn{io.MultiWriter(&buf, pw), dr}, nil
		},
	}
	defer t.CloseIdleConnections()

	// We need this channel to ensure that the reader
	// goroutine exits if t.RoundTrip returns an error.
	// See golang.org/issue/32571.
	quitReadCh := make(chan struct{})
	// Wait for the request before replying with a dummy response:
	go func() {
		req, err := ReadRequest(bufio.NewReader(pr))
		if err == nil {
			// Ensure all the body is read; otherwise
			// we'll get a partial dump.
			io.Copy(io.Discard, req.Body)
			req.Body.Close()
		}
		select {
		case dr.c <- strings.NewReader("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"):
		case <-quitReadCh:
			// Ensure delegateReader.Read doesn't block forever if we get an error.
			close(dr.c)
		}
	}()

	_, err := t.RoundTrip(reqSend)

	req.Body = save
	if err != nil {
		pw.Close()
		dr.err = err
		close(quitReadCh)
		return nil, err
	}
	dump := buf.Bytes()

	// If we used a dummy body above, remove it now.
	// TODO: if the req.ContentLength is large, we allocate memory
	// unnecessarily just to slice it off here. But this is just
	// a debug function, so this is acceptable for now. We could
	// discard the body earlier if this matters.
	if dummyBody {
		if i := bytes.Index(dump, []byte("\r\n\r\n")); i >= 0 {
			dump = dump[:i+4]
		}
	}
	return dump, nil
}

// delegateReader is a reader that delegates to another reader,
// once it arrives on a channel.
type delegateReader struct {
	c   chan io.Reader
	err error     // only used if r is nil and c is closed.
	r   io.Reader // nil until received from c
}

func (r *delegateReader) Read(p []byte) (int, error) {
	if r.r == nil {
		var ok bool
		if r.r, ok = <-r.c; !ok {
			return 0, r.err
		}
	}
	return r.r.Read(p)
}
