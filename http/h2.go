package http

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/smallerqiu/fhttp/http2/hpack"
	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/idna"
)

type http2erringRoundTripper struct{ err error }

func (rt http2erringRoundTripper) RoundTripErr() error { return rt.err }

func (rt http2erringRoundTripper) RoundTrip(*Request) (*Response, error) { return nil, rt.err }

type http2incomparable [0]func()

// flow is the flow control window's size.
type http2flow struct {
	_ http2incomparable

	// conn points to the shared connection-level flow that is
	// shared by all streams on that conn. It is nil for the flow
	// that's on the conn directly.
	conn *http2flow

	// n is the number of DATA bytes we're allowed to send.
	// A flow is kept both on a conn and a per-stream.
	n int32
}

func (f *http2flow) setConnFlow(cf *http2flow) { f.conn = cf }

func (f *http2flow) available() int32 {
	n := f.n
	if f.conn != nil && f.conn.n < n {
		n = f.conn.n
	}

	return n
}

func (f *http2flow) take(n int32) {
	if n > f.available() {
		panic("internal error: took too much")
	}
	f.n -= n
	if f.conn != nil {
		f.conn.n -= n
	}
}

// add adds n bytes (positive or negative) to the flow control window.
// It returns false if the sum would exceed 2^31-1.
func (f *http2flow) add(n int32) bool {
	sum := f.n + n
	if (sum > n) == (f.n > 0) {
		f.n = sum

		return true
	}

	return false
}

const (
	http2FrameContinuation http2FrameType = 0x9
	http2FrameData         http2FrameType = 0x0
	http2FrameGoAway       http2FrameType = 0x7
	http2FrameHeaders      http2FrameType = 0x1
	http2FramePing         http2FrameType = 0x6
	http2FramePriority     http2FrameType = 0x2
	http2FramePushPromise  http2FrameType = 0x5
	http2FrameRSTStream    http2FrameType = 0x3
	http2FrameSettings     http2FrameType = 0x4
	http2FrameWindowUpdate http2FrameType = 0x8
)

var http2frameName = map[http2FrameType]string{
	http2FrameData:         "DATA",
	http2FrameHeaders:      "HEADERS",
	http2FramePriority:     "PRIORITY",
	http2FrameRSTStream:    "RST_STREAM",
	http2FrameSettings:     "SETTINGS",
	http2FramePushPromise:  "PUSH_PROMISE",
	http2FramePing:         "PING",
	http2FrameGoAway:       "GOAWAY",
	http2FrameWindowUpdate: "WINDOW_UPDATE",
	http2FrameContinuation: "CONTINUATION",
}

type http2Flags uint8

// Has reports whether f contains all (0 or more) flags in v.
func (f http2Flags) Has(v http2Flags) bool {
	return (f & v) == v
}

type http2FrameType uint8

func (t http2FrameType) String() string {
	if s, ok := http2frameName[t]; ok {
		return s
	}

	return fmt.Sprintf("UNKNOWN_FRAME_TYPE_%d", uint8(t))
}

type http2FrameHeader struct {

	// Flags are the 1 byte of 8 potential bit flags per frame.
	// They are specific to the frame type.
	Flags http2Flags

	// Length is the length of the frame, not including the 9 byte header.
	// The maximum size is one byte less than 16MB (uint24), but only
	// frames up to 16KB are allowed without peer agreement.
	Length uint32

	// StreamID is which stream this frame is for. Certain frames
	// are not stream-specific, in which case this field is 0.
	StreamID uint32

	// Type is the 1 byte frame type. There are ten standard frame
	// types, but extension frame types may be written by WriteRawFrame
	// and will be returned by ReadFrame (as UnknownFrame).
	Type http2FrameType

	valid bool // caller can access []byte fields in the Frame

}

// Header returns h. It exists so FrameHeaders can be embedded in other
// specific frame types and implement the Frame interface.
func (h http2FrameHeader) Header() http2FrameHeader { return h }

func (h http2FrameHeader) String() string {
	var buf bytes.Buffer
	buf.WriteString("[FrameHeader ")
	h.writeDebug(&buf)
	buf.WriteByte(']')

	return buf.String()
}

func (h http2FrameHeader) writeDebug(buf *bytes.Buffer) {
	buf.WriteString(h.Type.String())
	if h.Flags != 0 {
		buf.WriteString(" flags=")
		set := 0
		for i := uint8(0); i < 8; i++ {
			if h.Flags&(1<<i) == 0 {
				continue
			}
			set++
			if set > 1 {
				buf.WriteByte('|')
			}
			name := http2flagName[h.Type][http2Flags(1<<i)]
			if name != "" {
				buf.WriteString(name)
			} else {
				fmt.Fprintf(buf, "0x%x", 1<<i)
			}
		}
	}
	if h.StreamID != 0 {
		fmt.Fprintf(buf, " stream=%d", h.StreamID)
	}
	fmt.Fprintf(buf, " len=%d", h.Length)
}

func (h *http2FrameHeader) checkValid() {
	if !h.valid {
		panic("Frame accessor called on non-owned Frame")
	}
}

func (h *http2FrameHeader) invalidate() { h.valid = false }

const (

	// Continuation Frame
	http2FlagContinuationEndHeaders http2Flags = 0x4

	// Data Frame
	http2FlagDataEndStream http2Flags = 0x1
	http2FlagDataPadded    http2Flags = 0x8

	http2FlagHeadersEndHeaders http2Flags = 0x4

	// Headers Frame
	http2FlagHeadersEndStream http2Flags = 0x1
	http2FlagHeadersPadded    http2Flags = 0x8
	http2FlagHeadersPriority  http2Flags = 0x20

	// Ping Frame
	http2FlagPingAck http2Flags = 0x1

	// PushPromise Frame
	http2FlagPushPromiseEndHeaders http2Flags = 0x4
	http2FlagPushPromisePadded     http2Flags = 0x8

	// Settings Frame
	http2FlagSettingsAck http2Flags = 0x1
)

var http2flagName = map[http2FrameType]map[http2Flags]string{
	http2FrameData: {
		http2FlagDataEndStream: "END_STREAM",
		http2FlagDataPadded:    "PADDED",
	},
	http2FrameHeaders: {
		http2FlagHeadersEndStream:  "END_STREAM",
		http2FlagHeadersEndHeaders: "END_HEADERS",
		http2FlagHeadersPadded:     "PADDED",
		http2FlagHeadersPriority:   "PRIORITY",
	},
	http2FrameSettings: {
		http2FlagSettingsAck: "ACK",
	},
	http2FramePing: {
		http2FlagPingAck: "ACK",
	},
	http2FrameContinuation: {
		http2FlagContinuationEndHeaders: "END_HEADERS",
	},
	http2FramePushPromise: {
		http2FlagPushPromiseEndHeaders: "END_HEADERS",
		http2FlagPushPromisePadded:     "PADDED",
	},
}

func http2parseDataFrame(fc *http2frameCache, fh http2FrameHeader, payload []byte) (http2Frame, error) {
	if fh.StreamID == 0 {
		// DATA frames MUST be associated with a stream. If a
		// DATA frame is received whose stream identifier
		// field is 0x0, the recipient MUST respond with a
		// connection error (Section 5.4.1) of type
		// PROTOCOL_ERROR.
		return nil, http2connError{http2ErrCodeProtocol, "DATA frame with stream ID 0"}
	}
	f := fc.getDataFrame()
	f.http2FrameHeader = fh

	var padSize byte
	if fh.Flags.Has(http2FlagDataPadded) {
		var err error
		payload, padSize, err = http2readByte(payload)
		if err != nil {
			return nil, err
		}
	}
	if int(padSize) > len(payload) {
		// If the length of the padding is greater than the
		// length of the frame payload, the recipient MUST
		// treat this as a connection error.
		// Filed: https://github.com/http2/http2-spec/issues/610
		return nil, http2connError{http2ErrCodeProtocol, "pad size larger than data payload"}
	}
	f.data = payload[:len(payload)-int(padSize)]

	return f, nil
}

type http2DataFrame struct {
	http2FrameHeader
	data []byte
}

func (f *http2DataFrame) StreamEnded() bool {
	return f.http2FrameHeader.Flags.Has(http2FlagDataEndStream)
}

// Data returns the frame's data octets, not including any padding
// size byte or padding suffix bytes.
// The caller must not retain the returned memory past the next
// call to ReadFrame.
func (f *http2DataFrame) Data() []byte {
	f.checkValid()

	return f.data
}

type http2frameCache struct {
	dataFrame http2DataFrame
}

func (fc *http2frameCache) getDataFrame() *http2DataFrame {
	if fc == nil {
		return &http2DataFrame{}
	}

	return &fc.dataFrame
}

// A Framer reads and writes Frames.
type http2Framer struct {

	// AllowIllegalReads permits the Framer's ReadFrame method
	// to return non-compliant frames or frame orders.
	// This is for testing and permits using the Framer to test
	// other HTTP/2 implementations' conformance to the spec.
	// It is not compatible with ReadMetaHeaders.
	AllowIllegalReads bool

	// AllowIllegalWrites permits the Framer's Write methods to
	// write frames that do not conform to the HTTP/2 spec. This
	// permits using the Framer to test other HTTP/2
	// implementations' conformance to the spec.
	// If false, the Write methods will prefer to return an error
	// rather than comply.
	AllowIllegalWrites bool

	debugFramer       *http2Framer // only use for logging written writes
	debugFramerBuf    *bytes.Buffer
	debugReadLoggerf  func(string, ...interface{})
	debugWriteLoggerf func(string, ...interface{})

	errDetail error

	frameCache *http2frameCache // nil if frames aren't reused (default)

	// TODO: let getReadBuf be configurable, and use a less memory-pinning
	// allocator in server.go to minimize memory pinned for many idle conns.
	// Will probably also need to make frame invalidation have a hook too.
	getReadBuf func(size uint32) []byte
	headerBuf  [http2frameHeaderLen]byte

	lastFrame http2Frame

	// lastHeaderStream is non-zero if the last frame was an
	// unfinished HEADERS/PUSH_PROMISE/CONTINUATION.
	lastHeaderStream uint32

	// TODO: track which type of frame & with which flags was sent
	// last. Then return an error (unless AllowIllegalWrites) if
	// we're in the middle of a header block and a
	// non-Continuation or Continuation on a different stream is
	// attempted to be written.

	logReads, logWrites bool

	// MaxHeaderListSize is the http2 MAX_HEADER_LIST_SIZE.
	// It's used only if ReadMetaHeaders is set; 0 means a sane default
	// (currently 16MB)
	// If the limit is hit, MetaHeadersFrame.Truncated is set true.
	MaxHeaderListSize uint32

	maxReadSize uint32

	maxWriteSize uint32 // zero means unlimited; TODO: implement

	r       io.Reader
	readBuf []byte // cache for default getReadBuf

	// ReadMetaHeaders if non-nil causes ReadFrame to merge:
	// HEADERS      + CONTINUATIONs -> MetaHeadersFrame
	// PUSH_PROMISE + CONTINUATIONs -> MetaPushPromiseFrame
	// and return the meta frame instead.
	ReadMetaHeaders *hpack.Decoder

	w    io.Writer
	wbuf []byte
}

func (fr *http2Framer) maxHeaderListSize() uint32 {
	if fr.MaxHeaderListSize == 0 {
		return 16 << 20 // sane default, per docs
	}

	return fr.MaxHeaderListSize
}

func (f *http2Framer) startWrite(ftype http2FrameType, flags http2Flags, streamID uint32) {
	// Write the FrameHeader.
	f.wbuf = append(f.wbuf[:0],
		0, // 3 bytes of length, filled in in endWrite
		0,
		0,
		byte(ftype),
		byte(flags),
		byte(streamID>>24),
		byte(streamID>>16),
		byte(streamID>>8),
		byte(streamID))
}
func (fr *http2Framer) SetMaxReadFrameSize(v uint32) {
	if v > http2maxFrameSize {
		v = http2maxFrameSize
	}
	fr.maxReadSize = v
}

const http2frameHeaderLen = 9

var http2ErrFrameTooLarge = errors.New("http2: frame too large")

func (f *http2Framer) endWrite() error {
	// Now that we know the final size, fill in the FrameHeader in
	// the space previously reserved for it. Abuse append.
	length := len(f.wbuf) - http2frameHeaderLen
	if length >= (1 << 24) {
		return http2ErrFrameTooLarge
	}
	_ = append(f.wbuf[:0],
		byte(length>>16),
		byte(length>>8),
		byte(length))
	if f.logWrites {
		f.logWrite()
	}

	n, err := f.w.Write(f.wbuf)
	if err == nil && n != len(f.wbuf) {
		err = io.ErrShortWrite
	}

	return err
}

var (
	http2inTests        bool
	http2logFrameReads  bool
	http2logFrameWrites bool
	http2VerboseLogs    bool
)

const (
	http2maxFrameSize    = 1<<24 - 1
	http2minMaxFrameSize = 1 << 14
)

func http2NewFramer(w io.Writer, r io.Reader) *http2Framer {
	fr := &http2Framer{
		w:                 w,
		r:                 r,
		logReads:          http2logFrameReads,
		logWrites:         http2logFrameWrites,
		debugReadLoggerf:  log.Printf,
		debugWriteLoggerf: log.Printf,
	}
	fr.getReadBuf = func(size uint32) []byte {
		if cap(fr.readBuf) >= int(size) {
			return fr.readBuf[:size]
		}
		fr.readBuf = make([]byte, size)

		return fr.readBuf
	}
	fr.SetMaxReadFrameSize(http2maxFrameSize)

	return fr
}

var http2fhBytes = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, http2frameHeaderLen)
		return &buf
	},
}

func http2readFrameHeader(buf []byte, r io.Reader) (http2FrameHeader, error) {
	_, err := io.ReadFull(r, buf[:http2frameHeaderLen])
	if err != nil {
		return http2FrameHeader{}, err
	}

	return http2FrameHeader{
		Length:   (uint32(buf[0])<<16 | uint32(buf[1])<<8 | uint32(buf[2])),
		Type:     http2FrameType(buf[3]),
		Flags:    http2Flags(buf[4]),
		StreamID: binary.BigEndian.Uint32(buf[5:]) & (1<<31 - 1),
		valid:    true,
	}, nil
}
func http2ReadFrameHeader(r io.Reader) (http2FrameHeader, error) {
	bufp := http2fhBytes.Get().(*[]byte)
	defer http2fhBytes.Put(bufp)

	return http2readFrameHeader(*bufp, r)
}

type http2PriorityParam struct {

	// Exclusive is whether the dependency is exclusive.
	Exclusive bool

	// StreamDep is a 31-bit stream identifier for the
	// stream that this stream depends on. Zero means no
	// dependency.
	StreamDep uint32

	// Weight is the stream's zero-indexed weight. It should be
	// set together with StreamDep, or neither should be set. Per
	// the spec, "Add one to the value to obtain a weight between
	// 1 and 256."
	Weight uint8
}

func (p http2PriorityParam) IsZero() bool {
	return p == http2PriorityParam{}
}

type http2HeadersFrame struct {
	http2FrameHeader

	headerFragBuf []byte // not owned

	// Priority is set if FlagHeadersPriority is set in the FrameHeader.
	Priority http2PriorityParam
}

func (f *http2HeadersFrame) HeaderBlockFragment() []byte {
	f.checkValid()

	return f.headerFragBuf
}

func (f *http2HeadersFrame) clearHeaderBlockFragment() {
	f.headerFragBuf = nil
}

func (f *http2HeadersFrame) HeadersEnded() bool {
	return f.http2FrameHeader.Flags.Has(http2FlagHeadersEndHeaders)
}

func (f *http2HeadersFrame) StreamEnded() bool {
	return f.http2FrameHeader.Flags.Has(http2FlagHeadersEndStream)
}

func (f *http2HeadersFrame) HasPriority() bool {
	return f.http2FrameHeader.Flags.Has(http2FlagHeadersPriority)
}
func http2readByte(p []byte) (remain []byte, b byte, err error) {
	if len(p) == 0 {
		return nil, 0, io.ErrUnexpectedEOF
	}

	return p[1:], p[0], nil
}

type http2connError struct {
	Code   http2ErrCode // the ConnectionError error code
	Reason string       // additional reason
}

func (e http2connError) Error() string {
	return fmt.Sprintf("http2: connection error: %v: %v", e.Code, e.Reason)
}

type http2StreamError struct {
	Cause    error // optional additional detail
	Code     http2ErrCode
	StreamID uint32
}

func (e http2StreamError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("stream error: stream ID %d; %v; %v", e.StreamID, e.Code, e.Cause)
	}

	return fmt.Sprintf("stream error: stream ID %d; %v", e.StreamID, e.Code)
}
func http2streamError(id uint32, code http2ErrCode) http2StreamError {
	return http2StreamError{StreamID: id, Code: code}
}

func http2parseHeadersFrame(_ *http2frameCache, fh http2FrameHeader, p []byte) (_ http2Frame, err error) {
	hf := &http2HeadersFrame{
		http2FrameHeader: fh,
	}
	if fh.StreamID == 0 {
		// HEADERS frames MUST be associated with a stream. If a HEADERS frame
		// is received whose stream identifier field is 0x0, the recipient MUST
		// respond with a connection error (Section 5.4.1) of type
		// PROTOCOL_ERROR.
		return nil, http2connError{http2ErrCodeProtocol, "HEADERS frame with stream ID 0"}
	}
	var padLength uint8
	if fh.Flags.Has(http2FlagHeadersPadded) {
		if p, padLength, err = http2readByte(p); err != nil {
			return
		}
	}
	if fh.Flags.Has(http2FlagHeadersPriority) {
		var v uint32
		p, v, err = http2readUint32(p)
		if err != nil {
			return nil, err
		}
		hf.Priority.StreamDep = v & 0x7fffffff
		hf.Priority.Exclusive = (v != hf.Priority.StreamDep) // high bit was set
		p, hf.Priority.Weight, err = http2readByte(p)
		if err != nil {
			return nil, err
		}
	}
	if len(p)-int(padLength) <= 0 {
		return nil, http2streamError(fh.StreamID, http2ErrCodeProtocol)
	}
	hf.headerFragBuf = p[:len(p)-int(padLength)]

	return hf, nil
}

type http2frameParser func(fc *http2frameCache, fh http2FrameHeader, payload []byte) (http2Frame, error)

var http2frameParsers = map[http2FrameType]http2frameParser{
	http2FrameData:         http2parseDataFrame,
	http2FrameHeaders:      http2parseHeadersFrame,
	http2FramePriority:     http2parsePriorityFrame,
	http2FrameRSTStream:    http2parseRSTStreamFrame,
	http2FrameSettings:     http2parseSettingsFrame,
	http2FramePushPromise:  http2parsePushPromise,
	http2FramePing:         http2parsePingFrame,
	http2FrameGoAway:       http2parseGoAwayFrame,
	http2FrameWindowUpdate: http2parseWindowUpdateFrame,
	http2FrameContinuation: http2parseContinuationFrame,
}

type http2ContinuationFrame struct {
	http2FrameHeader
	headerFragBuf []byte
}

func http2parseContinuationFrame(_ *http2frameCache, fh http2FrameHeader, p []byte) (http2Frame, error) {
	if fh.StreamID == 0 {
		return nil, http2connError{http2ErrCodeProtocol, "CONTINUATION frame with stream ID 0"}
	}

	return &http2ContinuationFrame{fh, p}, nil
}
func http2parseWindowUpdateFrame(_ *http2frameCache, fh http2FrameHeader, p []byte) (http2Frame, error) {
	if len(p) != 4 {
		return nil, http2ConnectionError(http2ErrCodeFrameSize)
	}
	inc := binary.BigEndian.Uint32(p[:4]) & 0x7fffffff // mask off high reserved bit
	if inc == 0 {
		// A receiver MUST treat the receipt of a
		// WINDOW_UPDATE frame with an flow control window
		// increment of 0 as a stream error (Section 5.4.2) of
		// type PROTOCOL_ERROR; errors on the connection flow
		// control window MUST be treated as a connection
		// error (Section 5.4.1).
		if fh.StreamID == 0 {
			return nil, http2ConnectionError(http2ErrCodeProtocol)
		}

		return nil, http2streamError(fh.StreamID, http2ErrCodeProtocol)
	}

	return &http2WindowUpdateFrame{
		http2FrameHeader: fh,
		Increment:        inc,
	}, nil
}
func http2parseGoAwayFrame(_ *http2frameCache, fh http2FrameHeader, p []byte) (http2Frame, error) {
	if fh.StreamID != 0 {
		return nil, http2ConnectionError(http2ErrCodeProtocol)
	}
	if len(p) < 8 {
		return nil, http2ConnectionError(http2ErrCodeFrameSize)
	}

	return &http2GoAwayFrame{
		http2FrameHeader: fh,
		LastStreamID:     binary.BigEndian.Uint32(p[:4]) & (1<<31 - 1),
		ErrCode:          http2ErrCode(binary.BigEndian.Uint32(p[4:8])),
		debugData:        p[8:],
	}, nil
}
func http2parsePingFrame(_ *http2frameCache, fh http2FrameHeader, payload []byte) (http2Frame, error) {
	if len(payload) != 8 {
		return nil, http2ConnectionError(http2ErrCodeFrameSize)
	}
	if fh.StreamID != 0 {
		return nil, http2ConnectionError(http2ErrCodeProtocol)
	}
	f := &http2PingFrame{http2FrameHeader: fh}
	copy(f.Data[:], payload)

	return f, nil
}

type http2SettingsFrame struct {
	http2FrameHeader
	p []byte
}

func (f *http2SettingsFrame) IsAck() bool {
	return f.http2FrameHeader.Flags.Has(http2FlagSettingsAck)
}

func (f *http2SettingsFrame) Value(id http2SettingID) (v uint32, ok bool) {
	f.checkValid()
	for i := 0; i < f.NumSettings(); i++ {
		if s := f.Setting(i); s.ID == id {
			return s.Val, true
		}
	}

	return 0, false
}

// Setting returns the setting from the frame at the given 0-based index.
// The index must be >= 0 and less than f.NumSettings().
func (f *http2SettingsFrame) Setting(i int) http2Setting {
	buf := f.p

	return http2Setting{
		ID:  http2SettingID(binary.BigEndian.Uint16(buf[i*6 : i*6+2])),
		Val: binary.BigEndian.Uint32(buf[i*6+2 : i*6+6]),
	}
}

func (f *http2SettingsFrame) NumSettings() int { return len(f.p) / 6 }

// HasDuplicates reports whether f contains any duplicate setting IDs.
func (f *http2SettingsFrame) HasDuplicates() bool {
	num := f.NumSettings()
	if num == 0 {
		return false
	}
	// If it's small enough (the common case), just do the n^2
	// thing and avoid a map allocation.
	if num < 10 {
		for i := 0; i < num; i++ {
			idi := f.Setting(i).ID
			for j := i + 1; j < num; j++ {
				idj := f.Setting(j).ID
				if idi == idj {
					return true
				}
			}
		}

		return false
	}
	seen := map[http2SettingID]bool{}
	for i := 0; i < num; i++ {
		id := f.Setting(i).ID
		if seen[id] {
			return true
		}
		seen[id] = true
	}

	return false
}

// ForeachSetting runs fn for each setting.
// It stops and returns the first error.
func (f *http2SettingsFrame) ForeachSetting(fn func(http2Setting) error) error {
	f.checkValid()
	for i := 0; i < f.NumSettings(); i++ {
		if err := fn(f.Setting(i)); err != nil {
			return err
		}
	}

	return nil
}

const (
	http2SettingEnablePush           http2SettingID = 0x2
	http2SettingHeaderTableSize      http2SettingID = 0x1
	http2SettingInitialWindowSize    http2SettingID = 0x4
	http2SettingMaxConcurrentStreams http2SettingID = 0x3
	http2SettingMaxFrameSize         http2SettingID = 0x5
	http2SettingMaxHeaderListSize    http2SettingID = 0x6
)

var http2settingName = map[http2SettingID]string{
	http2SettingHeaderTableSize:      "HEADER_TABLE_SIZE",
	http2SettingEnablePush:           "ENABLE_PUSH",
	http2SettingMaxConcurrentStreams: "MAX_CONCURRENT_STREAMS",
	http2SettingInitialWindowSize:    "INITIAL_WINDOW_SIZE",
	http2SettingMaxFrameSize:         "MAX_FRAME_SIZE",
	http2SettingMaxHeaderListSize:    "MAX_HEADER_LIST_SIZE",
}

func http2parseSettingsFrame(_ *http2frameCache, fh http2FrameHeader, p []byte) (http2Frame, error) {
	if fh.Flags.Has(http2FlagSettingsAck) && fh.Length > 0 {
		// When this (ACK 0x1) bit is set, the payload of the
		// SETTINGS frame MUST be empty. Receipt of a
		// SETTINGS frame with the ACK flag set and a length
		// field value other than 0 MUST be treated as a
		// connection error (Section 5.4.1) of type
		// FRAME_SIZE_ERROR.
		return nil, http2ConnectionError(http2ErrCodeFrameSize)
	}
	if fh.StreamID != 0 {
		// SETTINGS frames always apply to a connection,
		// never a single stream. The stream identifier for a
		// SETTINGS frame MUST be zero (0x0).  If an endpoint
		// receives a SETTINGS frame whose stream identifier
		// field is anything other than 0x0, the endpoint MUST
		// respond with a connection error (Section 5.4.1) of
		// type PROTOCOL_ERROR.
		return nil, http2ConnectionError(http2ErrCodeProtocol)
	}
	if len(p)%6 != 0 {
		// Expecting even number of 6 byte settings.
		return nil, http2ConnectionError(http2ErrCodeFrameSize)
	}
	f := &http2SettingsFrame{http2FrameHeader: fh, p: p}
	if v, ok := f.Value(http2SettingInitialWindowSize); ok && v > (1<<31)-1 {
		// Values above the maximum flow control window size of 2^31 - 1 MUST
		// be treated as a connection error (Section 5.4.1) of type
		// FLOW_CONTROL_ERROR.
		return nil, http2ConnectionError(http2ErrCodeFlowControl)
	}

	return f, nil
}
func http2parseRSTStreamFrame(_ *http2frameCache, fh http2FrameHeader, p []byte) (http2Frame, error) {
	if len(p) != 4 {
		return nil, http2ConnectionError(http2ErrCodeFrameSize)
	}
	if fh.StreamID == 0 {
		return nil, http2ConnectionError(http2ErrCodeProtocol)
	}

	return &http2RSTStreamFrame{fh, http2ErrCode(binary.BigEndian.Uint32(p[:4]))}, nil
}

type http2PriorityFrame struct {
	http2FrameHeader
	http2PriorityParam
}

func http2parsePriorityFrame(_ *http2frameCache, fh http2FrameHeader, payload []byte) (http2Frame, error) {
	if fh.StreamID == 0 {
		return nil, http2connError{http2ErrCodeProtocol, "PRIORITY frame with stream ID 0"}
	}
	if len(payload) != 5 {
		return nil, http2connError{http2ErrCodeFrameSize, fmt.Sprintf("PRIORITY frame payload size was %d; want 5", len(payload))}
	}
	v := binary.BigEndian.Uint32(payload[:4])
	streamID := v & 0x7fffffff // mask off high bit

	return &http2PriorityFrame{
		http2FrameHeader: fh,
		http2PriorityParam: http2PriorityParam{
			Weight:    payload[4],
			StreamDep: streamID,
			Exclusive: streamID != v, // was high bit set?
		},
	}, nil
}

type http2UnknownFrame struct {
	http2FrameHeader
	p []byte
}

func (f *http2UnknownFrame) Payload() []byte {
	f.checkValid()

	return f.p
}
func http2parseUnknownFrame(_ *http2frameCache, fh http2FrameHeader, p []byte) (http2Frame, error) {
	return &http2UnknownFrame{fh, p}, nil
}
func http2typeFrameParser(t http2FrameType) http2frameParser {
	if f := http2frameParsers[t]; f != nil {
		return f
	}

	return http2parseUnknownFrame
}
func (fr *http2Framer) ReadFrame() (http2Frame, error) {
	fr.errDetail = nil
	if fr.lastFrame != nil {
		fr.lastFrame.invalidate()
	}
	fh, err := http2readFrameHeader(fr.headerBuf[:], fr.r)
	if err != nil {
		return nil, err
	}
	if fh.Length > fr.maxReadSize {
		return nil, http2ErrFrameTooLarge
	}
	payload := fr.getReadBuf(fh.Length)
	if _, err := io.ReadFull(fr.r, payload); err != nil {
		return nil, err
	}
	f, err := http2typeFrameParser(fh.Type)(fr.frameCache, fh, payload)
	if err != nil {
		if ce, ok := err.(http2connError); ok {
			return nil, fr.connError(ce.Code, ce.Reason)
		}

		return nil, err
	}
	if err := fr.checkFrameOrder(f); err != nil {
		return nil, err
	}
	if fr.logReads {
		fr.debugReadLoggerf("http2: Framer %p: read %v. Type: %v", fr, http2summarizeFrame(f), fh.Type)
	}
	if (fh.Type == http2FrameHeaders || fh.Type == http2FramePushPromise) && fr.ReadMetaHeaders != nil {
		return fr.readMetaFrame(f.(http2continuable))
	}

	return f, nil
}
func (fr *http2Framer) checkFrameOrder(f http2Frame) error {
	last := fr.lastFrame
	fr.lastFrame = f
	if fr.AllowIllegalReads {
		return nil
	}

	fh := f.Header()
	if fr.lastHeaderStream != 0 {
		if fh.Type != http2FrameContinuation {
			return fr.connError(http2ErrCodeProtocol,
				fmt.Sprintf("got %s for stream %d; expected CONTINUATION following %s for stream %d",
					fh.Type, fh.StreamID,
					last.Header().Type, fr.lastHeaderStream))
		}
		if fh.StreamID != fr.lastHeaderStream {
			return fr.connError(http2ErrCodeProtocol,
				fmt.Sprintf("got CONTINUATION for stream %d; expected stream %d",
					fh.StreamID, fr.lastHeaderStream))
		}
	} else if fh.Type == http2FrameContinuation {
		return fr.connError(http2ErrCodeProtocol, fmt.Sprintf("unexpected CONTINUATION for stream %d", fh.StreamID))
	}

	switch fh.Type {
	case http2FrameHeaders, http2FramePushPromise, http2FrameContinuation:
		if fh.Flags.Has(http2FlagHeadersEndHeaders) {
			fr.lastHeaderStream = 0
		} else {
			fr.lastHeaderStream = fh.StreamID
		}
	}

	return nil
}

func http2summarizeFrame(f http2Frame) string {
	var buf bytes.Buffer
	f.Header().writeDebug(&buf)
	switch f := f.(type) {
	case *http2SettingsFrame:
		n := 0
		f.ForeachSetting(func(s http2Setting) error {
			n++
			if n == 1 {
				buf.WriteString(", settings:")
			}
			fmt.Fprintf(&buf, " %v=%v,", s.ID, s.Val)

			return nil
		})
		if n > 0 {
			buf.Truncate(buf.Len() - 1) // remove trailing comma
		}
	case *http2DataFrame:
		data := f.Data()
		const max = 256
		if len(data) > max {
			data = data[:max]
		}
		fmt.Fprintf(&buf, " data=%q", data)
		if len(f.Data()) > max {
			fmt.Fprintf(&buf, " (%d bytes omitted)", len(f.Data())-max)
		}
	case *http2WindowUpdateFrame:
		if f.StreamID == 0 {
			buf.WriteString(" (conn)")
		}
		fmt.Fprintf(&buf, " incr=%v", f.Increment)
	case *http2PingFrame:
		fmt.Fprintf(&buf, " ping=%q", f.Data[:])
	case *http2GoAwayFrame:
		fmt.Fprintf(&buf, " LastStreamID=%v ErrCode=%v Debug=%q",
			f.LastStreamID, f.ErrCode, f.debugData)
	case *http2RSTStreamFrame:
		fmt.Fprintf(&buf, " ErrCode=%v", f.ErrCode)
	case *http2MetaPushPromiseFrame:
		fmt.Fprintf(&buf, " PromiseID=%v", f.PromiseID)
	}

	return buf.String()
}

type http2PushPromiseFrame struct {
	http2FrameHeader
	headerFragBuf []byte // not owned
	PromiseID     uint32
}

type http2ConnectionError http2ErrCode

func (e http2ConnectionError) Error() string {
	return fmt.Sprintf("connection error: %s", http2ErrCode(e))
}

func (f *http2PushPromiseFrame) HeaderBlockFragment() []byte {
	f.checkValid()

	return f.headerFragBuf
}

func (f *http2PushPromiseFrame) clearHeaderBlockFragment() {
	f.headerFragBuf = nil
}

func (f *http2PushPromiseFrame) HeadersEnded() bool {
	return f.http2FrameHeader.Flags.Has(http2FlagPushPromiseEndHeaders)
}

func http2parsePushPromise(_ *http2frameCache, fh http2FrameHeader, p []byte) (_ http2Frame, err error) {
	pp := &http2PushPromiseFrame{
		http2FrameHeader: fh,
	}
	if pp.StreamID == 0 {
		// PUSH_PROMISE frames MUST be associated with an existing,
		// peer-initiated stream. The stream identifier of a
		// PUSH_PROMISE frame indicates the stream it is associated
		// with. If the stream identifier field specifies the value
		// 0x0, a recipient MUST respond with a connection error
		// (Section 5.4.1) of type PROTOCOL_ERROR.
		return nil, http2connError{http2ErrCodeProtocol, "PUSH_PROMISE frame with stream ID 0"}
	}
	// The PUSH_PROMISE frame includes optional padding.
	// Padding fields and flags are identical to those defined for DATA frames
	var padLength uint8
	if fh.Flags.Has(http2FlagPushPromisePadded) {
		if p, padLength, err = http2readByte(p); err != nil {
			return
		}
	}

	p, pp.PromiseID, err = http2readUint32(p)
	if err != nil {
		return
	}
	pp.PromiseID = pp.PromiseID & (1<<31 - 1)

	if int(padLength) > len(p) {
		// like the DATA frame, error out if padding is longer than the body.
		return nil, http2ConnectionError(http2ErrCodeProtocol)
	}
	pp.headerFragBuf = p[:len(p)-int(padLength)]

	return pp, nil
}
func http2readUint32(p []byte) (remain []byte, v uint32, err error) {
	if len(p) < 4 {
		return nil, 0, io.ErrUnexpectedEOF
	}

	return p[4:], binary.BigEndian.Uint32(p[:4]), nil
}

type http2MetaPushPromiseFrame struct {
	*http2PushPromiseFrame
	// Fields are the fields contained in the PUSH_PROMISE and
	// CONTINUATION frames. The underlying slice is owned by the
	// Framer and must not be retained after the next call to
	// ReadFrame.
	//
	// Fields are guaranteed to be in the correct http2 order and
	// not have unknown pseudo header fields or invalid header
	// field names or values. Required pseudo header fields may be
	// missing, however. Use the MetaPushPromiseFrame.Pseudo accessor
	// method to access pseudo headers.
	Fields []hpack.HeaderField
	// Truncated is whether the max header list size limit was hit
	// and Fields is incomplete. The hpack decoder state is still
	// valid, however.
	Truncated bool
}

// PseudoValue returns the given pseudo header field's value.
// The provided pseudo field should not contain the leading colon.
func (mp *http2MetaPushPromiseFrame) PseudoValue(pseudo string) string {
	for _, hf := range mp.Fields {
		if !hf.IsPseudo() {
			return ""
		}
		if hf.Name[1:] == pseudo {
			return hf.Value
		}
	}

	return ""
}

// RegularFields returns the regular (non-pseudo) header fields of mp.
// The caller does not own the returned slice.
func (mp *http2MetaPushPromiseFrame) RegularFields() []hpack.HeaderField {
	for i, hf := range mp.Fields {
		if !hf.IsPseudo() {
			return mp.Fields[i:]
		}
	}

	return nil
}

// PseudoFields returns the pseudo header fields of mp.
// The caller does not own the returned slice.
func (mp *http2MetaPushPromiseFrame) PseudoFields() []hpack.HeaderField {
	for i, hf := range mp.Fields {
		if !hf.IsPseudo() {
			return mp.Fields[:i]
		}
	}

	return mp.Fields
}

type http2RSTStreamFrame struct {
	http2FrameHeader
	ErrCode http2ErrCode
}
type http2GoAwayFrame struct {
	http2FrameHeader
	debugData    []byte
	ErrCode      http2ErrCode
	LastStreamID uint32
}

// DebugData returns any debug data in the GOAWAY frame. Its contents
// are not defined.
// The caller must not retain the returned memory past the next
// call to ReadFrame.
func (f *http2GoAwayFrame) DebugData() []byte {
	f.checkValid()

	return f.debugData
}

type http2WindowUpdateFrame struct {
	http2FrameHeader
	Increment uint32 // never read with high bit set
}
type http2PingFrame struct {
	http2FrameHeader
	Data [8]byte
}
type http2ErrCode uint32

const (
	http2ErrCodeCancel             http2ErrCode = 0x8
	http2ErrCodeCompression        http2ErrCode = 0x9
	http2ErrCodeConnect            http2ErrCode = 0xa
	http2ErrCodeEnhanceYourCalm    http2ErrCode = 0xb
	http2ErrCodeFlowControl        http2ErrCode = 0x3
	http2ErrCodeFrameSize          http2ErrCode = 0x6
	http2ErrCodeHTTP11Required     http2ErrCode = 0xd
	http2ErrCodeInadequateSecurity http2ErrCode = 0xc
	http2ErrCodeInternal           http2ErrCode = 0x2
	http2ErrCodeNo                 http2ErrCode = 0x0
	http2ErrCodeProtocol           http2ErrCode = 0x1
	http2ErrCodeRefusedStream      http2ErrCode = 0x7
	http2ErrCodeSettingsTimeout    http2ErrCode = 0x4
	http2ErrCodeStreamClosed       http2ErrCode = 0x5
)

var http2errCodeName = map[http2ErrCode]string{
	http2ErrCodeNo:                 "NO_ERROR",
	http2ErrCodeProtocol:           "PROTOCOL_ERROR",
	http2ErrCodeInternal:           "INTERNAL_ERROR",
	http2ErrCodeFlowControl:        "FLOW_CONTROL_ERROR",
	http2ErrCodeSettingsTimeout:    "SETTINGS_TIMEOUT",
	http2ErrCodeStreamClosed:       "STREAM_CLOSED",
	http2ErrCodeFrameSize:          "FRAME_SIZE_ERROR",
	http2ErrCodeRefusedStream:      "REFUSED_STREAM",
	http2ErrCodeCancel:             "CANCEL",
	http2ErrCodeCompression:        "COMPRESSION_ERROR",
	http2ErrCodeConnect:            "CONNECT_ERROR",
	http2ErrCodeEnhanceYourCalm:    "ENHANCE_YOUR_CALM",
	http2ErrCodeInadequateSecurity: "INADEQUATE_SECURITY",
	http2ErrCodeHTTP11Required:     "HTTP_1_1_REQUIRED",
}

type http2continuable interface {
	http2Frame
	http2headersEnder
	clearHeaderBlockFragment()
	HeaderBlockFragment() []byte
}

type http2Frame interface {
	Header() http2FrameHeader

	// invalidate is called by Framer.ReadFrame to make this
	// frame's buffers as being invalid, since the subsequent
	// frame will reuse them.
	invalidate()
}
type http2headersEnder interface {
	HeadersEnded() bool
}

type http2metaFrame struct {
	Fields    []hpack.HeaderField
	Truncated bool
}

// pseudoFields returns the pseudo header fields of mf.
// The caller does not own the returned slice.
func (mf *http2metaFrame) pseudoFields() []hpack.HeaderField {
	for i, hf := range mf.Fields {
		if !hf.IsPseudo() {
			return mf.Fields[:i]
		}
	}

	return mf.Fields
}

var (
	http2errMixPseudoHeaderTypes = errors.New("mix of request and response pseudo headers")
	http2errPseudoAfterRegular   = errors.New("pseudo header field after regular")
)

type http2pseudoHeaderError string

func (e http2pseudoHeaderError) Error() string {
	return fmt.Sprintf("invalid pseudo-header %q", string(e))
}

type http2duplicatePseudoHeaderError string

func (e http2duplicatePseudoHeaderError) Error() string {
	return fmt.Sprintf("duplicate pseudo-header %q", string(e))
}
func (mf *http2metaFrame) checkPseudos() error {
	var isRequest, isResponse bool
	pf := mf.pseudoFields()
	for i, hf := range pf {
		switch hf.Name {
		case ":method", ":path", ":scheme", ":authority":
			isRequest = true
		case ":status":
			isResponse = true
		default:
			return http2pseudoHeaderError(hf.Name)
		}
		// Check for duplicates.
		// This would be a bad algorithm, but N is 4.
		// And this doesn't allocate.
		for _, hf2 := range pf[:i] {
			if hf.Name == hf2.Name {
				return http2duplicatePseudoHeaderError(hf.Name)
			}
		}
	}
	if isRequest && isResponse {
		return http2errMixPseudoHeaderTypes
	}

	return nil
}
func (fr *http2Framer) connError(code http2ErrCode, reason string) error {
	fr.errDetail = errors.New(reason)

	return http2ConnectionError(code)
}
func (fr *http2Framer) readMetaFrame(cont http2continuable) (http2Frame, error) {
	if fr.AllowIllegalReads {
		return nil, errors.New("illegal use of AllowIllegalReads")
	}
	mf := &http2metaFrame{}

	var remainSize = fr.maxHeaderListSize()
	var sawRegular bool

	var invalid error // pseudo header field errors
	hdec := fr.ReadMetaHeaders
	hdec.SetEmitEnabled(true)
	hdec.SetMaxStringLength(fr.maxHeaderStringLen())
	hdec.SetEmitFunc(func(hf hpack.HeaderField) {
		if http2VerboseLogs && fr.logReads {
			fr.debugReadLoggerf("http2: decoded hpack field %+v", hf)
		}
		if !httpguts.ValidHeaderFieldValue(hf.Value) {
			invalid = http2headerFieldValueError(hf.Value)
		}
		isPseudo := strings.HasPrefix(hf.Name, ":")
		if isPseudo {
			if sawRegular {
				invalid = http2errPseudoAfterRegular
			}
		} else {
			sawRegular = true
			if !http2validWireHeaderFieldName(hf.Name) {
				invalid = http2headerFieldNameError(hf.Name)
			}
		}

		if invalid != nil {
			hdec.SetEmitEnabled(false)

			return
		}

		size := hf.Size()
		if size > remainSize {
			hdec.SetEmitEnabled(false)
			mf.Truncated = true

			return
		}
		remainSize -= size

		mf.Fields = append(mf.Fields, hf)
	})
	// Lose reference to metaFrame:
	defer hdec.SetEmitFunc(func(hf hpack.HeaderField) {})
	var hc = cont
	for {
		frag := hc.HeaderBlockFragment()
		if _, err := hdec.Write(frag); err != nil {
			return nil, http2ConnectionError(http2ErrCodeCompression)
		}

		if hc.HeadersEnded() {
			break
		}
		if f, err := fr.ReadFrame(); err != nil {
			return nil, err
		} else {
			hc = f.(*http2ContinuationFrame) // guaranteed by checkFrameOrder
		}
	}

	cont.clearHeaderBlockFragment()
	cont.invalidate()

	if err := hdec.Close(); err != nil {
		return nil, http2ConnectionError(http2ErrCodeCompression)
	}
	if invalid != nil {
		fr.errDetail = invalid
		if http2VerboseLogs {
			log.Printf("http2: invalid header: %v", invalid)
		}

		return nil, http2StreamError{invalid, http2ErrCodeProtocol, cont.Header().StreamID}
	}
	if err := mf.checkPseudos(); err != nil {
		fr.errDetail = err
		if http2VerboseLogs {
			log.Printf("http2: invalid pseudo headers: %v", err)
		}

		return nil, http2StreamError{err, http2ErrCodeProtocol, cont.Header().StreamID}
	}

	var f http2Frame
	switch orig := cont.(type) {
	case *http2HeadersFrame:
		f = &http2MetaHeadersFrame{http2HeadersFrame: orig, Fields: mf.Fields, Truncated: mf.Truncated}
	case *http2PushPromiseFrame:
		f = &http2MetaPushPromiseFrame{http2PushPromiseFrame: orig, Fields: mf.Fields, Truncated: mf.Truncated}
	default:
		panic("frame type not supported as meta frame")
	}

	return f, nil
}
func (f *http2Framer) logWrite() {
	if f.debugFramer == nil {
		f.debugFramerBuf = new(bytes.Buffer)
		f.debugFramer = http2NewFramer(nil, f.debugFramerBuf)
		f.debugFramer.logReads = false // we log it ourselves, saying "wrote" below
		// Let us read anything, even if we accidentally wrote it
		// in the wrong order:
		f.debugFramer.AllowIllegalReads = true
	}
	f.debugFramerBuf.Write(f.wbuf)
	fr, err := f.debugFramer.ReadFrame()
	if err != nil {
		f.debugWriteLoggerf("http2: Framer %p: failed to decode just-written frame", f)

		return
	}
	f.debugWriteLoggerf("http2: Framer %p: wrote %v", f, http2summarizeFrame(fr))
}
func (fr *http2Framer) maxHeaderStringLen() int {
	v := fr.maxHeaderListSize()
	if uint32(int(v)) == v {
		return int(v)
	}

	// They had a crazy big number for MaxHeaderBytes anyway,
	// so give them unlimited header lengths:
	return 0
}
func (f *http2Framer) writeByte(v byte) { f.wbuf = append(f.wbuf, v) }

func (f *http2Framer) writeBytes(v []byte) { f.wbuf = append(f.wbuf, v...) }

func (f *http2Framer) writeUint16(v uint16) { f.wbuf = append(f.wbuf, byte(v>>8), byte(v)) }

func (f *http2Framer) writeUint32(v uint32) {
	f.wbuf = append(f.wbuf, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

type http2ClientConn struct {
	br         *bufio.Reader
	bw         *bufio.Writer
	closed     bool
	closing    bool
	cond       *sync.Cond // hold mu; broadcast on flow/closed changes
	dialedAddr string     // addr dialed to create tconn; not set with NewClientConn
	flow       http2flow  // our conn-level flow control quota (cs.flow is per stream)
	fr         *http2Framer
	freeBuf    [][]byte

	goAway      *http2GoAwayFrame // if non-nil, the GoAwayFrame we received
	goAwayDebug string            // goAway frame's debug data, retained as a string

	hbuf             bytes.Buffer // HPACK encoder writes into this
	henc             *hpack.Encoder
	highestPromiseID uint32 // highest promise id so far received from server

	idleTimeout time.Duration // or 0 for never
	idleTimer   *time.Timer

	inflow            http2flow // peer's conn-level flow control
	initialWindowSize uint32

	lastActive           time.Time
	lastIdle             time.Time // time last idle
	maxConcurrentStreams uint32
	// Settings from peer: (also guarded by mu)
	maxFrameSize uint32

	mu                    sync.Mutex // guards following
	nextStreamID          uint32
	peerMaxHeaderListSize uint64
	pendingRequests       int                       // requests blocked and waiting to be sent because len(streams) == maxConcurrentStreams
	pings                 map[[8]byte]chan struct{} // in flight ping data to notification channel

	// readLoop goroutine fields:
	readerDone chan struct{} // closed on error
	readerErr  error         // set before readerDone is closed

	reused    uint32 // whether conn is being reused; atomic
	singleUse bool   // whether being used for a single http.Request

	streams         map[uint32]*http2clientStream // client-initiated
	t               *http2Transport
	tconn           net.Conn             // usually *tls.Conn, except specialized impls
	tlsState        *tls.ConnectionState // nil only for specialized impls
	wantSettingsAck bool                 // we sent a SETTINGS frame and haven't heard back
	werr            error                // first write error that has occurred

	wmu sync.Mutex // held while writing; acquire AFTER mu if holding both
}

func (cc *http2ClientConn) idleState() http2clientConnIdleState {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	return cc.idleStateLocked()
}
func (cc *http2ClientConn) tooIdleLocked() bool {
	// The Round(0) strips the monontonic clock reading so the
	// times are compared based on their wall time. We don't want
	// to reuse a connection that's been sitting idle during
	// VM/laptop suspend if monotonic time was also frozen.
	return cc.idleTimeout != 0 && !cc.lastIdle.IsZero() && time.Since(cc.lastIdle.Round(0)) > cc.idleTimeout
}
func (cc *http2ClientConn) idleStateLocked() (st http2clientConnIdleState) {
	if cc.singleUse && cc.nextStreamID > 1 {
		return
	}
	var maxConcurrentOkay bool
	if cc.t.StrictMaxConcurrentStreams {
		// We'll tell the caller we can take a new request to
		// prevent the caller from dialing a new TCP
		// connection, but then we'll block later before
		// writing it.
		maxConcurrentOkay = true
	} else {
		maxConcurrentOkay = int64(len(cc.streams)+1) < int64(cc.maxConcurrentStreams)
	}

	st.canTakeNewRequest = cc.goAway == nil && !cc.closed && !cc.closing && maxConcurrentOkay &&
		int64(cc.nextStreamID)+2*int64(cc.pendingRequests) < math.MaxInt32 &&
		!cc.tooIdleLocked()
	st.freshConn = cc.nextStreamID == 1 && st.canTakeNewRequest

	return
}
func (cc *http2ClientConn) canTakeNewRequestLocked() bool {
	st := cc.idleStateLocked()

	return st.canTakeNewRequest
}
func (cc *http2ClientConn) CanTakeNewRequest() bool {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	return cc.canTakeNewRequestLocked()
}
func (cc *http2ClientConn) onIdleTimeout() {
	cc.closeIfIdle()
}

func (cc *http2ClientConn) closeIfIdle() {
	cc.mu.Lock()
	if len(cc.streams) > 0 {
		cc.mu.Unlock()

		return
	}
	cc.closed = true
	nextID := cc.nextStreamID
	// TODO: do clients send GOAWAY too? maybe? Just Close:
	cc.mu.Unlock()

	if http2VerboseLogs {
		cc.vlogf("http2: Transport closing idle conn %p (forSingleUse=%v, maxStream=%v)", cc, cc.singleUse, nextID-2)
	}
	cc.tconn.Close()
}
func (cc *http2ClientConn) vlogf(format string, args ...interface{}) {
	cc.t.vlogf(format, args...)
}

type http2ClientConnPool interface {
	GetClientConn(req *Request, addr string) (*http2ClientConn, error)
	MarkDead(*http2ClientConn)
}

type http2SettingID uint16

type http2Setting struct {
	// ID is which setting is being set.
	// See http://http2.github.io/http2-spec/#SettingValues
	ID http2SettingID

	// Val is the value.
	Val uint32
}

func (s http2Setting) String() string {
	return fmt.Sprintf("[%v = %d]", s.ID, s.Val)
}

// Valid reports whether the setting is valid.
func (s http2Setting) Valid() error {
	// Limits and error codes from 6.5.2 Defined SETTINGS Parameters
	switch s.ID {
	case http2SettingEnablePush:
		if s.Val != 1 && s.Val != 0 {
			return http2ConnectionError(http2ErrCodeProtocol)
		}
	case http2SettingInitialWindowSize:
		if s.Val > 1<<31-1 {
			return http2ConnectionError(http2ErrCodeFlowControl)
		}
	case http2SettingMaxFrameSize:
		if s.Val < 16384 || s.Val > 1<<24-1 {
			return http2ConnectionError(http2ErrCodeProtocol)
		}
	}

	return nil
}

type http2resAndError struct {
	_   http2incomparable
	err error
	res *Response
}
type http2pipeBuffer interface {
	io.Reader
	io.Writer
	Len() int
}
type http2pipe struct {
	b        http2pipeBuffer // nil when done reading
	breakErr error           // immediate read error (caller doesn't see rest of b)
	c        sync.Cond       // c.L lazily initialized to &p.mu
	donec    chan struct{}   // closed on error
	err      error           // read error once empty. non-nil means closed.
	mu       sync.Mutex
	readFn   func() // optional code to run in Read before error
	unread   int    // bytes unread when done
}

type http2clientStream struct {
	bufPipe     http2pipe // buffered pipe with the flow-controlled response payload
	bytesRemain int64     // -1 means unknown; owned by transportResponseBody.Read
	cc          *http2ClientConn
	didReset    bool // whether we sent a RST_STREAM to the server; guarded by cc.mu

	done chan struct{} // closed when stream remove from cc.streams map; close calls guarded by cc.mu

	// owned by clientConnReadLoop:
	firstByte bool // got the first response byte

	flow         http2flow // guarded by cc.mu
	gotEndStream bool      // got frame with END_STREAM flag set
	ID           uint32
	inflow       http2flow // guarded by cc.mu
	num1xx       uint8     // number of 1xx responses seen

	on100 func() // optional code to run if get a 100 continue response

	pastHeaders  bool // got first MetaHeadersFrame (actual headers)
	pastTrailers bool // got optional second MetaHeadersFrame (trailers)

	peerReset     chan struct{} // closed on peer reset
	readErr       error         // sticky read error; owned by transportResponseBody.Read
	req           *Request
	requestedGzip bool
	resc          chan http2resAndError
	resetErr      error // populated before peerReset is closed

	resTrailer   *Header                // client's Response.Trailer
	startedWrite bool                   // started request body write; guarded by cc.mu
	stopReqBody  error                  // if non-nil, stop writing req body; guarded by cc.mu
	trace        *httptrace.ClientTrace // or nil

	trailer Header // accumulated trailers
}
type http2PushedRequest struct {

	// OriginalRequestHeader contains the headers of the original client request that triggered the push.
	OriginalRequestHeader Header

	// OriginalRequestURL is the URL of the original client request that triggered the push.
	OriginalRequestURL *url.URL

	// Promise is the HTTP/2 PUSH_PROMISE message. The promised
	// request does not have a body. Handlers should not modify Promise.
	//
	// Promise.RemoteAddr is the address of the server that started this push request.
	Promise *Request

	pushedStream *http2clientStream
}
type http2PushHandler interface {
	// HandlePush will be called once for every PUSH_PROMISE received
	// from the server. If HandlePush returns before the pushed stream
	// has completed, the pushed stream will be canceled.
	HandlePush(r *http2PushedRequest)
}

type http2Transport struct {

	// AllowHTTP, if true, permits HTTP/2 requests using the insecure,
	// plain-text "http" scheme. Note that this does not enable h2c support.
	AllowHTTP bool

	// ConnPool optionally specifies an alternate connection pool to use.
	// If nil, the default is used.
	ConnPool http2ClientConnPool

	connPoolOnce  sync.Once
	connPoolOrDef http2ClientConnPool // non-nil version of ConnPool

	// DialTLS specifies an optional dial function for creating
	// TLS connections for requests.
	//
	// If DialTLS is nil, tls.Dial is used.
	//
	// If the returned net.Conn has a ConnectionState method like tls.Conn,
	// it will be used to set http.Response.TLS.
	DialTLS func(network, addr string, cfg *tls.Config) (net.Conn, error)

	// DisableCompression, if true, prevents the Transport from
	// requesting compression with an "Accept-Encoding: gzip"
	// request header when the Request contains no existing
	// Accept-Encoding value. If the Transport requests gzip on
	// its own and gets a gzipped response, it's transparently
	// decoded in the Response.Body. However, if the user
	// explicitly requested gzip it is not automatically
	// uncompressed.
	DisableCompression bool

	HeaderTableSize   uint32 // if nil, will use global initialHeaderTableSize
	InitialWindowSize uint32 // if nil, will use global initialWindowSize

	// MaxHeaderListSize is the http2 SETTINGS_MAX_HEADER_LIST_SIZE to
	// send in the initial settings frame. It is how many bytes
	// of response headers are allowed. Unlike the http2 spec, zero here
	// means to use a default limit (currently 10MB). If you actually
	// want to advertise an unlimited value to the peer, Transport
	// interprets the highest possible value here (0xffffffff or 1<<32-1)
	// to mean no limit.
	MaxHeaderListSize uint32

	// PingTimeout is the timeout after which the connection will be closed
	// if a response to Ping is not received.
	// Defaults to 15s.
	PingTimeout time.Duration

	// PushHandler is called upon receiving PUSH_PROMISEs from the server.
	// If nil, server push is disabled.
	//
	// Unless TLSClientConfig.InsecureSkipVerify is set, the Transport verifies
	// whether the server is authoritative for the received PUSH_PROMISEs. On a
	// TLS connection, this is done by verifing the certificates. On a non-TLS
	// connection, the pushed request must have the same host name as the
	// original one.
	//
	// There is no support for limiting the number of responses
	// that can be concurrently pushed by the server, for example, by setting
	// SETTINGS_MAX_CONCURRENT_STREAMS.
	PushHandler http2PushHandler

	// ReadIdleTimeout is the timeout after which a health check using ping
	// frame will be carried out if no frame is received on the connection.
	// Note that a ping response will is considered a received frame, so if
	// there is no other traffic on the connection, the health check will
	// be performed every ReadIdleTimeout interval.
	// If zero, no health check is performed.
	ReadIdleTimeout time.Duration

	// Settings should not include InitialWindowSize or HeaderTableSize, set that in Transport
	Settings []http2Setting

	// StrictMaxConcurrentStreams controls whether the server's
	// SETTINGS_MAX_CONCURRENT_STREAMS should be respected
	// globally. If false, new TCP connections are created to the
	// server as needed to keep each under the per-connection
	// SETTINGS_MAX_CONCURRENT_STREAMS limit. If true, the
	// server's SETTINGS_MAX_CONCURRENT_STREAMS is interpreted as
	// a global limit and callers of RoundTrip block when needed,
	// waiting for their turn.
	StrictMaxConcurrentStreams bool

	// t1, if non-nil, is the standard library Transport using
	// this transport. Its settings are used (but not its
	// RoundTrip method, etc).
	t1 *Transport

	// TLSClientConfig specifies the TLS configuration to use with
	// tls.Client. If nil, the default configuration is used.
	TLSClientConfig *tls.Config
}

func (t *http2Transport) dialClientConn(addr string, singleUse bool) (*http2ClientConn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	tconn, err := t.dialTLS()("tcp", addr, t.newTLSConfig(host))
	if err != nil {
		return nil, err
	}

	return t.newClientConn(tconn, addr, singleUse)
}

func (t *http2Transport) newTLSConfig(host string) *tls.Config {
	cfg := new(tls.Config)
	if t.TLSClientConfig != nil {
		*cfg = *t.TLSClientConfig.Clone()
	}
	if !http2strSliceContains(cfg.NextProtos, http2NextProtoTLS) {
		cfg.NextProtos = append([]string{http2NextProtoTLS}, cfg.NextProtos...)
	}
	if cfg.ServerName == "" {
		cfg.ServerName = host
	}

	return cfg
}

func (t *http2Transport) dialTLS() func(string, string, *tls.Config) (net.Conn, error) {
	if t.DialTLS != nil {
		return t.DialTLS
	}

	return t.dialTLSDefault
}

func (t *http2Transport) dialTLSDefault(network, addr string, cfg *tls.Config) (net.Conn, error) {
	cn, err := tls.Dial(network, addr, cfg)
	if err != nil {
		return nil, err
	}
	if err := cn.Handshake(); err != nil {
		return nil, err
	}
	if !cfg.InsecureSkipVerify {
		if err := cn.VerifyHostname(cfg.ServerName); err != nil {
			return nil, err
		}
	}
	state := cn.ConnectionState()
	if p := state.NegotiatedProtocol; p != http2NextProtoTLS {
		return nil, fmt.Errorf("http2: unexpected ALPN protocol %q; want %q", p, http2NextProtoTLS)
	}
	if !state.NegotiatedProtocolIsMutual {
		return nil, errors.New("http2: could not negotiate protocol mutually")
	}

	return cn, nil
}

// disableKeepAlives reports whether connections should be closed as
// soon as possible after handling the first request.
func (t *http2Transport) disableKeepAlives() bool {
	return t.t1 != nil && t.t1.DisableKeepAlives
}

func (t *http2Transport) expectContinueTimeout() time.Duration {
	if t.t1 == nil {
		return 0
	}

	return t.t1.ExpectContinueTimeout
}

func (t *http2Transport) NewClientConn(c net.Conn) (*http2ClientConn, error) {
	return t.newClientConn(c, "", t.disableKeepAlives())
}
func (t *http2Transport) idleConnTimeout() time.Duration {
	if t.t1 != nil {
		return t.t1.IdleConnTimeout
	}

	return 0
}

func (t *http2Transport) newClientConn(c net.Conn, addr string, singleUse bool) (*http2ClientConn, error) {
	cc := &http2ClientConn{
		t:                     t,
		tconn:                 c,
		dialedAddr:            addr,
		readerDone:            make(chan struct{}),
		nextStreamID:          1,
		maxFrameSize:          16 << 10,           // spec default
		initialWindowSize:     65535,              // spec default
		maxConcurrentStreams:  1000,               // "infinite", per spec. 1000 seems good enough.
		peerMaxHeaderListSize: 0xffffffffffffffff, // "infinite", per spec. Use 2^64-1 instead.
		streams:               make(map[uint32]*http2clientStream),
		singleUse:             singleUse,
		wantSettingsAck:       true,
		pings:                 make(map[[8]byte]chan struct{}),
	}
	if d := t.idleConnTimeout(); d != 0 {
		cc.idleTimeout = d
		cc.idleTimer = time.AfterFunc(d, cc.onIdleTimeout)
	}
	if http2VerboseLogs {
		t.vlogf("http2: Transport creating client conn %p to %v", cc, c.RemoteAddr())
	}

	cc.cond = sync.NewCond(&cc.mu)
	cc.flow.add(int32(http2initialWindowSize))

	// TODO: adjust this writer size to account for frame size +
	// MTU + crypto/tls record padding.
	cc.bw = bufio.NewWriter(http2stickyErrWriter{&cc.werr, c})
	cc.br = bufio.NewReader(c)
	cc.fr = http2NewFramer(cc.bw, cc.br)
	if t.HeaderTableSize != 0 {
		cc.fr.ReadMetaHeaders = hpack.NewDecoder(t.HeaderTableSize, nil)
	} else {
		cc.fr.ReadMetaHeaders = hpack.NewDecoder(http2initialHeaderTableSize, nil)
	}
	cc.fr.MaxHeaderListSize = t.maxHeaderListSize()

	// TODO: SetMaxDynamicTableSize, SetMaxDynamicTableSizeLimit on
	// henc in response to SETTINGS frames?
	cc.henc = hpack.NewEncoder(&cc.hbuf)

	if t.AllowHTTP {
		cc.nextStreamID = 3
	}

	if cs, ok := c.(http2connectionStater); ok {
		state := cs.ConnectionState()
		cc.tlsState = &state
	}

	initialSettings := []http2Setting{}

	var pushEnabled uint32
	if t.PushHandler != nil {
		pushEnabled = 1
	}
	initialSettings = append(initialSettings, http2Setting{ID: http2SettingEnablePush, Val: pushEnabled})

	setMaxHeader := false
	if t.Settings != nil {
		for _, setting := range t.Settings {
			if setting.ID == http2SettingMaxHeaderListSize {
				setMaxHeader = true
			}
			if setting.ID == http2SettingHeaderTableSize || setting.ID == http2SettingInitialWindowSize {
				return nil, http2errSettingsIncludeIllegalSettings
			}
			initialSettings = append(initialSettings, setting)
		}
	}
	if t.InitialWindowSize != 0 {
		initialSettings = append(initialSettings, http2Setting{ID: http2SettingInitialWindowSize, Val: t.InitialWindowSize})
	} else {
		initialSettings = append(initialSettings, http2Setting{ID: http2SettingInitialWindowSize, Val: http2transportDefaultStreamFlow})
	}
	if t.HeaderTableSize != 0 {
		initialSettings = append(initialSettings, http2Setting{ID: http2SettingHeaderTableSize, Val: t.HeaderTableSize})
	} else {
		initialSettings = append(initialSettings, http2Setting{ID: http2SettingHeaderTableSize, Val: http2initialHeaderTableSize})
	}
	if max := t.maxHeaderListSize(); max != 0 && !setMaxHeader {
		initialSettings = append(initialSettings, http2Setting{ID: http2SettingMaxHeaderListSize, Val: max})
	}

	cc.bw.Write(http2clientPreface)
	cc.fr.WriteSettings(initialSettings...)
	cc.fr.WriteWindowUpdate(0, http2transportDefaultConnFlow)
	cc.inflow.add(http2transportDefaultConnFlow + http2initialWindowSize)
	cc.bw.Flush()
	if cc.werr != nil {
		cc.Close()

		return nil, cc.werr
	}

	go cc.readLoop()

	return cc, nil
}

const (
	// ClientPreface is the string that must be sent by new
	// connections from clients.
	http2ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

	http2defaultMaxReadFrameSize = 1 << 20

	// http://http2.github.io/http2-spec/#SettingValues
	http2initialHeaderTableSize = 4096

	// SETTINGS_MAX_FRAME_SIZE default
	// http://http2.github.io/http2-spec/#rfc.section.6.5.2
	http2initialMaxFrameSize = 16384

	http2initialWindowSize = 65535 // 6.9.2 Initial Flow Control Window Size

	// NextProtoTLS is the NPN/ALPN protocol negotiated during
	// HTTP/2's TLS setup.
	http2NextProtoTLS = "h2"
)

func http2strSliceContains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}

	return false
}

type http2noDialH2RoundTripper struct{ *http2Transport }

func (rt http2noDialH2RoundTripper) RoundTrip(req *Request) (*Response, error) {
	res, err := rt.http2Transport.RoundTrip(req)
	if http2isNoCachedConnError(err) {
		return nil, ErrSkipAltProtocol
	}

	return res, err
}

type http2RoundTripOpt struct {
	// OnlyCachedConn controls whether RoundTripOpt may
	// create a new TCP connection. If set true and
	// no cached connection is available, RoundTripOpt
	// will return ErrNoCachedConn.
	OnlyCachedConn bool
}

func http2authorityHostPort(scheme string, authority string) (host, port string) {
	host, port, err := net.SplitHostPort(authority)
	if err != nil { // authority didn't have a port
		port = "443"
		if scheme == "http" {
			port = "80"
		}
		host = authority
	}
	if a, err := idna.ToASCII(host); err == nil {
		host = a
	}

	return
}
func http2authorityAddr(scheme string, authority string) (addr string) {
	host, port := http2authorityHostPort(scheme, authority)
	// IPv6 address literal, without a port:
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return host + ":" + port
	}

	return net.JoinHostPort(host, port)
}
func (t *http2Transport) vlogf(format string, args ...interface{}) {
	if http2VerboseLogs {
		t.logf(format, args...)
	}
}
func (t *http2Transport) logf(format string, args ...interface{}) {
	log.Printf(format, args...)
}
func (t *http2Transport) connPool() http2ClientConnPool {
	t.connPoolOnce.Do(t.initConnPool)

	return t.connPoolOrDef
}
func (t *http2Transport) initConnPool() {
	if t.ConnPool != nil {
		t.connPoolOrDef = t.ConnPool
	} else {
		t.connPoolOrDef = &http2clientConnPool{t: t}
	}
}
func (t *http2Transport) RoundTrip(req *Request) (*Response, error) {
	return t.RoundTripOpt(req, http2RoundTripOpt{})
}
func (t *http2Transport) RoundTripOpt(req *Request, opt http2RoundTripOpt) (*Response, error) {
	if !(req.URL.Scheme == "https" || (req.URL.Scheme == "http" && t.AllowHTTP)) {
		return nil, errors.New("http2: unsupported scheme")
	}

	addr := http2authorityAddr(req.URL.Scheme, req.URL.Host)
	for retry := 0; ; retry++ {
		cc, err := t.connPool().GetClientConn(req, addr)
		if err != nil {
			t.vlogf("http2: Transport failed to get client conn for %s: %v", addr, err)

			return nil, err
		}
		reused := !atomic.CompareAndSwapUint32(&cc.reused, 0, 1)
		http2traceGotConn(req, cc, reused)
		res, gotErrAfterReqBodyWrite, err := cc.roundTrip(req)
		if err != nil && retry <= 6 {
			if req, err = http2shouldRetryRequest(req, err, gotErrAfterReqBodyWrite); err == nil {
				// After the first retry, do exponential backoff with 10% jitter.
				if retry == 0 {
					continue
				}
				backoff := float64(uint(1) << (uint(retry) - 1))
				backoff += backoff * (0.1 * mathrand.Float64())
				select {
				case <-time.After(time.Second * time.Duration(backoff)):
					continue
				case <-req.Context().Done():
					return nil, req.Context().Err()
				}
			}
		}
		if err != nil {
			t.vlogf("RoundTrip failure: %v", err)

			return nil, err
		}

		return res, nil
	}
}

type http2addConnCall struct {
	_    http2incomparable
	done chan struct{} // closed when done
	err  error
	p    *http2clientConnPool
}

func (c *http2addConnCall) run(t *http2Transport, key string, tc *tls.Conn) {
	cc, err := t.NewClientConn(tc)

	p := c.p
	p.mu.Lock()
	if err != nil {
		c.err = err
	} else {
		p.addConnLocked(key, cc)
	}
	delete(p.addConnCalls, key)
	p.mu.Unlock()
	close(c.done)
}

type http2dialCall struct {
	_    http2incomparable
	done chan struct{} // closed when done
	err  error         // valid after done is closed
	p    *http2clientConnPool
	res  *http2ClientConn // valid after done is closed
}

func (c *http2dialCall) dial(addr string) {
	const singleUse = false // shared conn
	c.res, c.err = c.p.t.dialClientConn(addr, singleUse)
	close(c.done)

	c.p.mu.Lock()
	delete(c.p.dialing, addr)
	if c.err == nil {
		c.p.addConnLocked(addr, c.res)
	}
	c.p.mu.Unlock()
}

// TODO: use singleflight for dialing and addConnCalls?
type http2clientConnPool struct {
	addConnCalls map[string]*http2addConnCall // in-flight addConnIfNeede calls
	// TODO: add support for sharing conns based on cert names
	// (e.g. share conn for googleapis.com and appspot.com)
	conns   map[string][]*http2ClientConn // key is host:port
	dialing map[string]*http2dialCall     // currently in-flight dials
	keys    map[*http2ClientConn][]string

	mu sync.Mutex // TODO: maybe switch to RWMutex
	t  *http2Transport
}

func (p *http2clientConnPool) addConnIfNeeded(key string, t *http2Transport, c *tls.Conn) (used bool, err error) {
	p.mu.Lock()
	for _, cc := range p.conns[key] {
		if cc.CanTakeNewRequest() {
			p.mu.Unlock()

			return false, nil
		}
	}
	call, dup := p.addConnCalls[key]
	if !dup {
		if p.addConnCalls == nil {
			p.addConnCalls = make(map[string]*http2addConnCall)
		}
		call = &http2addConnCall{
			p:    p,
			done: make(chan struct{}),
		}
		p.addConnCalls[key] = call
		go call.run(t, key, c)
	}
	p.mu.Unlock()

	<-call.done
	if call.err != nil {
		return false, call.err
	}

	return !dup, nil
}
func (p *http2clientConnPool) GetClientConn(req *Request, addr string) (*http2ClientConn, error) {
	return p.getClientConn(req, addr, http2dialOnMiss)
}
func (p *http2clientConnPool) addConnLocked(key string, cc *http2ClientConn) {
	for _, v := range p.conns[key] {
		if v == cc {
			return
		}
	}
	if p.conns == nil {
		p.conns = make(map[string][]*http2ClientConn)
	}
	if p.keys == nil {
		p.keys = make(map[*http2ClientConn][]string)
	}
	p.conns[key] = append(p.conns[key], cc)
	p.keys[cc] = append(p.keys[cc], key)
}

func (p *http2clientConnPool) MarkDead(cc *http2ClientConn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, key := range p.keys[cc] {
		vv, ok := p.conns[key]
		if !ok {
			continue
		}
		newList := http2filterOutClientConn(vv, cc)
		if len(newList) > 0 {
			p.conns[key] = newList
		} else {
			delete(p.conns, key)
		}
	}
	delete(p.keys, cc)
}

func (p *http2clientConnPool) closeIdleConnections() {
	p.mu.Lock()
	defer p.mu.Unlock()
	// TODO: don't close a cc if it was just added to the pool
	// milliseconds ago and has never been used. There's currently
	// a small race window with the HTTP/1 Transport's integration
	// where it can add an idle conn just before using it, and
	// somebody else can concurrently call CloseIdleConns and
	// break some caller's RoundTrip.
	for _, vv := range p.conns {
		for _, cc := range vv {
			cc.closeIfIdle()
		}
	}
}

const (
	http2dialOnMiss   = true
	http2noDialOnMiss = false
)

type http2clientConnIdleState struct {
	canTakeNewRequest bool
	freshConn         bool // whether it's unused by any previous request
}
type http2noDialClientConnPool struct{ *http2clientConnPool }

func (p http2noDialClientConnPool) GetClientConn(req *Request, addr string) (*http2ClientConn, error) {
	return p.getClientConn(req, addr, http2noDialOnMiss)
}

// shouldTraceGetConn reports whether getClientConn should call any
// ClientTrace.GetConn hook associated with the http.Request.
//
// This complexity is needed to avoid double calls of the GetConn hook
// during the back-and-forth between net/http and x/net/http2 (when the
// net/http.Transport is upgraded to also speak http2), as well as support
// the case where x/net/http2 is being used directly.
func (p *http2clientConnPool) shouldTraceGetConn(st http2clientConnIdleState) bool {
	// If our Transport wasn't made via ConfigureTransport, always
	// trace the GetConn hook if provided, because that means the
	// http2 package is being used directly and it's the one
	// dialing, as opposed to net/http.
	if _, ok := p.t.ConnPool.(http2noDialClientConnPool); !ok {
		return true
	}

	// Otherwise, only use the GetConn hook if this connection has
	// been used previously for other requests. For fresh
	// connections, the net/http package does the dialing.
	return !st.freshConn
}
func http2traceGetConn(req *Request, hostPort string) {
	trace := httptrace.ContextClientTrace(req.Context())
	if trace == nil || trace.GetConn == nil {
		return
	}
	trace.GetConn(hostPort)
}
func http2isConnectionCloseRequest(req *Request) bool {
	return req.Close || httpguts.HeaderValuesContainsToken(req.Header["Connection"], "close")
}

func (p *http2clientConnPool) getClientConn(req *Request, addr string, dialOnMiss bool) (*http2ClientConn, error) {
	if http2isConnectionCloseRequest(req) && dialOnMiss {
		// It gets its own connection.
		http2traceGetConn(req, addr)
		const singleUse = true
		cc, err := p.t.dialClientConn(addr, singleUse)
		if err != nil {
			return nil, err
		}

		return cc, nil
	}
	p.mu.Lock()
	for _, cc := range p.conns[addr] {
		if st := cc.idleState(); st.canTakeNewRequest {
			if p.shouldTraceGetConn(st) {
				http2traceGetConn(req, addr)
			}
			p.mu.Unlock()

			return cc, nil
		}
	}
	if !dialOnMiss {
		p.mu.Unlock()

		return nil, http2ErrNoCachedConn
	}
	http2traceGetConn(req, addr)
	call := p.getStartDialLocked(addr)
	p.mu.Unlock()
	<-call.done

	return call.res, call.err
}

func http2filterOutClientConn(in []*http2ClientConn, exclude *http2ClientConn) []*http2ClientConn {
	out := in[:0]
	for _, v := range in {
		if v != exclude {
			out = append(out, v)
		}
	}
	// If we filtered it out, zero out the last item to prevent
	// the GC from seeing it.
	if len(in) != len(out) {
		in[len(in)-1] = nil
	}

	return out
}
