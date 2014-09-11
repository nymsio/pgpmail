package pgpmail

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"mime"
	"strings"
)

type ProtocolError string

func (p ProtocolError) Error() string {
	return string(p)
}

type Reader struct {
	content []byte
	R       *bufio.Reader
	buf     []byte
}

func NewReader(s string) *Reader {
	sr := strings.NewReader(s)
	br := bufio.NewReader(sr)
	return &Reader{content: []byte(s), R: br, buf: nil}
}

func (r *Reader) ReadMessage() (*Message, error) {
	hs, err := r.ReadMIMEHeader()
	if err != nil {
		return nil, err
	}
	body, err := r.R.ReadBytes(0)
	if err != io.EOF {
		return nil, errors.New("Message body contained embedded null character")
	}
	m := new(Message)
	m.rawContent = r.content
	m.HeaderList = hs
	m.Body = string(body)
	m.parseContentType()
	if m.IsMultipart() {
		m.extractMultiparts()
	}
	return m, nil
}

func (r *Reader) ReadMessagePart() (*MessagePart, error) {
	part := new(MessagePart)
	if err := r.populatePart(part); err != nil {
		return nil, err
	}
	part.rawContent = r.content
	return part, nil
}

func (r *Reader) populatePart(part *MessagePart) error {
	hs, err := r.ReadMIMEHeader()
	if err != nil {
		return err
	}
	body, err := r.R.ReadBytes(0)
	if err != io.EOF {
		return errors.New("Message body contained embedded null character")
	}
	part.HeaderList = hs
	part.Body = string(body)
	return nil
}

func (m *Message) parseContentType() {
	ct := m.GetHeaderValue(ctHeader)
	if ct == "" {
		return
	}
	mt, ps, err := mime.ParseMediaType(ct)
	if err != nil {
		logger.Warning("Error parsing content type '" + ct + "' : " + err.Error())
		return
	}
	idx := strings.Index(mt, "/")
	if idx == -1 {
		logger.Warning("Malformed media type: " + mt)
		return
	}
	m.ctPrimary = mt[:idx]
	m.ctSecondary = mt[idx+1:]
	m.ctParams = ps
}

func (r *Reader) ReadMIMEHeader() ([]*Header, error) {

	var hs []*Header
	for {
		kv, err := r.readContinuedLineSlice()
		if len(kv) == 0 {
			return hs, err
		}

		// Key ends at first colon; should not have spaces but
		// they appear in the wild, violating specs, so we
		// remove them if present.
		i := bytes.IndexByte(kv, ':')
		if i < 0 {
			return hs, ProtocolError("malformed MIME header line: " + string(kv))
		}
		endKey := i
		for endKey > 0 && kv[endKey-1] == ' ' {
			endKey--
		}
		key := canonicalMIMEHeaderKey(kv[:endKey])

		// Skip initial spaces in value.
		i++ // skip colon
		for i < len(kv) && (kv[i] == ' ' || kv[i] == '\t') {
			i++
		}
		value := string(kv[i:])

		hs = append(hs, &Header{key, value})

		if err != nil {
			return hs, err
		}
	}
}

func (r *Reader) readContinuedLineSlice() ([]byte, error) {
	// Read the first line.
	line, err := r.readLineSlice()
	if err != nil {
		return nil, err
	}
	if len(line) == 0 { // blank line - no continuation
		return line, nil
	}

	// Optimistically assume that we have started to buffer the next line
	// and it starts with an ASCII letter (the next header key), so we can
	// avoid copying that buffered data around in memory and skipping over
	// non-existent whitespace.
	if r.R.Buffered() > 1 {
		peek, err := r.R.Peek(1)
		if err == nil && isASCIILetter(peek[0]) {
			return trim(line), nil
		}
	}

	// ReadByte or the next readLineSlice will flush the read buffer;
	// copy the slice into buf.
	r.buf = append(r.buf[:0], trim(line)...)

	// Read continuation lines.
	for r.skipSpace() > 0 {
		line, err := r.readLineSlice()
		if err != nil {
			break
		}
		r.buf = append(r.buf, ' ')
		r.buf = append(r.buf, line...)
	}
	return r.buf, nil
}

// skipSpace skips R over all spaces and returns the number of bytes skipped.
func (r *Reader) skipSpace() int {
	n := 0
	for {
		c, err := r.R.ReadByte()
		if err != nil {
			// Bufio will keep err until next read.
			break
		}
		if c != ' ' && c != '\t' {
			r.R.UnreadByte()
			break
		}
		n++
	}
	return n
}

// trim returns s with leading and trailing spaces and tabs removed.
// It does not assume Unicode or UTF-8.
func trim(s []byte) []byte {
	i := 0
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	n := len(s)
	for n > i && (s[n-1] == ' ' || s[n-1] == '\t') {
		n--
	}
	return s[i:n]
}

func isASCIILetter(b byte) bool {
	b |= 0x20 // make lower case
	return 'a' <= b && b <= 'z'
}

func (r *Reader) readLineSlice() ([]byte, error) {
	var line []byte
	for {
		l, more, err := r.R.ReadLine()
		if err != nil {
			return nil, err
		}
		// Avoid the copy if the first call produced a full line.
		if line == nil && !more {
			return l, nil
		}
		line = append(line, l...)
		if !more {
			break
		}
	}
	return line, nil
}

// CanonicalMIMEHeaderKey returns the canonical format of the
// MIME header key s.  The canonicalization converts the first
// letter and any letter following a hyphen to upper case;
// the rest are converted to lowercase.  For example, the
// canonical key for "accept-encoding" is "Accept-Encoding".
// MIME header keys are assumed to be ASCII only.
func CanonicalMIMEHeaderKey(s string) string {
	// Quick check for canonical encoding.
	upper := true
	for i := 0; i < len(s); i++ {
		c := s[i]
		if upper && 'a' <= c && c <= 'z' {
			return canonicalMIMEHeaderKey([]byte(s))
		}
		if !upper && 'A' <= c && c <= 'Z' {
			return canonicalMIMEHeaderKey([]byte(s))
		}
		upper = c == '-'
	}
	return s
}

const toLower = 'a' - 'A'

// canonicalMIMEHeaderKey is like CanonicalMIMEHeaderKey but is
// allowed to mutate the provided byte slice before returning the
// string.
func canonicalMIMEHeaderKey(a []byte) string {
	// Look for it in commonHeaders , so that we can avoid an
	// allocation by sharing the strings among all users
	// of textproto. If we don't find it, a has been canonicalized
	// so just return string(a).
	upper := true
	lo := 0
	hi := len(commonHeaders)
	for i := 0; i < len(a); i++ {
		// Canonicalize: first letter upper case
		// and upper case after each dash.
		// (Host, User-Agent, If-Modified-Since).
		// MIME headers are ASCII only, so no Unicode issues.
		c := a[i]
		if c == ' ' {
			c = '-'
		} else if upper && 'a' <= c && c <= 'z' {
			c -= toLower
		} else if !upper && 'A' <= c && c <= 'Z' {
			c += toLower
		}
		a[i] = c
		upper = c == '-' // for next time

		if lo < hi {
			for lo < hi && (len(commonHeaders[lo]) <= i || commonHeaders[lo][i] < c) {
				lo++
			}
			for hi > lo && commonHeaders[hi-1][i] > c {
				hi--
			}
		}
	}
	if lo < hi && len(commonHeaders[lo]) == len(a) {
		return commonHeaders[lo]
	}
	return string(a)
}

var commonHeaders = []string{
	"Accept",
	"Accept-Charset",
	"Accept-Encoding",
	"Accept-Language",
	"Accept-Ranges",
	"Cache-Control",
	"Cc",
	"Connection",
	"Content-Id",
	"Content-Language",
	"Content-Length",
	"Content-Transfer-Encoding",
	"Content-Type",
	"Cookie",
	"Date",
	"Dkim-Signature",
	"Etag",
	"Expires",
	"From",
	"Host",
	"If-Modified-Since",
	"If-None-Match",
	"In-Reply-To",
	"Last-Modified",
	"Location",
	"Message-Id",
	"Mime-Version",
	"Pragma",
	"Received",
	"Return-Path",
	"Server",
	"Set-Cookie",
	"Subject",
	"To",
	"User-Agent",
	"Via",
	"X-Forwarded-For",
	"X-Imforwards",
	"X-Powered-By",
}
