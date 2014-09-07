package pgpmail

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

func (m *Message) IsMultipart() bool {
	return m.ctPrimary == "multipart"
}

var malformed = errors.New("malformed mime body")

type part struct {
	content []byte
}

type multipartContent struct {
	preamble []byte
	boundary []byte
	parts    []*messagePart
}

type extractState struct {
	messageBody []byte
	seenFinal   bool
	delim       []byte
	crlf        []byte
	dashes      []byte
}

var dashes = []byte("--")

func NewMultipartContent(boundary, preamble string) *multipartContent {
	mp := new(multipartContent)
	mp.preamble = []byte(preamble)
	mp.boundary = []byte(boundary)
	mp.parts = []*messagePart{}
	return mp
}

func (mp *multipartContent) addPart(p *messagePart) {
	mp.parts = append(mp.parts, p)
}

func (m *Message) extractMultiparts() error {
	body := []byte(m.Body)
	boundary, ok := m.ctParams["boundary"]
	if !ok {
		return errors.New("cannot extract multiparts, no boundary parameter")
	}
	delim := []byte("\r\n--" + boundary)
	preamble, _, err := extractPart(&body, delim[2:])
	if err != nil {
		return err
	}
	mp := NewMultipartContent(boundary, string(preamble))
	for {
		p, last, err := extractPart(&body, delim)
		if err != nil {
			return err
		}

		r := NewReader(string(p))
		part, err := r.ReadMessagePart()
		if err != nil {
			return errors.New("failed to extract multiparts: " + err.Error())
		}

		mp.parts = append(mp.parts, part)
		if last {
			m.mpContent = mp
			return nil
		}
	}
}
func (m *Message) packMultiparts() error {
	if m.mpContent == nil {
		return errors.New("not a multipart message")
	}
	m.Body = renderMultiparts(m.mpContent)
	return nil
}

func renderMultiparts(mp *multipartContent) string {
	b := new(bytes.Buffer)
	b.Write(mp.preamble)
	for _, part := range mp.parts {
		writeBoundary(b, mp.boundary, false)
		b.WriteString(part.String())
	}
	writeBoundary(b, mp.boundary, true)
	return b.String()
}

func writeBoundary(buffer *bytes.Buffer, boundary []byte, final bool) {
	if buffer.Len() > 0 {
		buffer.Write(crlf)
	}
	buffer.Write(dashes)
	buffer.Write(boundary)
	if final {
		buffer.Write(dashes)
	}
	buffer.Write(crlf)
}

func extractPart(messageBody *[]byte, delim []byte) ([]byte, bool, error) {
	body := *messageBody
	idx := bytes.Index(body, delim)
	if idx == -1 {
		return nil, false, malformed
	}
	data := body[:idx]
	idx += len(delim)
	if len(body[idx:]) < 2 {
		return nil, false, malformed
	}
	suffix := body[idx : idx+2]
	body = body[idx+2:]

	if bytes.Equal(suffix, crlf) {
		*messageBody = body
		return data, false, nil
	} else if bytes.Equal(suffix, dashes) {
		*messageBody = body
		return data, true, nil
	} else {
		return nil, false, malformed
	}
}

func randomBoundary() string {
	var buf [30]byte
	rnd := rand.Reader
	if testingRandHook != nil {
		rnd = testingRandHook
	}
	_, err := io.ReadFull(rnd, buf[:])
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", buf[:])
}
