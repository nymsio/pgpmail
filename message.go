package pgpmail

import (
	"bytes"
	"fmt"
)

var crlf = []byte("\r\n")

type Header struct {
	Name  string
	Value string
}

func (h Header) String() string {
	return fmt.Sprintf("%s: %s", h.Name, h.Value)
}

// A messagePart represents either an entire message or a multipart section.
type messagePart struct {
	rawContent []byte
	// HeaderList contains Header values in the order in which they appear in the message
	HeaderList []*Header
	Body       string
}

type Message struct {
	messagePart
	ctPrimary   string
	ctSecondary string
	ctParams    map[string]string
	mpContent   *multipartContent
}

func ParseMessage(msg string) (*Message, error) {
	return NewReader(msg).ReadMessage()
}

func (m *messagePart) String() string {
	b := new(bytes.Buffer)
	for _, h := range m.HeaderList {
		b.WriteString(h.String())
		b.Write(crlf)
	}
	b.Write(crlf)
	b.WriteString(m.Body)
	return b.String()
}

func (m *messagePart) AddHeader(name, value string) {
	key := CanonicalMIMEHeaderKey(name)
	m.HeaderList = append(m.HeaderList, &Header{key, value})
}

func (m *messagePart) SetHeader(name, value string) {
	h := m.findFirstHeader(name)
	if h == nil {
		m.AddHeader(name, value)
	} else {
		h.Value = value
	}
}

// RemoveHeader removes all headers matching name and returns Value of
// the first one discovered.  Returns "" if no such header exists
func (m *messagePart) RemoveHeader(name string) string {
	h := m.findFirstHeader(name)
	if h == nil {
		return ""
	}

	newHdrs := make([]*Header, 0, len(m.HeaderList)-1)
	key := CanonicalMIMEHeaderKey(name)
	for _, h := range m.HeaderList {
		if h.Name != key {
			newHdrs = append(newHdrs, h)
		}
	}
	m.HeaderList = newHdrs
	return h.Value
}

func (m *messagePart) GetHeaderValue(name string) string {
	h := m.findFirstHeader(name)
	if h == nil {
		return ""
	}
	return h.Value
}

func (m *messagePart) findFirstHeader(name string) *Header {
	key := CanonicalMIMEHeaderKey(name)
	for _, h := range m.HeaderList {
		if h.Name == key {
			return h
		}
	}
	return nil
}

func (m *messagePart) GetHeaders(name string) []string {
	key := CanonicalMIMEHeaderKey(name)
	ret := []string{}
	for _, h := range m.HeaderList {
		if h.Name == key {
			ret = append(ret, h.Value)
		}
	}
	return ret
}
