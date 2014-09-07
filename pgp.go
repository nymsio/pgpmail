package pgpmail

import (
	"strings"

	"code.google.com/p/go.crypto/openpgp"
	gl "github.com/op/go-logging"
)

var logger = gl.MustGetLogger("pgpmail")

type KeySource interface {
	GetPublicKeyRing() openpgp.EntityList
	GetPublicKey(address string) (*openpgp.Entity, error)
	GetAllPublicKeys(address string) (openpgp.EntityList, error)
	GetPublicKeyById(keyid uint64) *openpgp.Entity

	GetSecretKey(address string) (*openpgp.Entity, error)
	GetAllSecretKeys(address string) (openpgp.EntityList, error)
	GetSecretKeyById(keyid uint64) *openpgp.Entity
	GetSecretKeyRing() openpgp.EntityList
}

func createBodyMimePart(m *Message) *messagePart {
	p := new(messagePart)
	p.Body = m.Body
	moveHeader(m, p, ctHeader, "text/plain")
	moveHeader(m, p, cteHeader, "")
	p.rawContent = []byte(p.String())
	return p
}

func moveHeader(from *Message, to *messagePart, name, defaultValue string) {
	if h := from.RemoveHeader(name); h != "" {
		to.AddHeader(name, h)
	} else if defaultValue != "" {
		to.AddHeader(name, defaultValue)
	}
}

func insertCR(s string) string {
	lines := []string{}
	for _, crlfLine := range strings.Split(s, "\r\n") {
		for _, line := range strings.Split(crlfLine, "\n") {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, "\r\n")
}
