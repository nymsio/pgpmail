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

type KeyRing struct {
	pubkeys openpgp.EntityList
	seckeys openpgp.EntityList
}

func (kr *KeyRing) AddPublicKey(k *openpgp.Entity) {
	kr.pubkeys = append(kr.pubkeys, k)
}

func (kr *KeyRing) AddSecretKey(k *openpgp.Entity) {
	kr.seckeys = append(kr.seckeys, k)
}

func (kr *KeyRing) GetPublicKeyRing() openpgp.EntityList {
	return kr.pubkeys
}

func (kr *KeyRing) GetPublicKey(address string) (*openpgp.Entity, error) {
	return firstKeyByEmail(address, kr.pubkeys), nil
}

func (kr *KeyRing) GetAllPublicKeys(address string) (openpgp.EntityList, error) {
	return keysByEmail(address, kr.pubkeys), nil
}

func (kr *KeyRing) GetPublicKeyById(keyid uint64) *openpgp.Entity {
	return keyById(keyid, kr.pubkeys)
}

func (kr *KeyRing) GetSecretKeyRing() openpgp.EntityList {
	return kr.seckeys
}

func (kr *KeyRing) GetSecretKey(address string) (*openpgp.Entity, error) {
	return firstKeyByEmail(address, kr.seckeys), nil
}

func (kr *KeyRing) GetAllSecretKeys(address string) (openpgp.EntityList, error) {
	return keysByEmail(address, kr.seckeys), nil
}

func (kr *KeyRing) GetSecretKeyById(keyid uint64) *openpgp.Entity {
	return keyById(keyid, kr.seckeys)
}

func keyById(keyid uint64, keys openpgp.EntityList) *openpgp.Entity {
	ks := keys.KeysById(keyid)
	if len(ks) == 0 {
		return nil
	}
	return ks[0].Entity
}

func firstKeyByEmail(email string, keys openpgp.EntityList) *openpgp.Entity {
	ks := keysByEmail(email, keys)
	if len(ks) == 0 {
		return nil
	}
	return ks[0]
}

func keysByEmail(email string, keys openpgp.EntityList) openpgp.EntityList {
	var matching openpgp.EntityList
	for _, e := range keys {
		if matchesEmail(email, e) {
			matching = append(matching, e)
		}
	}
	return matching
}

func matchesEmail(email string, e *openpgp.Entity) bool {
	for _, v := range e.Identities {
		if v.UserId.Email == email {
			return true
		}
	}
	return false
}

func createBodyMimePart(m *Message) *MessagePart {
	p := new(MessagePart)
	p.Body = m.Body
	moveHeader(m, p, ctHeader, "text/plain")
	moveHeader(m, p, cteHeader, "")
	p.rawContent = []byte(p.String())
	return p
}

func moveHeader(from *Message, to *MessagePart, name, defaultValue string) {
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
