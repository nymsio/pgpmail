package pgpmail

import (
	"bytes"
	"errors"
	"fmt"
	"net/mail"
	"time"

	"code.google.com/p/go.crypto/openpgp"
	"code.google.com/p/go.crypto/openpgp/armor"
)

const (
	StatusNone = iota
	StatusSignedOnly
	StatusEncryptedOnly
	StatusSignedAndEncrypted
	StatusFailedNoSignKey
	StatusFailedPassphraseNeeded
	StatusFailedNeedPubkeys
	StatusFailed
)

type EncryptStatus struct {
	Code           int
	MissingKeys    []string
	FailureMessage string
	Message        *Message
}

func (m *Message) Encrypt(keysrc KeySource) *EncryptStatus {
	return encryptMessage(m, keysrc, false, "")
}

func (m *Message) EncryptAndSign(keysrc KeySource, passphrase string) *EncryptStatus {
	return encryptMessage(m, keysrc, true, passphrase)
}

func createEncryptFailure(msg string) *EncryptStatus {
	status := new(EncryptStatus)
	status.Code = StatusFailed
	status.FailureMessage = msg
	return status
}

func encryptMessage(m *Message, keysrc KeySource, sign bool, passphrase string) *EncryptStatus {
	as := getRecipientAddresses(m)
	if len(as) == 0 {
		return createEncryptFailure("cannot encrypt message, no recipients")
	}
	pubkeys, err := getRecipientKeys(keysrc, as)
	if err != nil {
		return createEncryptFailure(err.Error())
	}
	if sign {
		return encryptAndSignMessage(m, pubkeys, keysrc, passphrase)
	}
	return encryptWith(m, pubkeys, nil, "")
}

func encryptAndSignMessage(m *Message, pubkeys openpgp.EntityList, keysrc KeySource, passphrase string) *EncryptStatus {
	if !useCombinedSignatures {
		st := m.Sign(keysrc, passphrase)
		if st.Code != StatusSignedOnly {
			return st
		}
		st = encryptWith(m, pubkeys, nil, "")
		if st.Code == StatusEncryptedOnly {
			st.Code = StatusSignedAndEncrypted
		}
		return st
	}
	signingKey, err := getSigningKey(m, keysrc)
	if err != nil {
		if _, ok := err.(NoSignaturePrivateKeyError); ok {
			return &EncryptStatus{Code: StatusFailedNoSignKey}
		}
		return createEncryptFailure(err.Error())
	}
	return encryptWith(m, pubkeys, signingKey, passphrase)
}

func getRecipientKeys(keysrc KeySource, addresses []string) ([]*openpgp.Entity, error) {
	var missing []string
	pubkeys := []*openpgp.Entity{}
	for _, a := range addresses {
		k, err := keysrc.GetPublicKey(a)
		if err != nil {
			return nil, errors.New("error looking up recipient key '" + a + "': " + err.Error())
		}
		if k == nil {
			missing = append(missing, a)
		} else {
			pubkeys = append(pubkeys, k)
		}
	}
	if len(missing) > 0 {
		return nil, PublicKeysNeededError{missing}
	}
	return pubkeys, nil
}

var recipientHeaders = []string{"To", "Cc", "Bcc"}

func getRecipientAddresses(m *Message) []string {
	as := []string{}
	for _, hName := range recipientHeaders {
		for _, hVal := range m.GetHeaders(hName) {
			addrs, err := mail.ParseAddressList(hVal)
			if err == nil {
				for _, addr := range addrs {
					as = append(as, addr.Address)
				}
			}
		}
	}
	if encryptToSelf {
		self := getSenderAddress(m)
		if self == "" {
			logger.Warning("Was unable to determine sender address while compiling recipient key list")
		} else {
			as = append(as, self)
		}
	}
	return as
}

func encryptWith(m *Message, pubkeys openpgp.EntityList, signingEntity *openpgp.Entity, passphrase string) *EncryptStatus {
	if len(pubkeys) == 0 {
		return createEncryptFailure("no recipient keys")
	}
	buffer := new(bytes.Buffer)
	ar, err := armor.Encode(buffer, "PGP MESSAGE", nil)
	if err != nil {
		return createEncryptFailure("error encoding output message: " + err.Error())
	}
	if signingEntity.PrivateKey == nil {
		return createEncryptFailure("signing key has no private key")
	}
	if signingEntity != nil && isSigningKeyLocked(signingEntity, passphrase) {
		return &EncryptStatus{Code: StatusFailedPassphraseNeeded}
	}
	w, err := openpgp.Encrypt(ar, pubkeys, signingEntity, nil, openpgpConfig)
	if err != nil {
		return createEncryptFailure("encryption operation failed: " + err.Error())
	}
	bodyPart := createBodyMimePart(m)
	w.Write(bodyPart.rawContent)
	w.Close()
	ar.Close()
	buffer.WriteString("\n")
	err = writeEncryptedMimeBody(m, buffer.Bytes())
	if err != nil {
		return createEncryptFailure(err.Error())
	}
	if signingEntity != nil {
		return &EncryptStatus{Code: StatusSignedAndEncrypted, Message: m}
	} else {
		return &EncryptStatus{Code: StatusEncryptedOnly, Message: m}
	}
}

func isSigningKeyLocked(e *openpgp.Entity, passphrase string) bool {
	sk, ok := signingKey(e, openpgpConfig.Now())
	// if !ok then openpgp.Encrypt() is going to fail and return the right error
	if !ok || !sk.PrivateKey.Encrypted {
		return false
	}
	err := sk.PrivateKey.Decrypt([]byte(passphrase))
	return err != nil
}

// signingKey return the best candidate Key for signing a message with this
// Entity.
func signingKey(e *openpgp.Entity, now time.Time) (openpgp.Key, bool) {
	candidateSubkey := -1

	for i, subkey := range e.Subkeys {
		if subkey.Sig.FlagsValid &&
			subkey.Sig.FlagSign &&
			subkey.PublicKey.PubKeyAlgo.CanSign() &&
			!subkey.Sig.KeyExpired(now) {
			candidateSubkey = i
			break
		}
	}

	if candidateSubkey != -1 {
		subkey := e.Subkeys[candidateSubkey]
		return openpgp.Key{e, subkey.PublicKey, subkey.PrivateKey, subkey.Sig}, true
	}

	// If we have no candidate subkey then we assume that it's ok to sign
	// with the primary key.
	i := primaryIdentity(e)
	if !i.SelfSignature.FlagsValid || i.SelfSignature.FlagSign &&
		!i.SelfSignature.KeyExpired(now) {
		return openpgp.Key{e, e.PrimaryKey, e.PrivateKey, i.SelfSignature}, true
	}

	return openpgp.Key{}, false
}

// primaryIdentity returns the Identity marked as primary or the first identity
// if none are so marked.
func primaryIdentity(e *openpgp.Entity) *openpgp.Identity {
	var firstIdentity *openpgp.Identity
	for _, ident := range e.Identities {
		if firstIdentity == nil {
			firstIdentity = ident
		}
		if ident.SelfSignature.IsPrimaryId != nil && *ident.SelfSignature.IsPrimaryId {
			return ident
		}
	}
	return firstIdentity
}

func writeEncryptedMimeBody(m *Message, encryptedBody []byte) error {
	boundary := randomBoundary()
	ct := fmt.Sprintf("multipart/encrypted; boundary=%s; protocol=\"application/pgp-encrypted\"", boundary)
	m.AddHeader(ctHeader, ct)
	m.parseContentType()
	m.mpContent = createEncryptedMultipart(boundary, encryptedBody)
	if err := m.PackMultiparts(); err != nil {
		return errors.New("failed writing multipart/encrypted body: " + err.Error())
	}
	return nil
}

func createEncryptedMultipart(boundary string, encryptedBody []byte) *multipartContent {
	const preamble = "This is an OpenPGP/MIME encrypted message (RFC 4880 and 3156)\r\n"
	mp := newMultipartContent(boundary, preamble)
	mp.addPart(createVersionMimePart())
	mp.addPart(createEncryptedMimePart(encryptedBody))
	return mp
}

func createVersionMimePart() *MessagePart {
	p := new(MessagePart)
	const contentType = "application/pgp-encrypted"
	const description = "PGP/MIME version identification"
	p.AddHeader(ctHeader, contentType)
	p.AddHeader("Content-Description", description)
	p.Body = "Version: 1\r\n"
	return p
}

func createEncryptedMimePart(encryptedBody []byte) *MessagePart {
	p := new(MessagePart)
	const contentType = "application/octet-stream; name=\"encrypted.asc\""
	const description = "OpenPGP encrypted message"
	const disposition = "inline; filename=\"encrypted.asc\""
	p.AddHeader(ctHeader, contentType)
	p.AddHeader("Content-Description", description)
	p.AddHeader("Content-Disposition", disposition)
	p.Body = insertCR(string(encryptedBody))
	return p
}
