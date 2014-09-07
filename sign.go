package pgpmail

import (
	"bytes"
	"errors"
	"fmt"
	"net/mail"

	"crypto"

	"code.google.com/p/go.crypto/openpgp"
	"code.google.com/p/go.crypto/openpgp/packet"
)

const ctHeader = "Content-Type"
const cteHeader = "Content-Transfer-Encoding"

func (m *Message) Sign(keysrc KeySource, passphrase string) *EncryptStatus {
	signingKey, err := getSigningKey(m, keysrc)
	if err != nil {
		if _, ok := err.(NoSignaturePrivateKeyError); ok {
			return &EncryptStatus{Code: StatusFailedNoSignKey}
		}
		return createEncryptFailure(err.Error())
	}
	err = signMessage(m, passphrase, signingKey)
	if err != nil {
		if _, ok := err.(PassphraseNeededError); ok {
			return &EncryptStatus{Code: StatusFailedPassphraseNeeded}
		}
	}
	return &EncryptStatus{Code: StatusSignedOnly, Message: m}
}

func signMessage(m *Message, passphrase string, signingKey *openpgp.Entity) error {
	if isSigningKeyLocked(signingKey, passphrase) {
		var e PassphraseNeededError
		e.KeyIds = append(e.KeyIds, signingKey.PrimaryKey.KeyId)
		return e
	}
	sigBody := createBodyMimePart(m)
	sig, err := createSignature([]byte(sigBody.String()), signingKey, openpgpConfig)
	if err != nil {
		return err
	}
	return writeMimeSignatureMessage(m, sigBody, sig)
}

func getSigningKey(m *Message, keysrc KeySource) (*openpgp.Entity, error) {
	sender := getSenderAddress(m)
	if sender == "" {
		return nil, errors.New("signing failed, no sender address found")
	}
	k, err := keysrc.GetSecretKey(sender)
	if err != nil {
		return nil, errors.New("error looking up signing key: " + err.Error())
	}
	if k == nil {
		return nil, NoSignaturePrivateKeyError{sender}
	}
	return k, nil
}

func getSenderAddress(m *Message) string {
	hdr := m.GetHeaderValue("From")
	if hdr == "" {
		return ""
	}
	as, err := mail.ParseAddressList(hdr)
	if err != nil {
		logger.Warning("Failed to parse sender address " + hdr)
		return ""
	}
	if len(as) == 0 {
		return ""
	} else if len(as) > 1 {
		logger.Warning("Multiple addresses found as sender address " + hdr)
	}
	return as[0].Address
}

func hashName(hash crypto.Hash) string {
	switch hash {
	case crypto.MD5:
		return "md5"
	case crypto.RIPEMD160:
		return "ripemd160"
	case crypto.SHA1:
		return "sha1"
	case crypto.SHA224:
		return "sha224"
	case crypto.SHA256:
		return "sha256"
	case crypto.SHA384:
		return "sha384"
	case crypto.SHA512:
		return "sha512"
	}
	panic(fmt.Sprintf("unknown hash %v", hash))
}

func writeMimeSignatureMessage(m *Message, body *messagePart, sig string) error {
	b := randomBoundary()
	ct := fmt.Sprintf("multipart/signed; boundary=%s; micalg=pgp-%s; protocol=\"application/pgp-signature\"", b, hashName(openpgpConfig.Hash()))
	m.AddHeader(ctHeader, ct)
	m.parseContentType()
	m.mpContent = NewMultipartContent(b, "")
	m.mpContent.addPart(body)
	m.mpContent.addPart(createSignaturePart(sig))
	if err := m.packMultiparts(); err != nil {
		return errors.New("failed writing signature multipart: " + err.Error())
	}
	return nil
}

func createSignaturePart(sig string) *messagePart {
	p := new(messagePart)
	const contentType = "application/pgp-signature; name=\"signature.asc\""
	const description = "OpenPGP digital signature"
	const disposition = "attachment; filename=\"signature.asc\""
	p.AddHeader(ctHeader, contentType)
	p.AddHeader("Content-Description", description)
	p.AddHeader("Content-Disposition", disposition)
	p.Body = insertCR(sig)
	return p
}

func createSignature(sigBody []byte, k *openpgp.Entity, config *packet.Config) (string, error) {
	r := bytes.NewReader(sigBody)
	b := new(bytes.Buffer)
	if err := openpgp.ArmoredDetachSignText(b, k, r, config); err != nil {
		return "", err
	}
	return b.String(), nil
}
