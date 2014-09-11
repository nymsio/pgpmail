package pgpmail

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime"

	"code.google.com/p/go.crypto/openpgp"
	"code.google.com/p/go.crypto/openpgp/armor"
	"code.google.com/p/go.crypto/openpgp/clearsign"
	pgperr "code.google.com/p/go.crypto/openpgp/errors"
	"code.google.com/p/go.crypto/openpgp/packet"
)

const (
	VerifyNotSigned  = iota // No signature found
	VerifySigValid          // Signature verified correctly
	VerifySigInvalid        // Signature did not verify correctly
	VerifyKeyExpired        // Signature verified correctly, but pubkey expired
	VerifyNoPubkey          // Public key needed to verify signature is not available
	VerifyFailed            // Error processing signature
)

type VerifyStatus struct {
	Code           int
	Message        *Message
	SignerKeyId    uint64
	FailureMessage string
}

func (m *Message) Verify(keysrc KeySource) *VerifyStatus {
	if m.IsMultipart() && m.ctSecondary == "signed" {
		return verifyMimeSignature(m, keysrc)
	}
	if processInlineSignatures {
		return verifyInlineSignature(m, keysrc)
	}
	return new(VerifyStatus)
}

func createVerifyFailure(message string) *VerifyStatus {
	status := new(VerifyStatus)
	status.Code = VerifyFailed
	status.FailureMessage = message
	return status
}

func verifyMimeSignature(m *Message, keysrc KeySource) *VerifyStatus {
	if !m.IsMultipart() || m.ctSecondary != "signed" {
		return createVerifyFailure("Not a multipart/signed message")
	}
	ps := m.mpContent.parts
	if len(ps) != 2 {
		return createVerifyFailure(fmt.Sprintf("cannot extract signature, expecting 2 mime parts, got %d", len(ps)))
	}
	sig := bytes.NewReader([]byte(ps[1].Body))
	sigBlock, err := armor.Decode(sig)
	if err != nil {
		return createVerifyFailure("error decoding armored signature: " + err.Error())
	}
	status := checkSignature(keysrc, ps[0].rawContent, sigBlock)
	if isVerifiedSignature(status) {
		processMimePlaintext(m, ps[0].rawContent)
		status.Message = m
	}
	return status
}

func getIssuerFromSignature(sigReader io.Reader) (uint64, error) {
	p, err := packet.Read(sigReader)
	if err != nil {
		return 0, err
	}
	switch sig := p.(type) {
	case *packet.Signature:
		if sig.IssuerKeyId == nil {
			return 0, errors.New("signature doesn't have an issuer")
		}
		return *sig.IssuerKeyId, nil
	case *packet.SignatureV3:
		return sig.IssuerKeyId, nil
	default:
		return 0, errors.New("non signature packet found")
	}
}

func checkSignature(keysrc KeySource, msg []byte, sigBlock *armor.Block) *VerifyStatus {
	if sigBlock.Type != openpgp.SignatureType {
		return createVerifyFailure("armored signature type is incorrect: " + sigBlock.Type)
	}
	msgReader := bytes.NewReader(msg)

	bb := new(bytes.Buffer)
	bb.ReadFrom(sigBlock.Body)
	sigBytes := bb.Bytes()
	signer, err := openpgp.CheckDetachedSignature(
		keysrc.GetPublicKeyRing(),
		msgReader,
		bytes.NewReader(sigBytes))

	keyId, e := getIssuerFromSignature(bytes.NewReader(sigBytes))
	if e != nil {
		logger.Warning("could not extract issuer id from signature: " + e.Error())
	}
	return processCheckSignatureResult(signer, keyId, err)
}

func processCheckSignatureResult(signer *openpgp.Entity, keyid uint64, err error) *VerifyStatus {
	status := new(VerifyStatus)
	status.SignerKeyId = keyid
	if err == nil && signer != nil {
		status.SignerKeyId = signer.PrimaryKey.KeyId
		status.Code = VerifySigValid
		if isSignerKeyExpired(signer) {
			status.Code = VerifyKeyExpired
		}
		// XXX Does uid match from address?
		return status
	}
	if _, ok := err.(pgperr.SignatureError); ok {
		status.Code = VerifySigInvalid
	} else if err == pgperr.ErrUnknownIssuer {
		status.Code = VerifyNoPubkey
	} else {
		status.Code = VerifyFailed
		status.FailureMessage = "error verifying signature: " + err.Error()
	}
	return status
}

func isSignerKeyExpired(signer *openpgp.Entity) bool {
	for _, v := range signer.Identities {
		return v.SelfSignature.KeyExpired(openpgpConfig.Now())
	}
	return false
}

func verifyInlineSignature(m *Message, keysrc KeySource) *VerifyStatus {
	if !m.IsMultipart() {
		status, plaintext := checkInlineSignature(m.Body, keysrc)
		if plaintext != nil {
			m.Body = string(plaintext)
			status.Message = m
		}
		return status
	}

	for _, p := range m.mpContent.parts {
		// Only consider the first text/plain section
		if isTextMimePart(p) {
			status, plaintext := checkInlineSignature(p.Body, keysrc)
			if plaintext != nil {
				p.Body = string(plaintext)
				p.rawContent = []byte(p.String())
				m.PackMultiparts()
				status.Message = m
			}
			return status
		}
	}
	return new(VerifyStatus)
}

func isTextMimePart(part *MessagePart) bool {
	ct := part.GetHeaderValue(ctHeader)
	if ct == "" {
		return true
	}
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return false
	}
	return mt == "text/plain"
}

func checkInlineSignature(body string, keysrc KeySource) (*VerifyStatus, []byte) {
	b, _ := clearsign.Decode([]byte(body))
	if b == nil {
		return new(VerifyStatus), nil
	}
	status := checkSignature(keysrc, b.Bytes, b.ArmoredSignature)
	if isVerifiedSignature(status) {
		return status, b.Plaintext
	}
	return status, nil
}

func isVerifiedSignature(status *VerifyStatus) bool {
	return status.Code == VerifySigValid || status.Code == VerifyKeyExpired
}
