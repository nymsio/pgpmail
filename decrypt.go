package pgpmail

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"code.google.com/p/go.crypto/openpgp"
	"code.google.com/p/go.crypto/openpgp/armor"
	pgperr "code.google.com/p/go.crypto/openpgp/errors"
)

const beginPgpMessage = "-----BEGIN PGP MESSAGE-----"
const endPgpMessage = "-----END PGP MESSAGE-----"

const (
	DecryptNotEncrypted = iota
	DecryptSuccess
	DecryptPassphraseNeeded
	DecryptFailedNoPrivateKey
	DecryptFailed
)

type DecryptionStatus struct {
	VerifyStatus
	Code           int
	Message        *Message
	KeyIds         []uint64
	FailureMessage string
}

func (m *Message) Decrypt(keysrc KeySource) *DecryptionStatus {
	return m.DecryptWith(keysrc, nil)
}

func (m *Message) DecryptWith(keysrc KeySource, passphrase []byte) *DecryptionStatus {
	if m.IsMultipart() && m.ctSecondary == "encrypted" {
		return decryptMimeMessage(m, keysrc, passphrase)
	} else if processInlineEncrypted {
		return decryptInlineMessage(m, keysrc, passphrase)
	}
	return new(DecryptionStatus)
}

func createFailureStatus(message string) *DecryptionStatus {
	status := new(DecryptionStatus)
	status.Code = DecryptFailed
	status.FailureMessage = message
	return status
}

func decryptMimeMessage(m *Message, keysrc KeySource, passphrase []byte) *DecryptionStatus {
	parts := m.mpContent.parts
	if len(parts) != 2 {
		return createFailureStatus(fmt.Sprintf("failed to extract encrypted body, expecting 2 mime parts, got %d", len(parts)))
	}
	block, err := armor.Decode(strings.NewReader(parts[1].Body))
	if err != nil {
		return createFailureStatus("armor decode of encrypted body failed: " + err.Error())
	}

	bs, status := decryptCiphertext(keysrc, block.Body, passphrase)
	if bs == nil {
		return status
	}
	err = processMimePlaintext(m, bs)
	if err != nil {
		status.Code = DecryptFailed
		status.FailureMessage = "error building plaintext message: " + err.Error()
		return status
	}
	status.Message = m
	return status
}

func processSignature(md *openpgp.MessageDetails, status *DecryptionStatus) {
	if !md.IsSigned {
		return
	}
	if md.SignedByKeyId != 0 {
		status.VerifyStatus.SignerKeyId = md.SignedByKeyId
	}
	if md.SignedBy == nil {
		status.VerifyStatus.Code = VerifyNoPubkey
		return
	}
	if md.SignatureError != nil {
		if _, ok := md.SignatureError.(pgperr.SignatureError); ok {
			status.VerifyStatus.Code = VerifySigInvalid
			return
		}
		status.VerifyStatus.Code = VerifyFailed
		status.VerifyStatus.FailureMessage = "error verifying signature: " + md.SignatureError.Error()
		return
	}
	if md.SignedBy.SelfSignature.KeyExpired(time.Now()) {
		status.VerifyStatus.Code = VerifyKeyExpired
		return
	}
	status.VerifyStatus.Code = VerifySigValid

}

func decryptCiphertext(keysrc KeySource, ctext io.Reader, passphrase []byte) ([]byte, *DecryptionStatus) {
	status := new(DecryptionStatus)
	md, err := openpgp.ReadMessage(ctext, keysrc.GetSecretKeyRing(), createPromptFunction(passphrase), openpgpConfig)
	if err == nil {
		status.Code = DecryptSuccess
		b := new(bytes.Buffer)
		b.ReadFrom(md.UnverifiedBody)
		if md.IsSigned {
			processSignature(md, status)
		}
		return b.Bytes(), status
	}
	if err == pgperr.ErrKeyIncorrect {
		status.Code = DecryptFailedNoPrivateKey
		return nil, status
	}
	if e, ok := err.(PassphraseNeededError); ok {
		status.Code = DecryptPassphraseNeeded
		status.KeyIds = e.KeyIds
		return nil, status
	}
	status.Code = DecryptFailed
	status.FailureMessage = "error decrypting message: " + err.Error()
	return nil, status
}

func decryptInlineMessage(m *Message, keysrc KeySource, passphrase []byte) *DecryptionStatus {
	if !m.IsMultipart() {
		ctext, err := extractInlineBody(m.Body)
		if err != nil {
			return createFailureStatus("error extracting inline message: " + err.Error())
		}
		if ctext != nil {
			bs, status := decryptCiphertext(keysrc, ctext, passphrase)
			if bs == nil {
				return status
			}
			m.Body = insertCR(string(bs))
			status.Message = m
			return status
		}
		return new(DecryptionStatus)
	}

	for _, part := range m.mpContent.parts {
		// XXX sanity check content type
		ctext, err := extractInlineBody(part.Body)
		if err != nil {
			return createFailureStatus("error extracting inline message part: " + err.Error())
		}
		if ctext != nil {
			bs, status := decryptCiphertext(keysrc, ctext, passphrase)
			if bs == nil {
				return status
			}
			part.Body = insertCR(string(bs))
			part.rawContent = []byte(part.String())
			m.PackMultiparts()
			status.Message = m
			return status
		}
	}
	return new(DecryptionStatus)
}

func createPromptFunction(passphrase []byte) openpgp.PromptFunction {
	first := true
	return func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
		if first && passphrase != nil {
			for _, k := range keys {
				e := k.PrivateKey.Decrypt(passphrase)
				if e != nil {
					logger.Info("Passphrase failed with " + e.Error())
				}
			}
			first = false
			return passphrase, nil
		}
		var err PassphraseNeededError
		for _, k := range keys {
			err.KeyIds = append(err.KeyIds, k.Entity.PrimaryKey.KeyId)
		}
		return nil, err
	}
}

func extractEncryptedBodyMime(m *Message) (io.Reader, error) {
	ps := m.mpContent.parts
	if len(ps) != 2 {
		return nil, fmt.Errorf("failed to extract encrypted body, expecting 2 mime parts, got %d", len(ps))
	}
	block, err := armor.Decode(strings.NewReader(ps[1].Body))
	if err != nil {
		return nil, errors.New("armor decode of encrypted body failed: " + err.Error())
	}
	return block.Body, nil
}

func extractInlineBody(body string) (io.Reader, error) {
	start := strings.Index(body, beginPgpMessage)
	if start == -1 {
		return nil, nil
	}

	end := strings.Index(body, endPgpMessage)
	if end == -1 {
		return nil, errors.New("End of inline PGP message not found")
	}
	armored := body[start:(end + len(endPgpMessage))]
	block, err := armor.Decode(bytes.NewReader([]byte(armored)))
	if err != nil {
		return nil, errors.New("armor decode of encrypted body failed: " + err.Error())
	}
	return block.Body, nil
}

func processMimePlaintext(m *Message, plaintext []byte) error {
	mimeReader := NewReader(string(plaintext))
	headers, err := mimeReader.ReadMIMEHeader()
	if err != nil {
		return err
	}
	for _, h := range headers {
		m.SetHeader(h.Name, h.Value)
	}
	body, err := mimeReader.R.ReadBytes(0)
	if err != io.EOF {
		return err
	}
	m.Body = string(body)
	m.parseContentType()
	m.extractMultiparts()
	return nil
}
