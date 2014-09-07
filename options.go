package pgpmail

import (
	"io"

	"code.google.com/p/go.crypto/openpgp/packet"
)

// encryptToSelf enables also encrypting every email message to the public key of the sender
var encryptToSelf = true

// processInlineEncrypted enables searching inside messages for pgp encrypted message content and processing it
var processInlineEncrypted = true

// processInlineSignatures enables processing of clear-signed message signatures
var processInlineSignatures = true

// useCombinedSignatures enables applying signatures to encrypted messages rather than creating signatures separately
var useCombinedSignatures = true

var openpgpConfig *packet.Config

var testingRandHook io.Reader

func SetEncryptToSelf(v bool) {
	encryptToSelf = v
}

func SetProcessInlineEncrypted(v bool) {
	processInlineEncrypted = v
}

func SetProcessInlineSignatures(v bool) {
	processInlineSignatures = v
}

func SetUseCombinedSignatures(v bool) {
	useCombinedSignatures = v
}
