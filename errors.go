package pgpmail

import "fmt"

// A NoSignaturePrivateKeyError is returned when no private key
// can be found matching sender email address
type NoSignaturePrivateKeyError struct {
	EmailAddress string
}

func (e NoSignaturePrivateKeyError) Error() string {
	return "signature failed, no private key for address " + e.EmailAddress
}

// PassphraseNeededError is returned from a sign or decrypt operation if
// private key needed is locked with a passphrase.
type PassphraseNeededError struct {
	KeyIds []uint64
}

func (e PassphraseNeededError) Error() string {
	return "passphrase needed to unlock secret key needed for operation"
}

// PublicKeysNeededError is returned from encryption operations when
// public keys are not available for some or all message recipients.
// Addresses contains the email addresses of the recipients without keys.
type PublicKeysNeededError struct {
	Addresses []string
}

func (e PublicKeysNeededError) Error() string {
	return fmt.Sprintf("public keys needed for recipient addresses: %v", e.Addresses)
}
