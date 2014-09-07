package pgpmail

import "testing"

func TestSign(t *testing.T) {
	k, _ := testKeys.GetSecretKey("user1@example.com")
	td := new(TestData)
	td.Body = "This is a test message.\n"
	m := td.Message()
	m.SetHeader(ctHeader, "text/plain; charset=us-ascii")
	sigBodyPart := createBodyMimePart(m)
	sig, _ := createSignature(sigBodyPart.rawContent, k, openpgpConfig)
	if sig != testExpectedSigUser1 {
		t.Error("Signature is not expected value")
	}
}

var testExpectedSigUser1 = `-----BEGIN PGP SIGNATURE-----

wpwEAQEIABAFAgAAAAAJEGG1Vm0p3l+0AACTkAQAymMahe+auV36Jn5kg3fDiAs+
rZmmg8SqpA4aYq2fDRLv1zLFDcjePKPUqR+isgFKpJL/Lrb5CrSo5aBdJZ3cNWeT
Rpp8Z/p0yrINVGWG+fIRk2ahZX9eqhcIUxWs1NQUgLtNz3XV7fB8NN05pc7mc8w5
AX9kg9PkbMQkDzBnS/k=
=x06Q
-----END PGP SIGNATURE-----`

func TestMimeSign(t *testing.T) {
	k, err := testKeys.GetSecretKey("user1@example.com")
	if err != nil {
		t.Error("error looking up secret key for user1@example.com: " + err.Error())
	}
	td := new(TestData)
	td.From = "user1@example.com"
	td.Body = "This is a test message.\n"
	m := td.Message()
	ss := m.Sign(testKeys, "")
	if ss.Code != StatusSignedOnly {
		t.Errorf("status is not expected value: %v", ss)
	}
	if err != nil {
		t.Error("unexpected error signing test message: " + err.Error())
	}
	status := m.Verify(testKeys)
	if status.Code != VerifySigValid {
		t.Error("Signature did not verify")
	}
	if status.SignerKeyId != k.PrimaryKey.KeyId {
		t.Error("Signature keyid does not match original signing key")
	}
	m = td.Message()
	m.Sign(testKeys, "")
	p := m.mpContent.parts[0]
	p.rawContent = p.rawContent[1:]
	status = m.Verify(testKeys)
	if status.Code != VerifySigInvalid {
		t.Error("Signature did not fail on corrupted text as expected")
	}
}

func TestClearSign(t *testing.T) {
	testClearsignMessage(t, clearsignData)
	testClearsignMessage(t, clearsignData2)
}

func testClearsignMessage(t *testing.T, msg string) {
	td := new(TestData)
	td.Body = msg
	m := td.Message()
	status := m.Verify(testKeys)
	k, _ := testKeys.GetPublicKey("user1@example.com")
	if status.Code != VerifySigValid {
		t.Error("Clearsign signature did not verify")
	}
	if status.SignerKeyId != k.PrimaryKey.KeyId {
		t.Error("Signature keyid does not match expected signing key")
	}
}

var clearsignData = `
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

This is a clearsign test message.
-----BEGIN PGP SIGNATURE-----

iJwEAQEKAAYFAlPoatUACgkQYbVWbSneX7SzsgP/Wt+eQ3gKR6OI6cN5iE9tbQur
+oQcYrtb/8SnDNClf4d+R/Ksif4JiI6zYrawz/HSC50XoaMjsmT7SPsoCi2r2zY7
C7Y1RWvall1BorUjefRqySf3Qm3AYHSbKR2S9ZZEeBMc8BXazrNlB5kpsimRAefw
QWLmlo+NjFTMK4Yf1gA=
=AsQ/
-----END PGP SIGNATURE-----
`

var clearsignData2 = `
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512



This is a clearsigned message body with leading newlines.
-----BEGIN PGP SIGNATURE-----
Version: GnuPG/MacGPG2 v2
Comment: GPGTools - https://gpgtools.org

iJwEAQEKAAYFAlPqEnoACgkQYbVWbSneX7TGlQP9F91/xLKB/OhF9IhcMH2g2c18
eUgPBUhg46T5a95zk6D0NoxvuSVp5o6XESYs7gg7XXweQGAHDu/cZTJxMBbRX6gU
AOTv4yh3X64MXmnoh/FvggE82QhNzzbj1nkAaVA5psAiMdT1U91VSyVEkhoQdnGC
P+qli0eg7HL/fPwl44A=
=4Hco
-----END PGP SIGNATURE-----
`

func TestUnsignedMessage(t *testing.T) {
	td := new(TestData)
	td.Body = "This message is not signed."
	m := td.Message()
	status := m.Verify(testKeys)
	if status.Code != VerifyNotSigned {
		t.Error("Unsigned message did not return VerifyUnsigned as expected")
	}

	td = new(TestData)
	td.Parts = []string{plainPart, htmlPart}
	m = td.Message()

	status = m.Verify(testKeys)
	if status.Code != VerifyNotSigned {
		t.Error("Unsigned message did not return VerifyUnsigned as expected")
	}
}
