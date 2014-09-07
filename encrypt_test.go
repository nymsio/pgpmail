package pgpmail

import "testing"

func TestEncrypt(t *testing.T) {
	encryptToSelf = false
	msg := "This is a test message.\n"
	tdata := new(TestData)
	tdata.To = "user1@example.com"
	tdata.Subject = "Test Encrypted Message"
	tdata.Body = msg
	m := tdata.Message()
	status := m.Encrypt(testKeys)
	if status.Code != StatusEncryptedOnly {
		t.Errorf("Status is not expected value %v", status)
	}
	if m.String() != expectedEncryptedMessage {
		t.Errorf("Encrypted message does not match expected content")
	}
	if status := m.Decrypt(testKeys); status.Code != DecryptSuccess {
		t.Error("Message did not decrypt successfully")
	}
	if m.String() != tdata.String() {
		t.Error("Decrypted message does not match original message")
	}
}

func TestInlineDecrypt(t *testing.T) {

	td := new(TestData)
	td.Body = testInlineCiphertext
	m := td.Message()

	status := m.Decrypt(testKeys)
	if status.Code != DecryptSuccess {
		t.Error("Inline encrypted message did not decrypt successfully")
	}
	const inlinePlaintext = "This is a test inline message.\r\n\r\n"
	if m.Body != inlinePlaintext {
		t.Error("Decrypted inline message does not match expected message")
	}
}

func TestDecryptNotEncrypted(t *testing.T) {
	td := new(TestData)
	td.Body = "Hello, World"
	m := td.Message()
	status := m.Decrypt(testKeys)
	if status.Code != DecryptNotEncrypted {
		t.Errorf("Expecting DecryptNotEncrypted (0) got: ", status.Code)
	}
}

var expectedEncryptedMessage = insertCR(`From: from@example.com
To: user1@example.com
Subject: Test Encrypted Message
Mime-Version: 1.0
Content-Type: multipart/encrypted; boundary=0c74507f56a92b4be35f4f8b18640f3b2e099f7cc8953151ef58abffe70c; protocol="application/pgp-encrypted"

This is an OpenPGP/MIME encrypted message (RFC 4880 and 3156)

--0c74507f56a92b4be35f4f8b18640f3b2e099f7cc8953151ef58abffe70c
Content-Type: application/pgp-encrypted
Content-Description: PGP/MIME version identification

Version: 1

--0c74507f56a92b4be35f4f8b18640f3b2e099f7cc8953151ef58abffe70c
Content-Type: application/octet-stream; name="encrypted.asc"
Content-Description: OpenPGP encrypted message
Content-Disposition: inline; filename="encrypted.asc"

-----BEGIN PGP MESSAGE-----

wYwD4aoKGtEFakQBBABay6xx2+vZkLjeyz6AEZDbLSGrLFcURgqwRZSDaYb2WKH5
9if2M4LArEwaaIfR4BUpxsrQIqiHnuL5e/5iojhogN9hx03IsQjWnTURHb5tBbCm
7fecytLL4Py1lCVgrY8QvK8ywzTLHTUctDAyW3679px5RRg5oxQoUaWmR18XDdLg
AeRnN8QOsAuzG65rS1D3cQ5+4Yns4EjgLOGUT+D54kyFN5LgVuau6XNcB+xHRHg7
bOZTtA5fL9Ze2doY2drbneZ6/AeBHmlwltyZSFaVtZuzc8cvv2MxFdy3fwHvPK6Q
cDMuYv8v4C3lNfUm9mOnYHCtd8DDpMMzP7baA1VHSfu0f6nY0uyejtbg++KyJgrz
4OXgjuAT5LAvANDwulz9novkEF2FZVDibaG7BeFWOgA=
=rlyK
-----END PGP MESSAGE-----

--0c74507f56a92b4be35f4f8b18640f3b2e099f7cc8953151ef58abffe70c--
`)

var testInlineCiphertext = `
-----BEGIN PGP MESSAGE-----

hIwD4aoKGtEFakQBBACUB9vtsVFmmwP3u+TdFBB2k14WEaZd49CqDVl9ohTTkpd1
sRbusVDrM2xzvPtkgcecZ53H+CGbrcxp1e8tNmoL1XyrhjzctoDKG4BzXjlu4rpz
lKQZ/Mj3oPFYHVeS6eJdBzwlnd3oRTpZaYZ/1Xes6CChrJLSDXkjeF83MX+l/dJa
AV6zMfa6dJKn4HXVSNuAe7j9NRsAzhjo2QP+hEljriXDqPg+N34z95JSslv2PLrl
ZoWyrrOdnU6wrrqsojU0oosS50CHez2DXJR14E02IBM4dDY2s9RQ8CVr
=QBqS
-----END PGP MESSAGE-----

blah blah`
